use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use tempfile::TempDir;

use crate::{APPLICATION_ID, Advisory, Error, check_schema, database_path, lock_database};

const BATCH_SIZE: usize = 1_000;

/// Build a database in the target directory and publish it after validation.
///
/// Hold an exclusive publication lock while importing. Dropping the writer
/// discards the staged database.
pub struct SnapshotWriter {
    connection: Connection,
    staging: TempDir,
    path: PathBuf,
    _lock: File,
    pending: usize,
    advisories: u64,
    failed: bool,
}

impl SnapshotWriter {
    pub fn new(path: &Path) -> Result<Self, Error> {
        let path = database_path(path)?;
        let lock = lock_database(&path, true)?;
        if path.try_exists()? {
            let existing = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            check_schema(&existing, &path)?;
        }

        let parent = path.parent().expect("database path has a parent");
        let staging = tempfile::Builder::new()
            .prefix(".osv-import-")
            .tempdir_in(parent)?;
        let connection = Connection::open(staging.path().join("snapshot.sqlite"))?;
        connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA cache_size = -65536;")?;
        connection.pragma_update(None, "application_id", APPLICATION_ID)?;

        connection.execute_batch(include_str!("../migrations/001_initial.sql"))?;
        crate::incremental::migrate(&connection, 1)?;
        // Only duplicate versions need this table. Keep older copies here so a
        // conflict is detected regardless of which version was seen first.
        connection.execute_batch(
            "CREATE TEMP TABLE superseded (
                id TEXT NOT NULL,
                modified_key TEXT NOT NULL,
                json TEXT NOT NULL,
                PRIMARY KEY (id, modified_key)
            ) WITHOUT ROWID;",
        )?;

        Ok(Self {
            connection,
            staging,
            path,
            _lock: lock,
            pending: 0,
            advisories: 0,
            failed: false,
        })
    }

    pub fn insert(&mut self, advisory: &Advisory<'_>) -> Result<(), Error> {
        if self.failed {
            return Err(Error::FailedImport);
        }
        let result = self.insert_record(advisory);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Verify the staged database, then atomically replace the previous copy.
    /// Returns the number of distinct advisory IDs published.
    pub fn publish(self) -> Result<u64, Error> {
        if self.failed {
            return Err(Error::FailedImport);
        }
        if self.pending > 0 {
            self.connection.execute_batch("COMMIT")?;
        }
        let integrity: String = self
            .connection
            .pragma_query_value(None, "quick_check", |row| row.get(0))?;
        if integrity != "ok" {
            return Err(Error::Integrity(integrity));
        }
        let violation = self
            .connection
            .query_row("PRAGMA foreign_key_check", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()?;
        if let Some(table) = violation {
            return Err(Error::Integrity(format!(
                "foreign key violation in {table}"
            )));
        }
        self.connection.close().map_err(|(_, error)| error)?;

        let staged_path = self.staging.path().join("snapshot.sqlite");
        File::open(&staged_path)?.sync_all()?;
        prepare_replacement(&self.path)?;
        fs::rename(staged_path, &self.path)?;
        Ok(self.advisories)
    }

    fn insert_record(&mut self, advisory: &Advisory<'_>) -> Result<(), Error> {
        if self.pending == 0 {
            self.connection.execute_batch("BEGIN IMMEDIATE")?;
        }

        let record = &advisory.record;
        let modified = advisory.modified_key();
        let withdrawn = &advisory.withdrawn_key;
        let inserted = self.connection.prepare_cached(
            "INSERT INTO advisories (id, modified_key, withdrawn_key, json) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO NOTHING",
        )?.execute(params![record.id, modified, withdrawn, advisory.json])? > 0;

        if inserted {
            self.advisories += 1;
            insert_aliases(&self.connection, advisory)?;
            crate::packages::replace_index(&self.connection, advisory)?;
        } else {
            let (existing_key, existing_json): (String, String) = self
                .connection
                .prepare_cached("SELECT modified_key, json FROM advisories WHERE id = ?1")?
                .query_row([&record.id], |row| Ok((row.get(0)?, row.get(1)?)))?;

            match modified.cmp(existing_key.as_str()) {
                std::cmp::Ordering::Less => {
                    self.remember_older(&record.id, modified, advisory.json)?;
                }
                std::cmp::Ordering::Equal => {
                    check_duplicate(&record.id, modified, &existing_json, advisory.json)?;
                }
                std::cmp::Ordering::Greater => {
                    self.remember_older(&record.id, &existing_key, &existing_json)?;
                    self.connection.prepare_cached(
                        "UPDATE advisories SET modified_key = ?2, withdrawn_key = ?3, json = ?4 WHERE id = ?1",
                    )?.execute(params![record.id, modified, withdrawn, advisory.json])?;
                    self.connection
                        .prepare_cached("DELETE FROM aliases WHERE advisory_id = ?1")?
                        .execute([&record.id])?;
                    insert_aliases(&self.connection, advisory)?;
                    crate::packages::replace_index(&self.connection, advisory)?;
                }
            }
        }

        self.pending += 1;
        if self.pending == BATCH_SIZE {
            self.connection.execute_batch("COMMIT")?;
            self.pending = 0;
        }
        Ok(())
    }

    fn remember_older(&self, id: &str, modified: &str, json: &str) -> Result<(), Error> {
        let inserted = self
            .connection
            .prepare_cached(
                "INSERT INTO superseded (id, modified_key, json) VALUES (?1, ?2, ?3)
             ON CONFLICT(id, modified_key) DO NOTHING",
            )?
            .execute(params![id, modified, json])?;
        if inserted == 0 {
            let previous: String = self
                .connection
                .prepare_cached("SELECT json FROM superseded WHERE id = ?1 AND modified_key = ?2")?
                .query_row(params![id, modified], |row| row.get(0))?;
            check_duplicate(id, modified, &previous, json)?;
        }
        Ok(())
    }
}

pub(crate) fn insert_aliases(
    connection: &Connection,
    advisory: &Advisory<'_>,
) -> Result<(), Error> {
    let Some(aliases) = &advisory.record.aliases else {
        return Ok(());
    };
    let mut statement = connection.prepare_cached(
        "INSERT INTO aliases (alias, advisory_id) VALUES (?1, ?2)
             ON CONFLICT(alias, advisory_id) DO NOTHING",
    )?;
    for alias in aliases {
        if !alias.is_empty() && alias != advisory.id() {
            statement.execute(params![alias, advisory.id()])?;
        }
    }
    Ok(())
}

fn check_duplicate(id: &str, modified: &str, first: &str, second: &str) -> Result<(), Error> {
    if first == second {
        return Ok(());
    }
    let without_modified = |json: &str| -> Result<_, serde_json::Error> {
        let mut value: serde_json::Value = serde_json::from_str(json)?;
        value["modified"] = serde_json::Value::Null; // Already compared by instant.
        Ok(value)
    };
    if without_modified(first)? == without_modified(second)? {
        Ok(())
    } else {
        Err(Error::ConflictingRecords {
            id: id.into(),
            modified: format!("{modified}Z"),
        })
    }
}

fn prepare_replacement(path: &Path) -> Result<(), Error> {
    if path.try_exists()? {
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        check_schema(&connection, path)?;
        let mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
        if mode == "wal" {
            let busy: i32 =
                connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
            if busy != 0 {
                return Err(Error::InUse(path.into()));
            }
            let mode: String =
                connection.query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))?;
            if mode != "delete" {
                return Err(Error::InUse(path.into()));
            }
        } else {
            // Fail if another SQLite client has an open transaction on the old file.
            connection.execute_batch("BEGIN EXCLUSIVE; COMMIT;")?;
        }
        connection.close().map_err(|(_, error)| error)?;
    }

    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        match fs::symlink_metadata(PathBuf::from(sidecar)) {
            Ok(_) => return Err(Error::InUse(path.into())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Lookup, Store};

    #[test]
    fn discarded_staging_batches_never_replace_a_closed_wal_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("osv.sqlite");
        let json = r#"{"id":"OSV-1","modified":"2026-11-12T12:00:00Z"}"#;
        let mut writer = SnapshotWriter::new(&path).unwrap();
        writer.insert(&Advisory::parse(json).unwrap()).unwrap();
        writer.publish().unwrap();

        let connection = Connection::open(&path).unwrap();
        let mode: String = connection
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        connection.close().unwrap();

        let mut writer = SnapshotWriter::new(&path).unwrap();
        for index in 0..=BATCH_SIZE {
            let staged = format!(r#"{{"id":"CVE-{index}","modified":"2026-11-12T12:00:00Z"}}"#);
            writer.insert(&Advisory::parse(&staged).unwrap()).unwrap();
        }
        drop(writer);
        let store = Store::open(&path).unwrap();
        assert_eq!(store.lookup("OSV-1").unwrap(), Lookup::Found(json.into()));
        assert_eq!(store.lookup("CVE-1").unwrap(), Lookup::Missing);
        drop(store);

        let mut writer = SnapshotWriter::new(&path).unwrap();
        let replacement = json.replace("OSV-1", "OSV-2");
        writer
            .insert(&Advisory::parse(&replacement).unwrap())
            .unwrap();
        writer.publish().unwrap();
        let store = Store::open(&path).unwrap();
        assert_eq!(store.lookup("OSV-1").unwrap(), Lookup::Missing);
        assert_eq!(store.lookup("OSV-2").unwrap(), Lookup::Found(replacement));
    }

    #[test]
    fn refuses_to_publish_over_orphaned_sqlite_sidecars() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("osv.sqlite");
        let wal = directory.path().join("osv.sqlite-wal");
        fs::write(&wal, b"previous WAL").unwrap();
        let writer = SnapshotWriter::new(&path).unwrap();
        assert!(matches!(writer.publish(), Err(Error::InUse(_))));
        assert!(!path.exists());
        assert_eq!(fs::read(wal).unwrap(), b"previous WAL");
    }
}
