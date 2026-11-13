use std::fs::File;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};

use crate::snapshot::insert_aliases;
use crate::{
    Advisory, Error, SCHEMA_VERSION, check_schema, database_path, lock_database, lock_sidecar,
};

#[derive(Clone, Debug, Default)]
pub struct Validators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub generation: Option<String>,
}

#[derive(Debug)]
pub struct FeedState {
    pub validators: Validators,
    pub inventory_digest: Option<String>,
    pub revision: i64,
    pub pending_absences: usize,
}

#[derive(Debug)]
pub struct Candidate {
    pub id: String,
    pub modified_key: String,
    pub ecosystems: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reconciliation {
    Unchanged,
    Checked,
    Incomplete { missing: usize, limit: usize },
}

#[derive(Debug)]
pub struct SyncReport {
    pub updated: usize,
    pub removed: usize,
    pub pending_absences: usize,
    pub revision: i64,
    pub reconciliation: Reconciliation,
}

pub(crate) fn migrate(connection: &Connection, version: i32) -> Result<(), Error> {
    if version == SCHEMA_VERSION {
        return Ok(());
    }
    let transaction = connection.unchecked_transaction()?;
    if version == 1 {
        transaction.execute_batch(include_str!("../migrations/002_sync.sql"))?;
    }
    if version < 3 {
        transaction.execute_batch(include_str!("../migrations/003_packages.sql"))?;
    }
    transaction.execute_batch(include_str!("../migrations/004_git.sql"))?;
    crate::packages::backfill(&transaction, version < 3)?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

/// Exclusive incremental writer, compatible with concurrent store readers.
/// The connection owns disk-backed temporary tables until the update commits.
pub struct SyncWriter {
    connection: Connection,
    _publication_lock: File,
    _writer_lock: File,
    feed: String,
    state: FeedState,
}

impl SyncWriter {
    pub fn open(path: &Path, feed: &str) -> Result<Self, Error> {
        let path = database_path(path)?;
        let publication_lock = lock_database(&path, false)?;
        let writer_lock = lock_sidecar(&path, ".osv-sync-lock", true)?;
        let connection = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        let version = check_schema(&connection, &path)?;
        let mode: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if mode != "wal" {
            return Err(Error::InUse(path));
        }
        connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA temp_store = FILE;")?;
        migrate(&connection, version)?;

        let (previous_feed, state): (Option<String>, _) = connection.query_row(
            "SELECT feed, etag, last_modified, generation, inventory_digest, revision,
                    (SELECT count(*) FROM pending_absences)
             FROM sync_state WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    FeedState {
                        validators: Validators {
                            etag: row.get(1)?,
                            last_modified: row.get(2)?,
                            generation: row.get(3)?,
                        },
                        inventory_digest: row.get(4)?,
                        revision: row.get(5)?,
                        pending_absences: row.get::<_, i64>(6)? as usize,
                    },
                ))
            },
        )?;
        if let Some(previous) = previous_feed.filter(|previous| previous != feed) {
            return Err(Error::FeedMismatch(previous));
        }

        connection.execute_batch(
            "CREATE TEMP TABLE inventory (
                 id TEXT NOT NULL, ecosystem TEXT NOT NULL, modified_key TEXT NOT NULL,
                 PRIMARY KEY (id, ecosystem)
             ) WITHOUT ROWID;
             CREATE TEMP TABLE current_inventory (
                 id TEXT PRIMARY KEY, modified_key TEXT NOT NULL
             ) WITHOUT ROWID;
             CREATE TEMP TABLE candidates (
                 id TEXT PRIMARY KEY, modified_key TEXT NOT NULL
             ) WITHOUT ROWID;
             CREATE TEMP TABLE bodies (
                 id TEXT PRIMARY KEY, json TEXT NOT NULL
             ) WITHOUT ROWID;
             CREATE TEMP TABLE missing (
                 id TEXT PRIMARY KEY
             ) WITHOUT ROWID;",
        )?;
        Ok(Self {
            connection,
            _publication_lock: publication_lock,
            _writer_lock: writer_lock,
            feed: feed.into(),
            state,
        })
    }

    pub fn state(&self) -> &FeedState {
        &self.state
    }

    pub fn reset_staging(&self) -> Result<(), Error> {
        self.connection.execute_batch(
            "DELETE FROM inventory; DELETE FROM current_inventory; DELETE FROM candidates;
             DELETE FROM bodies; DELETE FROM missing;",
        )?;
        Ok(())
    }

    /// Load the complete inventory in one temporary-table transaction.
    pub fn load_inventory<E>(
        &mut self,
        rows: impl IntoIterator<Item = Result<(String, String, String), E>>,
    ) -> Result<usize, E>
    where
        E: From<Error>,
    {
        let transaction = self.connection.transaction().map_err(Error::from)?;
        {
            let mut insert = transaction.prepare(
                "INSERT INTO inventory (id, ecosystem, modified_key) VALUES (?1, ?2, ?3)
                 ON CONFLICT(id, ecosystem) DO UPDATE SET modified_key = max(modified_key, excluded.modified_key)",
            ).map_err(Error::from)?;
            for row in rows {
                let (id, ecosystem, key) = row?;
                insert
                    .execute(params![id, ecosystem, key])
                    .map_err(Error::from)?;
            }
        }
        let count = transaction.execute(
            "INSERT INTO current_inventory SELECT id, max(modified_key) FROM inventory GROUP BY id",
            [],
        ).map_err(Error::from)?;
        transaction.commit().map_err(Error::from)?;
        Ok(count)
    }

    pub fn plan(&self) -> Result<(), Error> {
        let has_inventory: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM current_inventory)",
            [],
            |row| row.get(0),
        )?;
        if !has_inventory {
            return Err(Error::EmptyInventory);
        }
        self.connection.execute(
            "INSERT INTO candidates
             SELECT i.id, i.modified_key FROM current_inventory i
             LEFT JOIN advisories a ON a.id = i.id
             WHERE a.id IS NULL OR i.modified_key > a.modified_key",
            [],
        )?;
        Ok(())
    }

    pub fn candidates(&self, after: &str, limit: usize) -> Result<Vec<Candidate>, Error> {
        let mut statement = self.connection.prepare_cached(
            "SELECT id, modified_key FROM candidates WHERE id > ?1 ORDER BY id LIMIT ?2",
        )?;
        let mut paths = self.connection.prepare_cached(
            "SELECT ecosystem FROM inventory WHERE id = ?1 ORDER BY modified_key DESC, ecosystem LIMIT 257",
        )?;
        let mut result = Vec::new();
        let mut rows = statement.query(params![after, limit as i64])?;
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let ecosystems = paths
                .query_map([&id], |row| row.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            if ecosystems.len() > 256 {
                return Err(Error::TooManyPaths(id));
            }
            result.push(Candidate {
                id,
                modified_key: row.get(1)?,
                ecosystems,
            });
        }
        Ok(result)
    }

    pub fn stage(&mut self, bodies: &[(String, String)]) -> Result<(), Error> {
        let transaction = self.connection.transaction()?;
        {
            let mut statement =
                transaction.prepare_cached("INSERT INTO bodies (id, json) VALUES (?1, ?2)")?;
            for (id, json) in bodies {
                statement.execute(params![id, json])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Reject a stale GCS generation before downloading any advisory bodies.
    pub fn check_generation(&self, validators: &Validators) -> Result<(), Error> {
        if self.generation_order(validators) == Some(std::cmp::Ordering::Less) {
            return Err(Error::StaleInventory);
        }
        Ok(())
    }

    /// A newer upstream publication can confirm a pending absence even if its
    /// inventory bytes are unchanged. An ETag change alone is not evidence.
    pub fn needs_reconciliation(&self, digest: &str, validators: &Validators) -> bool {
        self.state.inventory_digest.as_deref() != Some(digest)
            || (self.state.pending_absences > 0
                && self.generation_order(validators) == Some(std::cmp::Ordering::Greater))
    }

    fn generation_order(&self, validators: &Validators) -> Option<std::cmp::Ordering> {
        let previous = self
            .state
            .validators
            .generation
            .as_deref()?
            .parse::<u64>()
            .ok()?;
        let current = validators.generation.as_deref()?.parse::<u64>().ok()?;
        Some(current.cmp(&previous))
    }

    /// Apply the staged update and its inventory checkpoint together.
    /// A 304 has no inventory digest and keeps the previous validators.
    pub fn finish(mut self, inventory: Option<(&str, &Validators)>) -> Result<SyncReport, Error> {
        let reconcile_inventory = inventory
            .is_some_and(|(digest, validators)| self.needs_reconciliation(digest, validators));
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let revision: i64 = transaction.query_row(
            "SELECT revision FROM sync_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if revision != self.state.revision {
            return Err(Error::RevisionChanged);
        }

        let (mut updated, mut removed) = (0, 0);
        let mut reconciliation = Reconciliation::Unchanged;
        if let Some((digest, validators)) = inventory {
            if reconcile_inventory {
                (reconciliation, removed) = reconcile(&transaction)?;
                updated = apply_bodies(&transaction)?;
            }
            transaction.execute(
                "UPDATE sync_state SET feed = ?1, etag = ?2, last_modified = ?3,
                 generation = coalesce(?4, generation), inventory_digest = ?5 WHERE singleton = 1",
                params![
                    self.feed,
                    validators.etag,
                    validators.last_modified,
                    validators.generation,
                    digest
                ],
            )?;
        }
        let revision = revision + i64::from(updated > 0 || removed > 0);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        transaction.execute(
            "UPDATE sync_state SET last_checked = ?1, revision = ?2 WHERE singleton = 1",
            params![now, revision],
        )?;
        let pending_absences: i64 =
            transaction.query_row("SELECT count(*) FROM pending_absences", [], |row| {
                row.get(0)
            })?;
        transaction.commit()?;
        Ok(SyncReport {
            updated,
            removed,
            pending_absences: pending_absences as usize,
            revision,
            reconciliation,
        })
    }
}

fn reconcile(connection: &Connection) -> Result<(Reconciliation, usize), Error> {
    let has_inventory: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM current_inventory)",
        [],
        |row| row.get(0),
    )?;
    if !has_inventory {
        return Err(Error::EmptyInventory);
    }
    connection.execute(
        "INSERT INTO missing
         SELECT a.id FROM advisories a WHERE NOT EXISTS (SELECT 1 FROM current_inventory i WHERE i.id = a.id)",
        [],
    )?;
    let missing = connection.changes() as usize;
    let local_count: i64 =
        connection.query_row("SELECT count(*) FROM advisories", [], |row| row.get(0))?;
    // A small mirror can reconcile a single deletion. Larger mirrors follow
    // the upstream export cleanup job's two-percent safety threshold.
    let limit = (local_count as usize / 50).max(1);
    if missing > limit {
        connection.execute("DELETE FROM pending_absences", [])?;
        return Ok((Reconciliation::Incomplete { missing, limit }, 0));
    }
    connection.execute(
        "DELETE FROM pending_absences WHERE id IN (SELECT id FROM current_inventory)",
        [],
    )?;
    connection.execute(
        "DELETE FROM advisories WHERE id IN (
             SELECT p.id FROM pending_absences p JOIN missing m USING (id)
         )",
        [],
    )?;
    let removed = connection.changes();
    connection.execute(
        "INSERT OR IGNORE INTO pending_absences
         SELECT m.id FROM missing m JOIN advisories a USING (id)",
        [],
    )?;
    Ok((Reconciliation::Checked, removed as usize))
}

fn apply_bodies(connection: &Connection) -> Result<usize, Error> {
    let mut statement = connection.prepare(
        "SELECT c.id, c.modified_key, b.json FROM candidates c LEFT JOIN bodies b USING (id) ORDER BY c.id",
    )?;
    let mut rows = statement.query([])?;
    let mut updated = 0;
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let expected: String = row.get(1)?;
        let body: Option<String> = row.get(2)?;
        let body = body.ok_or_else(|| Error::MissingUpdate(id.clone()))?;
        let advisory = Advisory::parse(&body)?;
        if advisory.id() != id || advisory.modified_key() < expected.as_str() {
            return Err(Error::MissingUpdate(id));
        }
        let changed = connection.prepare_cached(
            "INSERT INTO advisories (id, modified_key, withdrawn_key, json) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET modified_key = excluded.modified_key,
                 withdrawn_key = excluded.withdrawn_key, json = excluded.json
             WHERE excluded.modified_key > advisories.modified_key",
        )?.execute(params![id, advisory.modified_key, advisory.withdrawn_key, advisory.json])?;
        if changed > 0 {
            connection
                .prepare_cached("DELETE FROM aliases WHERE advisory_id = ?1")?
                .execute([&id])?;
            insert_aliases(connection, &advisory)?;
            crate::packages::replace_index(connection, &advisory)?;
            updated += changed;
        }
    }
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Lookup, SnapshotWriter, Store};

    #[test]
    fn migrates_existing_snapshot_and_rolls_back_a_partial_apply() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mirror.sqlite");
        let original = r#"{"id":"OSV-1","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"foo","ecosystem":"Go"}}]}"#;
        let mut snapshot = SnapshotWriter::new(&path).unwrap();
        snapshot
            .insert(&Advisory::parse(original).unwrap())
            .unwrap();
        snapshot.publish().unwrap();

        let old = Connection::open(&path).unwrap();
        old.execute_batch(
            "DROP TABLE git_matches; DROP TABLE git_commits; DROP TABLE git_coverage; DROP TABLE git_ranges; DROP TABLE affected_packages; DROP TABLE query_snapshot; DROP TABLE pending_absences; DROP TABLE sync_state; PRAGMA user_version = 1;",
        )
        .unwrap();
        drop(old);
        let reader = Store::open(&path).unwrap();
        let feed = "https://example.com/modified_id.csv";
        let mut writer = SyncWriter::open(&path, feed).unwrap();
        let modified = "2026-01-02T00:00:00";
        writer
            .load_inventory::<Error>(
                ["OSV-1", "OSV-2"].map(|id| Ok((id.into(), "Go".into(), modified.into()))),
            )
            .unwrap();
        writer.plan().unwrap();
        let updated = r#"{"id":"OSV-1","modified":"2026-01-02T00:00:00Z","aliases":["NEW-ALIAS"]}"#;
        writer.stage(&[("OSV-1".into(), updated.into())]).unwrap();
        assert!(
            matches!(writer.finish(Some(("digest", &Validators::default()))),
            Err(Error::MissingUpdate(id)) if id == "OSV-2")
        );
        assert_eq!(
            reader.lookup("OSV-1").unwrap(),
            Lookup::Found(original.into())
        );
        assert_eq!(reader.lookup("NEW-ALIAS").unwrap(), Lookup::Missing);
        let writer = SyncWriter::open(&path, feed).unwrap();
        assert_eq!(writer.state().revision, 0);
        assert!(writer.state().inventory_digest.is_none());
        reader
            .with_package_search(|search| -> Result<(), Error> {
                let page = search.page(
                    &crate::PackageQuery::new("foo", "Go", ""),
                    "",
                    10,
                    100,
                    None,
                )?;
                assert_eq!(page.matches.len(), 1);
                assert_eq!(page.matches[0].id, "OSV-1");
                Ok(())
            })
            .unwrap();
    }
}
