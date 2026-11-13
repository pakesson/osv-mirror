//! SQLite storage and snapshot publication for OSV advisories.

mod incremental;
mod snapshot;

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};

use osv_schema::{IndexMetadata, ValidationError};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use thiserror::Error;

pub use incremental::{Candidate, FeedState, Reconciliation, SyncReport, SyncWriter, Validators};
pub use snapshot::SnapshotWriter;

// ASCII "OSV" followed by a zero byte.
const APPLICATION_ID: i32 = 0x4f535600;
const SCHEMA_VERSION: i32 = 2;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error(transparent)]
    InvalidAdvisory(#[from] ValidationError),
    #[error("cannot compare duplicate records: {0}")]
    DuplicateJson(#[from] serde_json::Error),
    #[error("database is in use: {0}")]
    InUse(PathBuf),
    #[error("expected an OSV database at {0}")]
    WrongDatabase(PathBuf),
    #[error("unsupported OSV database schema version {0}")]
    UnsupportedVersion(i32),
    #[error("conflicting records for {id} at {modified}")]
    ConflictingRecords { id: String, modified: String },
    #[error("staged database failed validation: {0}")]
    Integrity(String),
    #[error("cannot publish a failed import")]
    FailedImport,
    #[error("this database is already synchronized with {0}; rebuild to change feeds")]
    FeedMismatch(String),
    #[error("database changed while an update was being staged")]
    RevisionChanged,
    #[error("staged update is missing a validated body for {0}")]
    MissingUpdate(String),
    #[error("inventory generation is older than the committed generation")]
    StaleInventory,
    #[error("too many object paths for advisory {0}")]
    TooManyPaths(String),
    #[error("cannot apply an empty inventory")]
    EmptyInventory,
}

/// An advisory validated for storage, retaining its original JSON.
pub struct Advisory<'a> {
    record: IndexMetadata,
    json: &'a str,
    modified_key: String,
    withdrawn_key: Option<String>,
}

impl<'a> Advisory<'a> {
    pub fn parse(json: &'a str) -> Result<Self, Error> {
        let record = IndexMetadata::from_json(json)?;
        let modified_key = osv_schema::timestamp_key(&record.modified)?;
        let withdrawn_key = record
            .withdrawn
            .as_deref()
            .map(osv_schema::timestamp_key)
            .transpose()?;
        Ok(Self {
            record,
            json,
            modified_key,
            withdrawn_key,
        })
    }

    pub fn modified_key(&self) -> &str {
        &self.modified_key
    }

    pub fn id(&self) -> &str {
        &self.record.id
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Lookup {
    Found(String),
    Aliases(Vec<String>),
    Missing,
}

/// A read handle that holds a shared publication lock for its lifetime.
pub struct Store {
    path: PathBuf,
    _lock: File,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, Error> {
        let path = database_path(path)?;
        let lock = lock_database(&path, false)?;
        let connection = open_read(&path)?;
        check_schema(&connection, &path)?;
        Ok(Self { path, _lock: lock })
    }

    /// Look up a primary ID, then the connected alias group if it is absent.
    pub fn lookup(&self, id: &str) -> Result<Lookup, Error> {
        let mut connection = open_read(&self.path)?;
        let transaction = connection.transaction()?;
        let record = transaction
            .query_row("SELECT json FROM advisories WHERE id = ?1", [id], |row| {
                row.get(0)
            })
            .optional()?;
        if let Some(json) = record {
            return Ok(Lookup::Found(json));
        }

        let mut statement = transaction.prepare(
            "WITH RECURSIVE connected(id) AS (
                VALUES (?1)
                UNION
                SELECT a.advisory_id FROM connected c JOIN aliases a ON a.alias = c.id
                UNION
                SELECT a.alias FROM connected c JOIN aliases a ON a.advisory_id = c.id
            )
            SELECT id FROM connected WHERE id != ?1 ORDER BY id",
        )?;
        let aliases = statement
            .query_map([id], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if aliases.is_empty() {
            Ok(Lookup::Missing)
        } else {
            Ok(Lookup::Aliases(aliases))
        }
    }
}

fn open_read(path: &Path) -> Result<Connection, Error> {
    Ok(Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?)
}

fn check_schema(connection: &Connection, path: &Path) -> Result<i32, Error> {
    let application_id: i32 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    if application_id != APPLICATION_ID {
        return Err(Error::WrongDatabase(path.into()));
    }
    let version: i32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if !(1..=SCHEMA_VERSION).contains(&version) {
        return Err(Error::UnsupportedVersion(version));
    }
    Ok(version)
}

fn database_path(path: &Path) -> Result<PathBuf, Error> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "expected a database filename")
    })?;
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let absolute = fs::canonicalize(parent)?.join(name);
    match fs::symlink_metadata(&absolute) {
        Ok(metadata) if !metadata.is_file() => Err(Error::WrongDatabase(absolute)),
        Ok(_) => Ok(absolute),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(absolute),
        Err(error) => Err(error.into()),
    }
}

fn lock_database(path: &Path, exclusive: bool) -> Result<File, Error> {
    lock_sidecar(path, ".osv-lock", exclusive)
}

fn lock_sidecar(path: &Path, suffix: &str, exclusive: bool) -> Result<File, Error> {
    // Leave the sidecar in place so concurrent opens always lock the same inode.
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(suffix);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    match if exclusive {
        lock.try_lock()
    } else {
        lock.try_lock_shared()
    } {
        Ok(()) => Ok(lock),
        Err(TryLockError::WouldBlock) => Err(Error::InUse(path.into())),
        Err(TryLockError::Error(error)) => Err(error.into()),
    }
}
