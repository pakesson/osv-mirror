//! Download and import OSV.dev ZIP exports.

mod archive;
mod download;
mod incremental;
mod inventory;

pub use archive::{ImportError, ImportReport, import_zip};
pub use download::{ALL_ZIP_URL, DownloadError, download_zip};

pub use incremental::{EXPORT_BASE_URL, SyncError, sync};

const MAX_ARCHIVE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_ENTRIES: u64 = 10_000_000;
