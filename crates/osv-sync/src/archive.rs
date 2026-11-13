use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use flate2::{Decompress, FlushDecompress, Status};
use osv_store::{Advisory, SnapshotWriter};
use rawzip::{CompressionMethod, FileReader, ZipArchive, ZipFileHeaderRecord, ZipVerification};
use thiserror::Error;

use crate::{MAX_ARCHIVE_BYTES, MAX_ENTRIES};

const MAX_ENTRY_BYTES: u64 = 32 * 1024 * 1024;
const MAX_INFLATED_BYTES: u64 = 64 * 1024 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ImportError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("invalid ZIP archive: {0}")]
    Zip(#[from] rawzip::Error),
    #[error("invalid ZIP archive: {0}")]
    InvalidArchive(&'static str),
    #[error("ZIP entry {name:?}: {message}")]
    Entry { name: String, message: String },
    #[error(transparent)]
    Store(#[from] osv_store::Error),
}

#[derive(Debug, PartialEq, Eq)]
pub struct ImportReport {
    pub entries: u64,
    pub advisories: u64,
    pub uncompressed_bytes: u64,
}

/// Import an existing OSV ZIP into a staged database and atomically publish it.
///
/// This performs synchronous file and database work. Async callers should run
/// it on a blocking worker.
pub fn import_zip(zip: &Path, database: &Path) -> Result<ImportReport, ImportError> {
    let mut directory = vec![0; rawzip::RECOMMENDED_BUFFER_SIZE];
    let archive = open_archive(File::open(zip)?, &mut directory)?;
    let mut entries = archive.entries(&mut directory);
    let mut snapshot = SnapshotWriter::new(database)?;
    let mut decoder = Decompress::new(false);
    let mut compressed = Vec::new();
    let mut decoded = Vec::new();
    let mut count = 0;
    let mut uncompressed_bytes = 0;

    while let Some(entry) = entries.next_entry()? {
        count += 1;
        if count > archive.entries_hint() {
            return Err(ImportError::InvalidArchive(
                "central directory entry count mismatch",
            ));
        }
        let size = entry.uncompressed_size_hint();
        if size > MAX_INFLATED_BYTES - uncompressed_bytes {
            return Err(ImportError::InvalidArchive(
                "uncompressed archive exceeds 64 GiB",
            ));
        }
        uncompressed_bytes += size;

        let path = entry.file_path();
        let name = std::str::from_utf8(path.as_ref())
            .map_err(|_| ImportError::InvalidArchive("entry filename is not UTF-8"))?;
        let invalid_entry = |message: String| ImportError::Entry {
            name: name.into(),
            message,
        };
        let id = name
            .strip_suffix(".json")
            .filter(|id| osv_schema::is_indexable_id(id))
            .ok_or_else(|| invalid_entry("expected a root-level OSV advisory filename".into()))?;

        let data = read_entry(
            &archive,
            &entry,
            &mut decoder,
            &mut compressed,
            &mut decoded,
        )
        .map_err(invalid_entry)?;
        let json = std::str::from_utf8(data).map_err(|error| invalid_entry(error.to_string()))?;
        let advisory = Advisory::parse(json).map_err(|error| invalid_entry(error.to_string()))?;
        if advisory.id() != id {
            return Err(invalid_entry(format!(
                "advisory ID {:?} does not match filename",
                advisory.id()
            )));
        }
        snapshot
            .insert(&advisory)
            .map_err(|error| invalid_entry(error.to_string()))?;
    }

    if count != archive.entries_hint() {
        return Err(ImportError::InvalidArchive(
            "central directory entry count mismatch",
        ));
    }
    let advisories = snapshot.publish()?;
    Ok(ImportReport {
        entries: count,
        advisories,
        uncompressed_bytes,
    })
}

pub(crate) fn open_archive(
    file: File,
    directory: &mut [u8],
) -> Result<ZipArchive<FileReader>, ImportError> {
    let size = file.metadata()?.len();
    if size > MAX_ARCHIVE_BYTES {
        return Err(ImportError::InvalidArchive(
            "compressed archive exceeds 16 GiB",
        ));
    }
    let archive = ZipArchive::from_file(file, directory)?;
    if archive.end_offset() != size {
        return Err(ImportError::InvalidArchive(
            "ZIP end record does not match file length",
        ));
    }
    if !(1..=MAX_ENTRIES).contains(&archive.entries_hint()) {
        return Err(ImportError::InvalidArchive(
            "expected 1 to 10,000,000 ZIP entries",
        ));
    }
    Ok(archive)
}

fn read_entry<'a>(
    archive: &ZipArchive<FileReader>,
    header: &ZipFileHeaderRecord<'_>,
    decoder: &mut Decompress,
    compressed: &'a mut Vec<u8>,
    decoded: &'a mut Vec<u8>,
) -> Result<&'a [u8], String> {
    let size = header.uncompressed_size_hint();
    let compressed_size = header.compressed_size_hint();
    if size > MAX_ENTRY_BYTES || compressed_size > MAX_ENTRY_BYTES + 1024 * 1024 {
        return Err("entry exceeds the compressed or uncompressed size limit".into());
    }
    if header.flags().is_encrypted() || header.mode().is_symlink() {
        return Err("encrypted and symbolic link entries are unsupported".into());
    }
    let entry = archive
        .get_entry(header.wayfinder())
        .map_err(|error| error.to_string())?;
    if entry.compressed_data_range().1 > archive.directory_offset() {
        return Err("entry data extends into the central directory".into());
    }

    compressed.resize(compressed_size as usize, 0);
    entry
        .reader()
        .read_exact(compressed)
        .map_err(|error| error.to_string())?;
    let data = match header.compression_method() {
        CompressionMethod::STORE => compressed.as_slice(),
        CompressionMethod::DEFLATE => {
            // An extra byte allows the inflater to detect an understated size.
            decoded.resize(size as usize + 1, 0);
            decoder.reset(false);
            let status = decoder
                .decompress(compressed, decoded, FlushDecompress::Finish)
                .map_err(|error| error.to_string())?;
            if status != Status::StreamEnd || decoder.total_in() != compressed_size {
                return Err("incomplete DEFLATE stream or incorrect entry size".into());
            }
            &decoded[..decoder.total_out() as usize]
        }
        method => return Err(format!("unsupported ZIP compression method {method:?}")),
    };
    entry
        .reader()
        .claim_verifier()
        .valid(ZipVerification {
            crc: crc32fast::hash(data),
            uncompressed_size: data.len() as u64,
        })
        .map_err(|error| error.to_string())?;
    Ok(data)
}
