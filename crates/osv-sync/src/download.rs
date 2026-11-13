use std::io;
use std::path::Path;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use md5::{Digest, Md5};
use reqwest::{StatusCode, header::HeaderMap};
use tempfile::NamedTempFile;
use thiserror::Error;
use tokio::io::{AsyncWriteExt, BufWriter};

use crate::{MAX_ARCHIVE_BYTES, archive::open_archive};

pub const ALL_ZIP_URL: &str = "https://storage.googleapis.com/osv-vulnerabilities/all.zip";

#[derive(Debug, Error)]
pub enum DownloadError {
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("expected HTTP 200 for the OSV ZIP, got {0}")]
    Status(StatusCode),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("download exceeds the 16 GiB ZIP limit")]
    TooLarge,
    #[error("incomplete download: expected {expected} bytes, received {actual}")]
    Incomplete { expected: u64, actual: u64 },
    #[error("download does not match the export's MD5 checksum")]
    Checksum,
    #[error(transparent)]
    InvalidZip(#[from] crate::ImportError),
    #[error("ZIP publication worker failed: {0}")]
    Worker(#[from] tokio::task::JoinError),
}

/// Stream a complete archive to a temporary file, then publish it atomically.
///
/// Checks the response length and GCS MD5 when available, and verifies the ZIP
/// directory before publication. Entry data is decompressed and verified on import.
pub async fn download_zip(url: &str, output: &Path) -> Result<u64, DownloadError> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(60))
        .build()?;
    let mut response = client.get(url).send().await?;
    if response.status() != StatusCode::OK {
        return Err(DownloadError::Status(response.status()));
    }

    let expected = response.content_length();
    if expected.is_some_and(|size| size > MAX_ARCHIVE_BYTES) {
        return Err(DownloadError::TooLarge);
    }
    let expected_md5 = gcs_md5(response.headers()).map(str::to_owned);
    let mut digest = expected_md5.as_ref().map(|_| Md5::new());

    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temp = NamedTempFile::new_in(parent)?;
    let mut writer =
        BufWriter::with_capacity(1024 * 1024, tokio::fs::File::from_std(temp.reopen()?));
    let mut bytes = 0;
    while let Some(chunk) = response.chunk().await? {
        bytes += chunk.len() as u64;
        if bytes > MAX_ARCHIVE_BYTES {
            return Err(DownloadError::TooLarge);
        }
        if let Some(digest) = &mut digest {
            digest.update(&chunk);
        }
        writer.write_all(&chunk).await?;
    }
    if let Some(expected) = expected
        && expected != bytes
    {
        return Err(DownloadError::Incomplete {
            expected,
            actual: bytes,
        });
    }
    if let Some((expected, digest)) = expected_md5.zip(digest)
        && STANDARD.encode(digest.finalize()) != expected
    {
        return Err(DownloadError::Checksum);
    }
    writer.flush().await?;
    writer.get_ref().sync_all().await?;
    drop(writer);

    let output = output.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut directory = vec![0; rawzip::RECOMMENDED_BUFFER_SIZE];
        let archive = open_archive(temp.reopen()?, &mut directory)?;
        let mut entries = archive.entries(&mut directory);
        for _ in 0..archive.entries_hint() {
            if entries
                .next_entry()
                .map_err(crate::ImportError::from)?
                .is_none()
            {
                return Err(crate::ImportError::InvalidArchive(
                    "central directory entry count mismatch",
                )
                .into());
            }
        }
        if entries
            .next_entry()
            .map_err(crate::ImportError::from)?
            .is_some()
        {
            return Err(crate::ImportError::InvalidArchive(
                "central directory entry count mismatch",
            )
            .into());
        }
        drop(archive);
        temp.persist(output).map_err(|error| error.error)?;
        Ok(bytes)
    })
    .await?
}

pub(crate) fn gcs_md5(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all("x-goog-hash")
        .iter()
        .filter_map(|header| header.to_str().ok())
        .flat_map(|header| header.split(','))
        .find_map(|hash| hash.trim().strip_prefix("md5="))
}
