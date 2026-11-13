use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::path::Path;
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{StreamExt, TryStreamExt, stream};
use md5::Md5;
use osv_store::{Advisory, Candidate, SyncWriter, Validators};
use reqwest::{Client, StatusCode, Url, header};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncWriteExt, BufWriter};

use crate::inventory;

pub const EXPORT_BASE_URL: &str = "https://storage.googleapis.com/osv-vulnerabilities";
const MAX_CSV_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
const DOWNLOAD_CONCURRENCY: usize = 8;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error(transparent)]
    Store(#[from] osv_store::Error),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Csv(#[from] csv::Error),
    #[error("invalid export base URL: {0}")]
    BaseUrl(String),
    #[error("inventory request returned HTTP {0}")]
    InventoryStatus(StatusCode),
    #[error("invalid inventory: {0}")]
    InvalidInventory(&'static str),
    #[error("inventory row {row}: {message}")]
    InventoryRow { row: usize, message: String },
    #[error("cannot download current advisory {id}: {reason}")]
    Advisory { id: String, reason: String },
    #[error("sync worker failed: {0}")]
    Worker(#[from] tokio::task::JoinError),
}

/// Synchronize an existing full snapshot from an OSV export bucket.
pub async fn sync(database: &Path, base_url: &str) -> Result<osv_store::SyncReport, SyncError> {
    let base = Url::parse(base_url).map_err(|error| SyncError::BaseUrl(error.to_string()))?;
    if !matches!(base.scheme(), "http" | "https")
        || base.host().is_none()
        || base.query().is_some()
        || base.fragment().is_some()
        || !base.username().is_empty()
        || base.password().is_some()
    {
        return Err(SyncError::BaseUrl(
            "expected HTTP(S) without credentials, query or fragment".into(),
        ));
    }
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let url = endpoint(&base, &["modified_id.csv"]);
    let database = database.to_owned();
    let feed = url.to_string();
    let mut writer =
        tokio::task::spawn_blocking(move || SyncWriter::open(&database, &feed)).await??;
    // Refresh once if the inventory points at unavailable or stale objects.
    for refresh in [false, true] {
        // GCS can reuse a content-based ETag for a new generation. Fetch the
        // current representation when pending removals need confirmation.
        let validators = if refresh || writer.state().pending_absences > 0 {
            None
        } else {
            Some(&writer.state().validators)
        };
        let inventory = fetch_inventory(&client, url.clone(), validators).await?;
        let Some(inventory) = inventory else {
            return tokio::task::spawn_blocking(move || writer.finish(None))
                .await?
                .map_err(Into::into);
        };
        writer.check_generation(&inventory.validators)?;
        let digest = inventory.digest;
        let validators = inventory.validators;
        if !writer.needs_reconciliation(&digest, &validators) {
            return finish(writer, digest, validators).await;
        }
        writer = work(writer, move |writer| {
            writer.reset_staging()?;
            inventory::load(writer, inventory.file)?;
            writer.plan()?;
            Ok(())
        })
        .await?
        .0;
        match fetch_updates(writer, &client, &base).await? {
            (staged, Ok(())) => return finish(staged, digest, validators).await,
            (staged, Err(_)) if !refresh => writer = staged,
            (_, Err(error)) => return Err(error),
        }
    }
    unreachable!("the refresh attempt returns its result")
}

async fn work<T: Send + 'static>(
    mut writer: SyncWriter,
    operation: impl FnOnce(&mut SyncWriter) -> Result<T, SyncError> + Send + 'static,
) -> Result<(SyncWriter, T), SyncError> {
    tokio::task::spawn_blocking(move || {
        let result = operation(&mut writer)?;
        Ok((writer, result))
    })
    .await?
}

async fn finish(
    writer: SyncWriter,
    digest: String,
    validators: Validators,
) -> Result<osv_store::SyncReport, SyncError> {
    tokio::task::spawn_blocking(move || writer.finish(Some((&digest, &validators))))
        .await?
        .map_err(Into::into)
}

struct Inventory {
    file: File,
    digest: String,
    validators: Validators,
}

async fn fetch_inventory(
    client: &Client,
    url: Url,
    validators: Option<&Validators>,
) -> Result<Option<Inventory>, SyncError> {
    let mut request = client.get(url);
    let mut conditional = false;
    if let Some(validators) = validators {
        if let Some(etag) = &validators.etag {
            request = request.header(header::IF_NONE_MATCH, etag);
            conditional = true;
        } else if let Some(last_modified) = &validators.last_modified {
            request = request.header(header::IF_MODIFIED_SINCE, last_modified);
            conditional = true;
        }
    } else {
        request = request.header(header::CACHE_CONTROL, "no-cache");
    }
    let mut response = request.send().await?;
    match response.status() {
        StatusCode::NOT_MODIFIED if conditional => return Ok(None),
        StatusCode::OK => {}
        status => return Err(SyncError::InventoryStatus(status)),
    }
    let get_header = |name| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let validators = Validators {
        etag: get_header("etag"),
        last_modified: get_header("last-modified"),
        generation: get_header("x-goog-generation"),
    };
    let expected = response.content_length();
    let expected_md5 = crate::download::gcs_md5(response.headers()).map(str::to_owned);
    let mut md5 = expected_md5.as_ref().map(|_| Md5::new());
    if expected.is_some_and(|length| length > MAX_CSV_BYTES) {
        return Err(SyncError::InvalidInventory("inventory exceeds 2 GiB"));
    }
    let file = tempfile::tempfile()?;
    let mut output = BufWriter::with_capacity(1024 * 1024, tokio::fs::File::from_std(file));
    let mut digest = Sha256::new();
    let mut bytes = 0;
    let mut framing = inventory::Framing::default();
    while let Some(chunk) = response.chunk().await? {
        bytes += chunk.len() as u64;
        if bytes > MAX_CSV_BYTES {
            return Err(SyncError::InvalidInventory("inventory exceeds 2 GiB"));
        }
        framing.check_chunk(&chunk)?;
        if let Some(md5) = &mut md5 {
            md5.update(&chunk);
        }
        digest.update(&chunk);
        output.write_all(&chunk).await?;
    }
    if expected.is_some_and(|expected| expected != bytes) || !framing.at_line_end() {
        return Err(SyncError::InvalidInventory(
            "inventory ended before a complete export",
        ));
    }
    if let Some((expected, md5)) = expected_md5.zip(md5)
        && STANDARD.encode(md5.finalize()) != expected
    {
        return Err(SyncError::InvalidInventory("inventory checksum mismatch"));
    }
    output.flush().await?;
    let mut file = output.into_inner().into_std().await;
    file.seek(SeekFrom::Start(0))?;
    Ok(Some(Inventory {
        file,
        digest: format!("{:x}", digest.finalize()),
        validators,
    }))
}

async fn fetch_updates(
    mut writer: SyncWriter,
    client: &Client,
    base: &Url,
) -> Result<(SyncWriter, Result<(), SyncError>), SyncError> {
    let mut after = String::new();
    loop {
        let (next_writer, candidates) = work(writer, move |writer| {
            Ok(writer.candidates(&after, DOWNLOAD_CONCURRENCY)?)
        })
        .await?;
        writer = next_writer;
        let Some(last) = candidates.last() else {
            return Ok((writer, Ok(())));
        };
        after = last.id.clone();
        let bodies: Result<Vec<_>, _> = stream::iter(candidates)
            .map(|candidate| fetch_advisory(client, base, candidate))
            .buffer_unordered(DOWNLOAD_CONCURRENCY)
            .try_collect()
            .await;
        match bodies {
            Ok(bodies) => {
                writer = work(writer, move |writer| Ok(writer.stage(&bodies)?))
                    .await?
                    .0;
            }
            Err(error) => return Ok((writer, Err(error))),
        }
    }
}

async fn fetch_advisory(
    client: &Client,
    base: &Url,
    candidate: Candidate,
) -> Result<(String, String), SyncError> {
    let filename = format!("{}.json", candidate.id);
    let mut reasons = Vec::new();
    for attempt in 0..2 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        reasons.clear();
        for ecosystem in &candidate.ecosystems {
            let url = endpoint(base, &[ecosystem, &filename]);
            match read_advisory(client, url, &candidate).await {
                Ok(json) => return Ok((candidate.id, json)),
                Err(reason) => reasons.push(format!("{ecosystem}: {reason}")),
            }
        }
    }
    Err(SyncError::Advisory {
        id: candidate.id,
        reason: reasons.join("; "),
    })
}

async fn read_advisory(client: &Client, url: Url, candidate: &Candidate) -> Result<String, String> {
    let mut response = client
        .get(url)
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if response.status() != StatusCode::OK {
        return Err(format!("HTTP {}", response.status()));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BODY_BYTES as u64)
    {
        return Err("body exceeds 32 MiB".into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| error.to_string())? {
        if chunk.len() > MAX_BODY_BYTES - body.len() {
            return Err("body exceeds 32 MiB".into());
        }
        body.extend_from_slice(&chunk);
    }
    let json = String::from_utf8(body).map_err(|error| error.to_string())?;
    let advisory = Advisory::parse(&json).map_err(|error| error.to_string())?;
    if advisory.id() != candidate.id {
        return Err(format!("unexpected advisory ID {:?}", advisory.id()));
    }
    if advisory.modified_key() < candidate.modified_key.as_str() {
        return Err("advisory is older than its inventory row".into());
    }
    Ok(json)
}

fn endpoint(base: &Url, segments: &[&str]) -> Url {
    let mut url = base.clone();
    url.path_segments_mut()
        .expect("validated HTTP base URL")
        .pop_if_empty()
        .extend(segments);
    url
}
