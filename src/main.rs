use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use osv_store::{Reconciliation, Store};
use osv_sync::{ALL_ZIP_URL, EXPORT_BASE_URL, download_zip, import_zip, sync};
use tokio::net::TcpListener;

#[derive(Parser)]
#[command(about = "Download, import, and serve an OSV vulnerability mirror")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Download the OSV export ZIP over HTTP.
    Download {
        #[arg(long, default_value = "all.zip")]
        output: PathBuf,
        #[arg(long, default_value = ALL_ZIP_URL)]
        url: String,
    },
    /// Build and publish a SQLite database from an existing ZIP.
    Import {
        #[arg(long)]
        zip: PathBuf,
        #[arg(long)]
        db: PathBuf,
    },
    /// Update a full SQLite mirror from the OSV export inventory.
    Sync {
        #[arg(long)]
        db: PathBuf,
        #[arg(long, default_value = EXPORT_BASE_URL)]
        base_url: String,
    },
    /// Build a local affected-commit index using a provisioned Git repository.
    IndexGit {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        repository: String,
        #[arg(long)]
        mirror: PathBuf,
    },
    /// Serve advisory lookups and package queries from a local SQLite database.
    Serve {
        #[arg(long)]
        db: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: SocketAddr,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    match Cli::parse().command {
        Command::Download { output, url } => {
            let bytes = download_zip(&url, &output).await?;
            println!("Downloaded {bytes} bytes to {}", output.display());
        }
        Command::Import { zip, db } => {
            let target = db.clone();
            let report = tokio::task::spawn_blocking(move || import_zip(&zip, &target)).await??;
            println!(
                "Imported {} advisories from {} ZIP entries ({} uncompressed bytes) into {}",
                report.advisories,
                report.entries,
                report.uncompressed_bytes,
                db.display()
            );
        }
        Command::Sync { db, base_url } => {
            let report = sync(&db, &base_url).await?;
            println!(
                "Revision {}: {} updated, {} removed, {} pending absences",
                report.revision, report.updated, report.removed, report.pending_absences
            );
            match report.reconciliation {
                Reconciliation::Unchanged => println!("Inventory unchanged"),
                Reconciliation::Checked => println!("Inventory reconciled"),
                Reconciliation::Incomplete { missing, limit } => eprintln!(
                    "Skipped removal reconciliation: {missing} advisories absent, exceeding the limit of {limit}"
                ),
            }
        }
        Command::IndexGit {
            db,
            repository,
            mirror,
        } => {
            let report = tokio::task::spawn_blocking(move || {
                Store::open(&db)?.index_git(&repository, &mirror)
            })
            .await??;
            println!(
                "Indexed {} commits and {} advisory matches from {} Git ranges",
                report.commits, report.matches, report.ranges
            );
        }
        Command::Serve { db, bind } => {
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .init();
            let store = tokio::task::spawn_blocking(move || {
                let store = Store::open(&db)?;
                store.prepare_queries()?;
                Ok::<_, osv_store::Error>(store)
            })
            .await??;
            let listener = TcpListener::bind(bind).await?;
            println!("Serving OSV queries at http://{}", listener.local_addr()?);
            axum::serve(listener, osv_server::router(store))
                .with_graceful_shutdown(async {
                    if let Err(error) = tokio::signal::ctrl_c().await {
                        eprintln!("Cannot listen for Ctrl-C: {error}");
                    }
                })
                .await?;
        }
    }
    Ok(())
}
