# osv-mirror

`osv-mirror` is a CLI tool for mirroring the [Open Source Vulnerabilities (OSV)](https://osv.dev/) database in SQLite and serving it through an OSV.dev-compatible HTTP API.

Features:
- Download the full OSV database dump, import an existing ZIP, and apply incremental updates.
- Look up advisories by ID and query packages, versions, and PURLs individually or in batches.
- Query Git tags from exported advisories and index affected commits from local Git mirrors.

## Building

Run these commands from the repository root. The build requires Rust, Cargo, and a C toolchain.

```sh
cargo build --release --locked
```

Run the binary with `./target/release/osv-mirror --help`.

Alternatively, `osv-mirror` can be installed with:
```sh
cargo install --path . --locked
```

## Usage

Download the database dump and import it into a local database:
```sh
osv-mirror download && osv-mirror import --zip all.zip --db osv.sqlite
```
If you already have `all.zip`, run the import command directly. Stop the server before replacing a database with a full import.

Update the mirror and start the server:
```sh
osv-mirror sync --db osv.sqlite
osv-mirror serve --db osv.sqlite
```

Run `sync` again as needed while the server is running.

From another terminal, look up an advisory, query a package by PURL, or send a batch that includes a Git tag query.

```sh
curl http://127.0.0.1:8080/v1/vulns/GHSA-jfh8-c2jp-5v3q
curl --json '{"package":{"purl":"pkg:pypi/jinja2@3.1.4"}}' http://127.0.0.1:8080/v1/query
curl --json '{"queries":[{"package":{"ecosystem":"PyPI","name":"jinja2"}},{"package":{"ecosystem":"GIT","name":"https://github.com/curl/curl.git"},"version":"8.5.0"}]}' http://127.0.0.1:8080/v1/querybatch
```

For commit queries, index a full local Git mirror and send a full commit hash with its repository.

```sh
git clone --mirror https://github.com/curl/curl.git curl.git
osv-mirror index-git --db osv.sqlite --repository https://github.com/curl/curl.git --mirror curl.git
curl --json "{\"commit\":\"$(git -C curl.git rev-parse HEAD)\",\"package\":{\"ecosystem\":\"GIT\",\"name\":\"https://github.com/curl/curl.git\"}}" http://127.0.0.1:8080/v1/query
```

Commit queries return HTTP 503 for missing or stale coverage. A commit query without a repository requires current indexes for all repositories with active Git ranges. Refresh the mirrors and rebuild their indexes after an advisory revision changes.

## Command-line arguments

| Command | Arguments |
| --- | --- |
| `download` | `--output` ZIP destination (default `all.zip`). `--url` export URL (default OSV.dev full export). |
| `import` | `--zip` input archive. `--db` SQLite destination. |
| `sync` | `--db` existing SQLite mirror. `--base-url` export root (default OSV.dev export bucket). |
| `serve` | `--db` SQLite mirror. `--bind` listen address (default `127.0.0.1:8080`). |
| `index-git` | `--db` SQLite mirror. `--repository` advisory repository URL. `--mirror` path to a full local Git mirror. |

## Use the Rust crates in another project

### Query OSV.dev with `osv-api`

With a checkout of `osv-mirror` beside your project, add these dependencies to your `Cargo.toml`.

```toml
[dependencies]
osv-api = { path = "../osv-mirror/crates/osv-api" }
tokio = { version = "1", features = ["macros", "rt"] }
```

Look up an advisory by ID and query all pages of results for a versioned PURL.

```rust
use osv_api::{Client, Query};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new()?;
    let advisory = client.get_vulnerability("GHSA-jfh8-c2jp-5v3q").await?;
    println!("{}", advisory.id);

    let query = Query::for_purl("pkg:pypi/jinja2@3.1.4");
    for advisory in client.query_all(&query).await? {
        println!("{}", advisory.id);
    }
    Ok(())
}
```

Use `client.query_batch_all(&[query_a, query_b]).await?` for multiple packages. Results contain advisory IDs and modification timestamps in input order. Set `Client::builder().base_url("http://127.0.0.1:8080").build()?` to query a running local mirror.

### Validate an advisory with `osv-schema`

Use `osv-schema` directly to validate and parse OSV JSON offline.

```toml
[dependencies]
osv-schema = { path = "../osv-mirror/crates/osv-schema" }
serde_json = "1"
```

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let json = std::fs::read_to_string("advisory.json")?;
    let document = serde_json::from_str(&json)?;
    osv_schema::validate_json(&document)?;

    let advisory = osv_schema::from_json(&json)?;
    println!("{}", advisory.id);
    Ok(())
}
```

## License

This project is licensed under the terms in the repository LICENSE file.
