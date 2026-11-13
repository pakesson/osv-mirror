mod history;

use std::path::Path;

use percent_encoding::percent_decode_str;
use rusqlite::{Connection, params};
use serde::Deserialize;
use serde_json::value::RawValue;
use url::{Position, Url};

use crate::{Error, PackagePage, PackageSearch, Store, versions};

pub use history::GitIndexReport;

/// The host and decoded path used by OSV.dev repository queries.
pub fn normalize_repository(repository: &str) -> Option<String> {
    let url = Url::parse(repository).ok()?;
    url.host_str()?;
    let host = &url[Position::BeforeHost..Position::AfterPort];
    let path = percent_decode_str(url.path()).decode_utf8().ok()?;
    let key = format!("{host}{path}").to_lowercase();
    let key = key.trim_end_matches('/');
    let key = key.strip_suffix(".git").unwrap_or(key);
    (!key.chars().any(char::is_control)).then(|| key.to_owned())
}

#[derive(Deserialize)]
struct RangeIdentity<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    #[serde(borrow)]
    repo: Option<&'a RawValue>,
}

pub(crate) fn index_ranges(
    connection: &Connection,
    id: &str,
    ordinal: i64,
    ranges: Option<&RawValue>,
) -> Result<(), Error> {
    let Some(ranges) =
        ranges.and_then(|raw| serde_json::from_str::<Vec<&RawValue>>(raw.get()).ok())
    else {
        return Ok(());
    };
    let mut insert = connection.prepare_cached("INSERT INTO git_ranges VALUES (?1, ?2, ?3, ?4)")?;
    for (index, range) in ranges.into_iter().enumerate() {
        let Ok(identity) = serde_json::from_str::<RangeIdentity<'_>>(range.get()) else {
            continue;
        };
        if identity.kind != "GIT" {
            continue;
        }
        // Keep an unresolvable range visible to the unscoped coverage check.
        let repo = identity
            .repo
            .and_then(|value| serde_json::from_str::<String>(value.get()).ok())
            .and_then(|repo| normalize_repository(&repo))
            .unwrap_or_default();
        insert.execute(params![repo, id, ordinal, index as i64])?;
    }
    Ok(())
}

pub(crate) fn tag_candidates(
    connection: &Connection,
    repo: &str,
    after: &str,
    limit: usize,
) -> Result<Vec<String>, Error> {
    let mut query = connection.prepare_cached(
        "SELECT DISTINCT advisory_id FROM git_ranges
         WHERE repo = ?1 AND advisory_id > ?2 ORDER BY advisory_id LIMIT ?3",
    )?;
    let rows = query.query_map(params![repo, after, limit as i64], |row| row.get(0))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub(crate) fn matches_tag(
    connection: &Connection,
    id: &str,
    repo: &str,
    tag: &str,
) -> Result<bool, Error> {
    let mut query = connection.prepare_cached(
        "SELECT json_extract(a.json, '$.affected[' || r.affected_ordinal || '].versions')
         FROM git_ranges r JOIN advisories a ON a.id = r.advisory_id
         WHERE r.repo = ?1 AND r.advisory_id = ?2 GROUP BY r.affected_ordinal",
    )?;
    let mut rows = query.query(params![repo, id])?;
    let (project, owner) = {
        let mut parts = repo.rsplit('/');
        (
            parts.next().unwrap_or_default(),
            parts.next().unwrap_or_default(),
        )
    };
    let mut uncertain = false;
    while let Some(row) = rows.next()? {
        let Some(json) = row.get::<_, Option<String>>(0)? else {
            continue;
        };
        let Ok(tags) = serde_json::from_str::<Vec<String>>(&json) else {
            uncertain = true;
            continue;
        };
        if tags.iter().any(|listed| {
            if listed == tag {
                return true;
            }
            let lower = listed.to_lowercase();
            let stripped = lower.strip_prefix(owner).unwrap_or(&lower);
            let stripped = stripped.strip_prefix(project).unwrap_or(stripped);
            versions::fuzzy_equal(tag, stripped.strip_prefix('-').unwrap_or(stripped))
        }) {
            return Ok(true);
        }
    }
    if uncertain {
        return Err(Error::UnsupportedMatch {
            id: id.into(),
            ecosystem: "GIT".into(),
        });
    }
    Ok(false)
}

impl Store {
    /// Build and publish an affected-commit index from an operator-supplied mirror.
    pub fn index_git(&self, repository: &str, mirror: &Path) -> Result<GitIndexReport, Error> {
        history::build(&self.path, repository, mirror)
    }
}

impl PackageSearch<'_> {
    pub fn commit_page(
        &self,
        sha: &str,
        repo: Option<&str>,
        after: &str,
        limit: usize,
        json_budget: Option<usize>,
    ) -> Result<PackagePage, Error> {
        let connection = &self.transaction;
        let missing: bool = connection.query_row(
            "SELECT EXISTS (
                 SELECT 1 FROM git_ranges r WHERE (?1 IS NULL OR r.repo = ?1)
                 AND NOT EXISTS (SELECT 1 FROM git_coverage c WHERE c.repo = r.repo AND c.revision = ?2)
             )",
            params![repo, self.revision], |row| row.get(0),
        )?;
        if missing {
            return Err(Error::GitUnavailable(
                "one or more repositories need a current commit index".into(),
            ));
        }
        let known: bool = if let Some(repo) = repo {
            connection.query_row(
                "SELECT EXISTS (SELECT 1 FROM git_commits g JOIN git_coverage c USING(repo)
                  WHERE g.repo = ?1 AND g.sha = ?2 AND c.revision = ?3)",
                params![repo, sha, self.revision],
                |row| row.get(0),
            )?
        } else {
            connection.query_row(
                "SELECT EXISTS (SELECT 1 FROM git_commits g JOIN git_coverage c USING(repo)
                  WHERE g.sha = ?1 AND c.revision = ?2)",
                params![sha, self.revision],
                |row| row.get(0),
            )?
        };
        if !known {
            return Err(Error::GitUnavailable(
                "commit is outside indexed repository history".into(),
            ));
        }

        let mut statement = connection.prepare_cached(
            "SELECT DISTINCT m.advisory_id FROM git_matches m JOIN git_coverage c USING(repo)
             WHERE m.sha = ?1 AND m.advisory_id > ?2 AND c.revision = ?3
             AND (?4 IS NULL OR m.repo = ?4)
             ORDER BY m.advisory_id LIMIT ?5",
        )?;
        let ids = statement
            .query_map(
                params![sha, after, self.revision, repo, limit as i64 + 1],
                |row| row.get(0),
            )?
            .collect::<Result<Vec<String>, _>>()?;
        self.hydrate_page(ids, after, limit, limit, json_budget, |_, _| Ok(true))
    }
}
