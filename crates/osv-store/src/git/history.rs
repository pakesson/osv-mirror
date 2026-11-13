use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};

use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use serde::Deserialize;

use super::normalize_repository;
use crate::{Error, check_schema, database_path, incremental, lock_database, lock_sidecar};

#[derive(Debug)]
pub struct GitIndexReport {
    pub commits: usize,
    pub matches: usize,
    pub ranges: usize,
}

pub(super) fn build(path: &Path, repository: &str, mirror: &Path) -> Result<GitIndexReport, Error> {
    let repo =
        normalize_repository(repository).ok_or_else(|| history_error("invalid repository URL"))?;
    let path = database_path(path)?;
    let _publication = lock_database(&path, false)?;
    let _writer = lock_sidecar(&path, ".osv-sync-lock", true)?;
    let mut connection = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let version = check_schema(&connection, &path)?;
    connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA temp_store = FILE;")?;
    incremental::migrate(&connection, version)?;
    let revision = revision(&connection)?;
    let mut report = GitIndexReport {
        commits: 0,
        matches: 0,
        ranges: 0,
    };

    let graph = Graph::read(mirror)?;
    report.commits = graph.nodes.len();
    connection.execute_batch(
        "CREATE TEMP TABLE staged_matches (
             sha TEXT NOT NULL, advisory_id TEXT NOT NULL, PRIMARY KEY (sha, advisory_id)
         ) WITHOUT ROWID;",
    )?;
    {
        let stage = connection.transaction()?;
        let mut ranges = stage.prepare(
            "SELECT r.advisory_id, json_extract(a.json, '$.affected[' || r.affected_ordinal ||
                      '].ranges[' || r.range_ordinal || '].events')
             FROM git_ranges r JOIN advisories a ON a.id = r.advisory_id WHERE r.repo = ?1",
        )?;
        let mut insert = stage.prepare("INSERT OR IGNORE INTO staged_matches VALUES (?1, ?2)")?;
        let mut rows = ranges.query([&repo])?;
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let json: Option<String> = row.get(1)?;
            let affected = graph
                .affected(json.as_deref().unwrap_or_default())
                .map_err(|error| history_error(format!("{id} in {repository}: {error}")))?;
            for (node, affected) in graph.nodes.iter().zip(affected) {
                if affected {
                    report.matches += insert.execute(params![node.sha, id])?;
                }
            }
            report.ranges += 1;
        }
        drop(rows);
        drop(ranges);
        drop(insert);
        stage.commit()?;
    }

    let publish = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if self::revision(&publish)? != revision {
        return Err(Error::RevisionChanged);
    }
    publish.execute("DELETE FROM git_coverage WHERE repo = ?1", [&repo])?;
    publish.execute(
        "INSERT INTO git_coverage VALUES (?1, ?2)",
        params![repo, revision],
    )?;
    {
        let mut insert = publish.prepare("INSERT INTO git_commits VALUES (?1, ?2)")?;
        for node in graph.nodes {
            insert.execute(params![repo, node.sha])?;
        }
    }
    publish.execute(
        "INSERT INTO git_matches SELECT ?1, sha, advisory_id FROM staged_matches",
        [&repo],
    )?;
    // Invalidate cursors even when only the supplied history has changed.
    publish.execute(
        "UPDATE query_snapshot SET id = lower(hex(randomblob(16)))",
        [],
    )?;
    publish.commit()?;
    Ok(report)
}

fn revision(connection: &Connection) -> Result<i64, Error> {
    Ok(connection.query_row(
        "SELECT revision FROM sync_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?)
}

fn history_error(message: impl Into<String>) -> Error {
    Error::GitHistory(message.into())
}

struct Node {
    sha: String,
    parents: Vec<usize>,
}

struct Graph {
    nodes: Vec<Node>,
    lookup: HashMap<String, usize>,
}

fn git(mirror: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .args([
            "--no-replace-objects",
            "-c",
            "advice.graftFileDeprecated=false",
            "-C",
        ])
        .arg(mirror)
        .env("GIT_NO_LAZY_FETCH", "1")
        .env(
            "GIT_GRAFT_FILE",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .env_remove("GIT_DIR")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES");
    command
}

impl Graph {
    fn read(mirror: &Path) -> Result<Self, Error> {
        let shallow = git(mirror)
            .args(["rev-parse", "--is-shallow-repository"])
            .output()?;
        if !shallow.status.success() || shallow.stdout != b"false\n" {
            return Err(history_error(
                "expected a full, non-shallow local Git repository",
            ));
        }

        let mut child = git(mirror)
            .args([
                "rev-list",
                "--topo-order",
                "--reverse",
                "--parents",
                "--all",
            ])
            .stdout(Stdio::piped())
            .spawn()?;
        let reader = BufReader::new(child.stdout.take().expect("Git stdout is piped"));
        let graph = Self::parse(reader);
        let status = child.wait()?;
        if !status.success() {
            return Err(history_error(format!("git rev-list exited with {status}")));
        }
        graph
    }

    fn parse(reader: impl BufRead) -> Result<Self, Error> {
        let mut nodes = Vec::new();
        let mut lookup = HashMap::new();
        for line in reader.lines() {
            let line = line?;
            let mut fields = line.split_ascii_whitespace();
            let sha = fields
                .next()
                .filter(|sha| full_hash(sha))
                .ok_or_else(|| history_error("invalid commit in rev-list output"))?;
            let parents = fields
                .map(|parent| {
                    lookup
                        .get(parent)
                        .copied()
                        .ok_or_else(|| history_error(format!("missing parent {parent}")))
                })
                .collect::<Result<_, _>>()?;
            lookup.insert(sha.to_owned(), nodes.len());
            nodes.push(Node {
                sha: sha.into(),
                parents,
            });
        }
        if nodes.is_empty() {
            return Err(history_error("no commits reachable from local refs"));
        }
        Ok(Self { nodes, lookup })
    }

    fn affected(&self, events: &str) -> Result<Vec<bool>, Error> {
        let events: Vec<Event> = serde_json::from_str(events)
            .map_err(|error| history_error(format!("invalid range events: {error}")))?;
        let mut introduced = Vec::new();
        let mut fixed = Vec::new();
        let mut last = Vec::new();
        let mut limits = Vec::new();
        let mut starts_at_root = false;
        let mut unlimited = false;
        for event in events {
            match event {
                Event::Introduced(sha) if sha == "0" => starts_at_root = true,
                Event::Limit(sha) if sha == "*" => unlimited = true,
                Event::Introduced(sha) => introduced.push(self.resolve(&sha)?),
                Event::Fixed(sha) => fixed.push(self.resolve(&sha)?),
                Event::LastAffected(sha) => last.push(self.resolve(&sha)?),
                Event::Limit(sha) => limits.push(self.resolve(&sha)?),
            }
        }
        if (!starts_at_root && introduced.is_empty()) || (!last.is_empty() && !fixed.is_empty()) {
            return Err(history_error(
                "expected an introduction and either fixed or last_affected boundaries",
            ));
        }

        // Propagate the most recent reachable introductions/fixes. A boundary
        // supersedes its ancestors. At a merge a remaining fix takes precedence.
        let mut boundaries: Vec<_> = introduced
            .into_iter()
            .map(|index| (index, false))
            .chain(fixed.into_iter().map(|index| (index, true)))
            .collect();
        boundaries.sort_unstable();
        boundaries.dedup();
        let mut supersedes = Vec::with_capacity(boundaries.len());
        let mut lookup = HashMap::new();
        for (ordinal, &(index, _)) in boundaries.iter().enumerate() {
            let ancestors = self.ancestors(self.nodes[index].parents.iter().copied());
            supersedes.push(
                boundaries[..ordinal]
                    .iter()
                    .enumerate()
                    .filter_map(|(prior, (node, _))| ancestors[*node].then_some(prior))
                    .collect::<Vec<_>>(),
            );
            lookup.entry(index).or_insert_with(Vec::new).push(ordinal);
        }

        let allowed_last = (!last.is_empty()).then(|| self.ancestors(last));
        let allowed_limit = (!unlimited && !limits.is_empty()).then(|| {
            self.ancestors(
                limits
                    .into_iter()
                    .flat_map(|index| self.nodes[index].parents.iter().copied()),
            )
        });
        let mut active: Vec<Vec<usize>> = Vec::with_capacity(self.nodes.len());
        let mut affected = Vec::with_capacity(self.nodes.len());
        for (index, node) in self.nodes.iter().enumerate() {
            let mut state: Vec<_> = node
                .parents
                .iter()
                .flat_map(|&parent| active[parent].iter().copied())
                .collect();
            state.extend(lookup.get(&index).into_iter().flatten().copied());
            state.sort_unstable();
            state.dedup();
            let mut maximal = state.clone();
            maximal.retain(|boundary| {
                !state
                    .iter()
                    .any(|&other| supersedes[other].binary_search(boundary).is_ok())
            });
            affected.push(
                (starts_at_root || !maximal.is_empty())
                    && !maximal.iter().any(|&boundary| boundaries[boundary].1)
                    && allowed_last.as_ref().is_none_or(|allowed| allowed[index])
                    && allowed_limit.as_ref().is_none_or(|allowed| allowed[index]),
            );
            active.push(maximal);
        }
        Ok(affected)
    }

    fn resolve(&self, sha: &str) -> Result<usize, Error> {
        if full_hash(sha)
            && let Some(&index) = self.lookup.get(&sha.to_ascii_lowercase())
        {
            return Ok(index);
        }
        Err(history_error(format!(
            "boundary {sha:?} is missing from reachable mirror history"
        )))
    }

    fn ancestors(&self, starts: impl IntoIterator<Item = usize>) -> Vec<bool> {
        let mut seen = vec![false; self.nodes.len()];
        let mut queue: VecDeque<_> = starts.into_iter().collect();
        while let Some(index) = queue.pop_front() {
            if !std::mem::replace(&mut seen[index], true) {
                queue.extend(self.nodes[index].parents.iter().copied());
            }
        }
        seen
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Event {
    Introduced(String),
    Fixed(String),
    LastAffected(String),
    Limit(String),
}

fn full_hash(sha: &str) -> bool {
    matches!(sha.len(), 40 | 64) && sha.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_fix_survives_merging_an_unfixed_branch_until_reintroduction() {
        let hashes: Vec<_> = (1..=7).map(|value| format!("{value:040x}")).collect();
        let parents: &[&[usize]] = &[&[], &[0], &[1], &[1], &[2, 3], &[4], &[5]];
        let history = hashes
            .iter()
            .zip(parents)
            .map(|(hash, parents)| {
                let parents = parents
                    .iter()
                    .map(|&index| hashes[index].as_str())
                    .collect::<Vec<_>>();
                format!("{hash} {}\n", parents.join(" "))
            })
            .collect::<String>();
        let graph = Graph::parse(history.as_bytes()).unwrap();
        let events = json!([
            {"introduced":hashes[1]}, {"fixed":hashes[2]},
            {"introduced":hashes[5]}, {"fixed":hashes[6]},
        ]);
        assert_eq!(
            graph.affected(&events.to_string()).unwrap(),
            [false, true, false, true, false, true, false]
        );
    }
}
