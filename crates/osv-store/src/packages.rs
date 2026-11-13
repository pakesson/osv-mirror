use rusqlite::{Connection, Transaction, params};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::{Advisory, Error, Store, open_read, versions};

pub fn base_ecosystem(ecosystem: &str) -> &str {
    ecosystem
        .split_once(':')
        .map_or(ecosystem, |(base, _)| base)
}

pub fn known_ecosystem(ecosystem: &str) -> bool {
    osv_schema::is_known_ecosystem(base_ecosystem(ecosystem))
}

fn normalize_name(ecosystem: &str, name: &str) -> String {
    let base = base_ecosystem(ecosystem);
    let native = ecosystem.split_once(':').map_or("", |(_, suffix)| suffix);
    match (base, native) {
        ("PyPI", _) | ("Echo" | "Red Hat Lightwell", "PyPI") => {
            let mut normalized = String::new();
            for c in name.chars() {
                if matches!(c, '-' | '_' | '.') {
                    if !normalized.ends_with('-') {
                        normalized.push('-');
                    }
                } else {
                    normalized.push(c.to_ascii_lowercase());
                }
            }
            normalized
        }
        ("NuGet", _) | ("Echo", "NuGet") => name.to_ascii_lowercase(),
        ("crates.io", _) => name.to_ascii_lowercase().replace('_', "-"),
        _ => name.to_owned(),
    }
}

fn ubuntu_variant(ecosystem: &str) -> String {
    ecosystem
        .split(':')
        .filter(|part| !matches!(*part, "LTS" | "Pro"))
        .collect::<Vec<_>>()
        .join(":")
}

fn applies_to_scope(requested: &str, actual: &str) -> bool {
    requested.is_empty()
        || requested == actual
        || requested == base_ecosystem(actual)
        || (base_ecosystem(actual) == "Ubuntu" && requested == ubuntu_variant(actual))
}

#[derive(Deserialize)]
struct Record<'a> {
    #[serde(borrow)]
    affected: Option<Vec<&'a RawValue>>,
}

#[derive(Deserialize)]
struct Affected<'a> {
    #[serde(borrow)]
    package: Option<&'a RawValue>,
    #[serde(borrow)]
    versions: Option<&'a RawValue>,
    #[serde(borrow)]
    ranges: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct Package {
    ecosystem: String,
    name: String,
}

fn index_record(
    connection: &Connection,
    id: &str,
    json: &str,
    packages: bool,
) -> Result<(), Error> {
    let Ok(record) = serde_json::from_str::<Record<'_>>(json) else {
        return Ok(());
    };
    let mut insert = connection.prepare_cached(
        "INSERT INTO affected_packages (name, ecosystem, advisory_id, ordinal)
         VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
    )?;
    for (ordinal, entry) in record.affected.into_iter().flatten().enumerate() {
        let Ok(affected) = serde_json::from_str::<Affected<'_>>(entry.get()) else {
            continue;
        };
        let ordinal = ordinal as i64;
        crate::git::index_ranges(connection, id, ordinal, affected.ranges)?;
        let Some(package) = affected
            .package
            .filter(|_| packages)
            .and_then(|raw| serde_json::from_str::<Package>(raw.get()).ok())
        else {
            continue;
        };
        if package.name.is_empty()
            || package.ecosystem.is_empty()
            || base_ecosystem(&package.ecosystem) == "GIT"
        {
            continue;
        }
        let name = normalize_name(&package.ecosystem, &package.name);
        let base = base_ecosystem(&package.ecosystem);
        insert.execute(params![name, package.ecosystem, id, ordinal])?;
        if base != package.ecosystem {
            insert.execute(params![name, base, id, ordinal])?;
        }
        if base == "Ubuntu" {
            let variant = ubuntu_variant(&package.ecosystem);
            if variant != base && variant != package.ecosystem {
                insert.execute(params![name, variant, id, ordinal])?;
            }
        }
    }
    Ok(())
}

pub(crate) fn replace_index(connection: &Connection, advisory: &Advisory<'_>) -> Result<(), Error> {
    connection
        .prepare_cached("DELETE FROM affected_packages WHERE advisory_id = ?1")?
        .execute([advisory.id()])?;
    connection
        .prepare_cached("DELETE FROM git_ranges WHERE advisory_id = ?1")?
        .execute([advisory.id()])?;
    if advisory.withdrawn_key.is_none() {
        index_record(connection, advisory.id(), advisory.json, true)?;
    }
    Ok(())
}

pub(crate) fn backfill(connection: &Connection, packages: bool) -> Result<(), Error> {
    let mut statement =
        connection.prepare("SELECT id, json FROM advisories WHERE withdrawn_key IS NULL")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        index_record(
            connection,
            &row.get::<_, String>(0)?,
            &row.get::<_, String>(1)?,
            packages,
        )?;
    }
    Ok(())
}

#[derive(Debug)]
pub struct PackageQuery {
    name: String,
    ecosystem: String,
    version: String,
}

impl PackageQuery {
    pub fn new(name: &str, ecosystem: &str, version: &str) -> Self {
        Self {
            name: if ecosystem == "GIT" {
                crate::normalize_repository(name).unwrap_or_default()
            } else {
                normalize_name(ecosystem, name)
            },
            ecosystem: ecosystem.into(),
            version: version.into(),
        }
    }

    pub fn identity(&self) -> [&str; 3] {
        [&self.name, &self.ecosystem, &self.version]
    }
}

pub struct PackageMatch {
    pub id: String,
    pub modified: String,
    pub json: Option<String>,
}

pub struct PackagePage {
    pub matches: Vec<PackageMatch>,
    pub next_after: Option<String>,
}

pub struct PackageSearch<'a> {
    pub(crate) transaction: Transaction<'a>,
    pub snapshot: String,
    pub revision: i64,
}

impl Store {
    /// A request (including every item in a batch) sees one SQLite revision.
    pub fn with_package_search<T, E>(
        &self,
        read: impl FnOnce(&PackageSearch<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<Error>,
    {
        let mut connection = open_read(&self.path)?;
        let transaction = connection.transaction().map_err(Error::from)?;
        let (snapshot, revision) = transaction.query_row(
            "SELECT q.id, s.revision FROM query_snapshot q CROSS JOIN sync_state s WHERE s.singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(Error::from)?;
        read(&PackageSearch {
            transaction,
            snapshot,
            revision,
        })
    }
}

impl PackageSearch<'_> {
    pub fn page(
        &self,
        query: &PackageQuery,
        after: &str,
        limit: usize,
        scan_limit: usize,
        json_budget: Option<usize>,
    ) -> Result<PackagePage, Error> {
        let ids = if query.ecosystem == "GIT" {
            crate::git::tag_candidates(&self.transaction, &query.name, after, scan_limit + 1)?
        } else {
            self.candidates(query, after, scan_limit + 1)?
        };
        self.hydrate_page(ids, after, limit, scan_limit, json_budget, |json, id| {
            if query.version.is_empty() {
                Ok(true)
            } else if query.ecosystem == "GIT" {
                crate::git::matches_tag(&self.transaction, id, &query.name, &query.version)
            } else {
                matches_record(json, id, query)
            }
        })
    }

    pub(crate) fn hydrate_page(
        &self,
        mut ids: Vec<String>,
        after: &str,
        limit: usize,
        scan_limit: usize,
        json_budget: Option<usize>,
        matches: impl Fn(&str, &str) -> Result<bool, Error>,
    ) -> Result<PackagePage, Error> {
        let mut output = PackagePage {
            matches: Vec::new(),
            next_after: None,
        };
        let mut last = after.to_owned();
        let mut remaining = json_budget.unwrap_or(usize::MAX);
        let has_more = ids.len() > scan_limit;
        ids.truncate(scan_limit);

        let mut get = self.transaction.prepare_cached(
            "SELECT json, modified_key FROM advisories WHERE id = ?1 AND withdrawn_key IS NULL",
        )?;
        for id in ids {
            if output.matches.len() == limit {
                output.next_after = Some(last);
                return Ok(output);
            }
            let (json, modified_key): (String, String) =
                get.query_row([&id], |row| Ok((row.get(0)?, row.get(1)?)))?;
            if !matches(&json, &id)? {
                last = id;
                continue;
            }
            if json_budget.is_some() && json.len() + 1 > remaining {
                if output.matches.is_empty() {
                    return Err(Error::ResponseTooLarge);
                }
                output.next_after = Some(last);
                return Ok(output);
            }
            if json_budget.is_some() {
                remaining -= json.len() + 1;
            }
            last.clone_from(&id);
            // The key omits only redundant fractional trailing zeroes and Z.
            let modified = format!("{modified_key}Z");
            output.matches.push(PackageMatch {
                id,
                modified,
                json: json_budget.map(|_| json),
            });
        }
        output.next_after = has_more.then_some(last);
        Ok(output)
    }

    fn candidates(
        &self,
        query: &PackageQuery,
        after: &str,
        limit: usize,
    ) -> Result<Vec<String>, Error> {
        let ecosystem = &query.ecosystem;
        if ecosystem.is_empty() {
            let mut statement = self.transaction.prepare_cached(
                "SELECT DISTINCT advisory_id FROM affected_packages
                 WHERE name = ?1 AND advisory_id > ?2 ORDER BY advisory_id LIMIT ?3",
            )?;
            return Ok(statement
                .query_map(params![query.name, after, limit as i64], |row| row.get(0))?
                .collect::<Result<_, _>>()?);
        }
        let mut statement = self.transaction.prepare_cached(
            "SELECT advisory_id FROM (
                SELECT advisory_id FROM (
                    SELECT DISTINCT advisory_id FROM affected_packages
                    WHERE name = ?1 AND ecosystem = ?2 AND advisory_id > ?3
                    ORDER BY advisory_id LIMIT ?4
                )
                UNION
                SELECT advisory_id FROM (
                    SELECT DISTINCT advisory_id FROM affected_packages
                    WHERE name = '*' AND ecosystem = ?2 AND advisory_id > ?3
                    ORDER BY advisory_id LIMIT ?4
                )
             ) ORDER BY advisory_id LIMIT ?4",
        )?;
        Ok(statement
            .query_map(params![query.name, ecosystem, after, limit as i64], |row| {
                row.get(0)
            })?
            .collect::<Result<_, _>>()?)
    }
}

fn matches_record(json: &str, id: &str, query: &PackageQuery) -> Result<bool, Error> {
    let mut unsupported = None;
    // The index was built from this same record using this same projection.
    let record: Record<'_> = serde_json::from_str(json)?;
    for entry in record.affected.into_iter().flatten() {
        let Ok(affected) = serde_json::from_str::<Affected<'_>>(entry.get()) else {
            continue;
        };
        let Some(package) = affected
            .package
            .and_then(|raw| serde_json::from_str::<Package>(raw.get()).ok())
        else {
            continue;
        };
        if base_ecosystem(&package.ecosystem) == "GIT"
            || !applies_to_scope(&query.ecosystem, &package.ecosystem)
        {
            continue;
        }
        if normalize_name(&package.ecosystem, &package.name) != query.name
            && (query.ecosystem.is_empty() || package.name != "*")
        {
            continue;
        }
        match versions::matches(
            &package.ecosystem,
            &query.ecosystem,
            &query.version,
            affected.versions,
            affected.ranges,
        ) {
            Some(true) => return Ok(true),
            Some(false) => {}
            None => unsupported = Some(package.ecosystem),
        }
    }
    match unsupported {
        Some(ecosystem) => Err(Error::UnsupportedMatch {
            id: id.into(),
            ecosystem,
        }),
        None => Ok(false),
    }
}
