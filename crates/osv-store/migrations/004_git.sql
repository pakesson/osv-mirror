CREATE TABLE git_ranges (
    repo TEXT NOT NULL,
    advisory_id TEXT NOT NULL REFERENCES advisories (id) ON DELETE CASCADE,
    affected_ordinal INTEGER NOT NULL,
    range_ordinal INTEGER NOT NULL,
    PRIMARY KEY (repo, advisory_id, affected_ordinal, range_ordinal)
) WITHOUT ROWID;
CREATE INDEX git_ranges_by_advisory ON git_ranges (advisory_id);

CREATE TABLE git_coverage (
    repo TEXT PRIMARY KEY,
    revision INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE git_commits (
    repo TEXT NOT NULL REFERENCES git_coverage (repo) ON DELETE CASCADE,
    sha TEXT NOT NULL,
    PRIMARY KEY (repo, sha)
) WITHOUT ROWID;
CREATE INDEX git_commits_by_hash ON git_commits (sha, repo);
CREATE TABLE git_matches (
    repo TEXT NOT NULL REFERENCES git_coverage (repo) ON DELETE CASCADE,
    sha TEXT NOT NULL,
    advisory_id TEXT NOT NULL REFERENCES advisories (id) ON DELETE CASCADE,
    PRIMARY KEY (repo, sha, advisory_id)
) WITHOUT ROWID;
CREATE INDEX git_matches_by_hash ON git_matches (sha, advisory_id);
CREATE INDEX git_matches_by_advisory ON git_matches (advisory_id);
