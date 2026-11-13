CREATE TABLE affected_packages (
    name TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    advisory_id TEXT NOT NULL REFERENCES advisories (id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    PRIMARY KEY (name, ecosystem, advisory_id, ordinal)
) WITHOUT ROWID;

CREATE INDEX affected_packages_by_advisory ON affected_packages (advisory_id);
CREATE INDEX affected_packages_by_name ON affected_packages (name, advisory_id, ordinal);

-- Rebuilding from the same ZIP starts a new pagination history.
CREATE TABLE query_snapshot (id TEXT NOT NULL);
INSERT INTO query_snapshot VALUES (lower(hex(randomblob(16))));
