CREATE TABLE advisories (
    id TEXT PRIMARY KEY,
    modified_key TEXT NOT NULL,
    withdrawn_key TEXT,
    json TEXT NOT NULL
);

CREATE TABLE aliases (
    alias TEXT NOT NULL,
    advisory_id TEXT NOT NULL REFERENCES advisories (id) ON DELETE CASCADE,
    PRIMARY KEY (alias, advisory_id)
) WITHOUT ROWID;

CREATE INDEX aliases_by_advisory ON aliases (advisory_id);
