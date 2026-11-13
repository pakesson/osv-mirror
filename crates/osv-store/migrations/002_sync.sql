CREATE TABLE sync_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    feed TEXT,
    scope TEXT NOT NULL DEFAULT 'global',
    etag TEXT,
    last_modified TEXT,
    generation TEXT,
    inventory_digest TEXT,
    last_checked INTEGER,
    revision INTEGER NOT NULL DEFAULT 0
);
INSERT INTO sync_state (singleton) VALUES (1);

CREATE TABLE pending_absences (
    id TEXT PRIMARY KEY REFERENCES advisories (id) ON DELETE CASCADE
) WITHOUT ROWID;
