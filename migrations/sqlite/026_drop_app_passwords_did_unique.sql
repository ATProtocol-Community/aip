-- Migration: Drop unique constraint on did column in app_passwords table
-- This allows the same DID to have app-passwords with multiple clients
-- The composite unique constraint (client_id, did) already ensures uniqueness per client
-- SQLite doesn't support DROP CONSTRAINT, so we need to recreate the table

-- Create new table without the UNIQUE constraint on did
CREATE TABLE app_passwords_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT NOT NULL,
    did TEXT NOT NULL,
    app_password TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(client_id, did)
);

-- Copy data from old table
INSERT INTO app_passwords_new (id, client_id, did, app_password, created_at, updated_at)
SELECT id, client_id, did, app_password, created_at, updated_at FROM app_passwords;

-- Drop old table
DROP TABLE app_passwords;

-- Rename new table
ALTER TABLE app_passwords_new RENAME TO app_passwords;

-- Recreate indexes
CREATE INDEX idx_app_passwords_client_id ON app_passwords(client_id);
CREATE INDEX idx_app_passwords_did ON app_passwords(did);
CREATE INDEX idx_app_passwords_updated_at ON app_passwords(updated_at);
