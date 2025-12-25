-- Migration: Drop unique constraint on did column in app_passwords table
-- This allows the same DID to have app-passwords with multiple clients
-- The composite primary key (client_id, did) already ensures uniqueness per client

ALTER TABLE app_passwords DROP CONSTRAINT IF EXISTS app_passwords_did_key;
