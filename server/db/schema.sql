-- Applied on every boot. Everything is IF NOT EXISTS so it is safe to re-run;
-- a real app would use versioned migration files instead of a single idempotent
-- script, so that changes to existing columns could be expressed too.

CREATE TABLE IF NOT EXISTS users (
    id              BIGSERIAL   PRIMARY KEY,
    username        TEXT        NOT NULL UNIQUE,
    hashed_password TEXT        NOT NULL,
    -- Session and CSRF tokens live on the user row, mirroring the struct this
    -- replaced. That caps a user at one active session and gives no server-side
    -- expiry. A production schema would use a sessions table
    -- (id, user_id, token_hash, expires_at) so sessions can be listed, expired
    -- and revoked individually -- and would store a hash of the token, not the
    -- token itself, so a database leak does not hand over live sessions.
    session_token   TEXT,
    csrf_token      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Every authorized request looks the user up by session token, so this index
-- keeps that off a sequential scan.
CREATE INDEX IF NOT EXISTS users_session_token_idx ON users (session_token);

-- Uploaded log files.
--
-- content is BYTEA -- the file bytes live directly in the row (the "BLOB"
-- approach). The upside is that one database holds both the file and its
-- metadata, so an upload is a single atomic INSERT with no second system to
-- keep in sync and no orphaned objects if a write half-fails.
--
-- The cost is that large files bloat the table, every read pulls the whole
-- payload through the DB connection, and backups grow with the raw data.
-- Postgres transparently moves values over ~2KB into TOAST storage, which keeps
-- the main table scannable, but the ceiling on a single BYTEA value is 1GB.
-- Past a few MB per file the usual move is object storage (S3/GCS) with only
-- the key kept here. For log files in a prototype, BYTEA is the simpler call.
CREATE TABLE IF NOT EXISTS uploads (
    id           BIGSERIAL   PRIMARY KEY,
    user_id      BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    filename     TEXT        NOT NULL,
    content_type TEXT        NOT NULL,
    size_bytes   BIGINT      NOT NULL,
    content      BYTEA       NOT NULL,
    uploaded_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Listing a user's uploads newest-first is the only read path so far.
CREATE INDEX IF NOT EXISTS uploads_user_idx ON uploads (user_id, uploaded_at DESC);
