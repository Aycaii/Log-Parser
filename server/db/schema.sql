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

-- Set once at upload time by the parser, so the uploads list can show
-- "987/1000 lines parsed" without a COUNT query against `events`.
ALTER TABLE uploads ADD COLUMN IF NOT EXISTS parsed_count  INT NOT NULL DEFAULT 0;
ALTER TABLE uploads ADD COLUMN IF NOT EXISTS skipped_count INT NOT NULL DEFAULT 0;

-- Raw text of lines the parser couldn't match, newline-joined -- lets the
-- "skipped lines" tab show an analyst exactly what didn't parse, not just a
-- count.
ALTER TABLE uploads ADD COLUMN IF NOT EXISTS skipped_lines TEXT NOT NULL DEFAULT '';

-- One row per successfully parsed log line. Populated once, at upload time,
-- from the raw bytes already sitting in uploads.content -- not re-parsed on
-- every read.
CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL   PRIMARY KEY,
    upload_id   BIGINT      NOT NULL REFERENCES uploads (id) ON DELETE CASCADE,
    source_ip   TEXT        NOT NULL,
    event_time  TIMESTAMPTZ NOT NULL,
    method      TEXT        NOT NULL,
    url         TEXT        NOT NULL,
    status_code INT         NOT NULL,
    bytes_sent  BIGINT      NOT NULL
);

-- Backs both the per-upload event list and the timeline summary, which both
-- read in event_time order.
CREATE INDEX IF NOT EXISTS events_upload_idx ON events (upload_id, event_time);

-- AI-based anomaly detection (bonus). Best-effort at upload time: a missing
-- OPENAI_API_KEY or a failed call just leaves these empty rather than
-- failing the upload -- see threatdetect.AnalyzeLogsWithAI and its caller
-- in upload.go.
ALTER TABLE uploads ADD COLUMN IF NOT EXISTS threat_summary TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS anomalies (
    id               BIGSERIAL        PRIMARY KEY,
    upload_id        BIGINT           NOT NULL REFERENCES uploads (id) ON DELETE CASCADE,
    source_ip        TEXT             NOT NULL,
    -- Stored as the model returned it (TEXT, not TIMESTAMPTZ) -- an LLM
    -- response isn't a trusted, guaranteed-parseable timestamp source the
    -- way the regex parser's own output is.
    event_time       TEXT             NOT NULL,
    is_anomaly       BOOLEAN          NOT NULL,
    reason           TEXT             NOT NULL,
    confidence_score DOUBLE PRECISION NOT NULL
);

CREATE INDEX IF NOT EXISTS anomalies_upload_idx ON anomalies (upload_id);
