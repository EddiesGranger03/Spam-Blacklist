CREATE SEQUENCE blacklist_entries_id_seq;

CREATE TABLE blacklist_entries (
    id               BIGINT      NOT NULL DEFAULT nextval('blacklist_entries_id_seq'),
    type             TEXT        NOT NULL CHECK (type IN ('phone', 'url')),
    match_type       TEXT        NOT NULL CHECK (match_type IN ('exact', 'domain', 'prefix')),
    value_normalized TEXT        NOT NULL,
    value_hash       BIGINT      NOT NULL,
    category         TEXT        NOT NULL DEFAULT 'spam',
    risk_score       SMALLINT    NOT NULL DEFAULT 50 CHECK (risk_score BETWEEN 0 AND 100),
    source           TEXT        NOT NULL DEFAULT '',
    note             TEXT        NOT NULL DEFAULT '',
    expires_at       TIMESTAMPTZ,
    created_by       TEXT        NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
) PARTITION BY HASH (value_hash);

ALTER SEQUENCE blacklist_entries_id_seq OWNED BY blacklist_entries.id;

DO $$
BEGIN
    FOR i IN 0..31 LOOP
        EXECUTE format(
            'CREATE TABLE blacklist_entries_p%s PARTITION OF blacklist_entries
             FOR VALUES WITH (MODULUS 32, REMAINDER %s)', i, i);
    END LOOP;
END $$;

CREATE UNIQUE INDEX blacklist_entries_uniq
    ON blacklist_entries (value_hash, type, match_type, value_normalized);

CREATE INDEX blacklist_entries_id_idx ON blacklist_entries (id);

CREATE TABLE change_log (
    seq        BIGSERIAL   PRIMARY KEY,
    xid        xid8        NOT NULL DEFAULT pg_current_xact_id(),
    value_hash BIGINT      NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX change_log_xid_seq_idx ON change_log (xid, seq);
CREATE INDEX change_log_created_at_idx ON change_log (created_at);

CREATE TABLE admins (
    id            BIGSERIAL   PRIMARY KEY,
    email         TEXT        NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,
    role          TEXT        NOT NULL DEFAULT 'viewer' CHECK (role IN ('viewer', 'editor', 'admin')),
    disabled      BOOLEAN     NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id_hash      BYTEA       PRIMARY KEY,
    admin_id     BIGINT      NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
    csrf_token   TEXT        NOT NULL,
    ip           TEXT        NOT NULL DEFAULT '',
    user_agent   TEXT        NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
CREATE INDEX sessions_admin_id_idx ON sessions (admin_id);

CREATE TABLE audit_logs (
    id          BIGSERIAL   PRIMARY KEY,
    actor_id    BIGINT,
    actor_email TEXT        NOT NULL DEFAULT '',
    action      TEXT        NOT NULL,
    entry_id    BIGINT,
    detail      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    ip          TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_logs_created_at_idx ON audit_logs (created_at DESC);

CREATE TABLE api_keys (
    id            BIGSERIAL   PRIMARY KEY,
    name          TEXT        NOT NULL,
    prefix        TEXT        NOT NULL UNIQUE,
    key_hash      BYTEA       NOT NULL,
    status        TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    rps_limit     INT         NOT NULL DEFAULT 100,
    daily_quota   BIGINT      NOT NULL DEFAULT 0,
    expires_at    TIMESTAMPTZ,
    rotated_from  BIGINT      REFERENCES api_keys (id),
    created_by    TEXT        NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ
);
