-- Snapshots of the static filter layer, so pods start without scanning blacklist_entries.
-- A snapshot is written in one transaction and marked complete only when every chunk is stored.
CREATE TABLE filter_snapshots (
    id          BIGSERIAL   PRIMARY KEY,
    kind        SMALLINT    NOT NULL,
    items       BIGINT      NOT NULL,
    cursor_xid  TEXT        NOT NULL,
    cursor_seq  BIGINT      NOT NULL,
    size_bytes  BIGINT      NOT NULL DEFAULT 0,
    chunks      INT         NOT NULL DEFAULT 0,
    checksum    BIGINT      NOT NULL DEFAULT 0,
    complete    BOOLEAN     NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX filter_snapshots_complete_idx ON filter_snapshots (id DESC) WHERE complete;

CREATE TABLE filter_snapshot_chunks (
    snapshot_id BIGINT NOT NULL REFERENCES filter_snapshots (id) ON DELETE CASCADE,
    idx         INT    NOT NULL,
    data        BYTEA  NOT NULL,
    PRIMARY KEY (snapshot_id, idx)
);
