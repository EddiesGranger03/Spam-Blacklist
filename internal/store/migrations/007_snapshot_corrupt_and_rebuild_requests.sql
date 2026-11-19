-- F2: a snapshot found corrupt by any pod is flagged so nobody retries it; readers fall back to the next older good one.
ALTER TABLE filter_snapshots
    ADD COLUMN IF NOT EXISTS corrupt        BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS corrupt_reason TEXT    NOT NULL DEFAULT '';

DROP INDEX IF EXISTS filter_snapshots_complete_idx;
CREATE INDEX IF NOT EXISTS filter_snapshots_usable_idx ON filter_snapshots (id DESC) WHERE complete AND NOT corrupt;

-- F3: a pod that finds no usable snapshot asks the leader to build one. A single row with two counters:
-- a request is only recorded while none is pending (requests <= handled), and the leader sets handled to the value it
-- saw before it started building. Any number of pods asking therefore causes exactly one extra build.
CREATE TABLE IF NOT EXISTS filter_rebuild_requests (
    id         SMALLINT    PRIMARY KEY CHECK (id = 1),
    requests   BIGINT      NOT NULL DEFAULT 0,
    handled    BIGINT      NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO filter_rebuild_requests (id) VALUES (1) ON CONFLICT DO NOTHING;
