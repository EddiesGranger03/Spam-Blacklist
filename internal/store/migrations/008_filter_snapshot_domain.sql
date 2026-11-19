-- G1: the hash domain (which DATA_PEPPER produced value_hash) a snapshot was built under. 0 = written before this
-- column existed: never matches a real domain, so such snapshots are never installed and age out via Prune.
ALTER TABLE filter_snapshots ADD COLUMN IF NOT EXISTS domain_id BIGINT NOT NULL DEFAULT 0;

DROP INDEX IF EXISTS filter_snapshots_usable_idx;
CREATE INDEX IF NOT EXISTS filter_snapshots_usable_idx ON filter_snapshots (domain_id, id DESC) WHERE complete AND NOT corrupt;
