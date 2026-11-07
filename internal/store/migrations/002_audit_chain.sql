-- Tamper-evident audit log: each row stores an HMAC over its own content plus
-- the previous row's hash. Rows written before this migration keep NULL hashes.
ALTER TABLE audit_logs
    ADD COLUMN prev_hash  BYTEA,
    ADD COLUMN entry_hash BYTEA;
