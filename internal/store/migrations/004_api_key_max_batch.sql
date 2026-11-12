-- Per-key burst allowance for batch calls.
--   max_batch = 0  -> the key's burst equals its rps_limit (previous behaviour, nothing changes).
--   max_batch > 0  -> the key may send one call of up to max_batch items at once; the sustained
--                     rate is still capped by rps_limit (items per second).
-- DEFAULT 0 keeps every existing key exactly as it was. A constant default is a metadata-only
-- change on PostgreSQL 11+, so this does not rewrite or long-lock the table.
ALTER TABLE api_keys
    ADD COLUMN max_batch INT NOT NULL DEFAULT 0 CHECK (max_batch >= 0);
