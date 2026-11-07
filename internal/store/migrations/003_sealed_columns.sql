-- Step 1 of encrypting data at rest. Columns are nullable and unused by reads
-- until the backfill (step 2) and the switch-over (step 3) have run.
--   value_blind : HMAC-SHA256(pepper, type|match_type|value)  -- lookup index
--   value_enc / note_enc / source_enc : AES-256-GCM (nonce || ciphertext)
--   key_version : which DATA_KEY generation produced the ciphertexts
ALTER TABLE blacklist_entries
    ADD COLUMN value_blind BYTEA,
    ADD COLUMN value_enc   BYTEA,
    ADD COLUMN note_enc    BYTEA,
    ADD COLUMN source_enc  BYTEA,
    ADD COLUMN key_version SMALLINT;
