-- Entry status: a WHITELIST entry is an explicit exception that wins over any BLACKLIST rule
-- (including domain/prefix rules). Constant defaults are metadata-only on PostgreSQL 11+, so neither
-- statement rewrites or long-locks the table. Existing rows become BLACKLIST, existing change_log
-- rows become op 1 (add), which is exactly what they meant before.
ALTER TABLE blacklist_entries
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'BLACKLIST' CHECK (status IN ('BLACKLIST', 'WHITELIST'));

-- change_log.op: 1 = hash must be (re)added to the filter, 2 = hash must be removed from the filter.
ALTER TABLE change_log
    ADD COLUMN IF NOT EXISTS op SMALLINT NOT NULL DEFAULT 1 CHECK (op IN (1, 2));
