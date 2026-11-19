package store

import "testing"

// Regression test for finding F5 (docs/SCALE_TEST.md section 3): the snapshot leader's session-level advisory lock used
// the same key as the audit chain's transaction-level lock, so while a leader existed every audit write (login, entry
// edits) blocked. Every advisory key in the store must be distinct.
func TestAdvisoryLockKeysAreDistinct(t *testing.T) {
	const migrateLockID = 727274 // store.Migrate

	keys := map[string]int64{"migrate": migrateLockID, "audit": auditLockID, "snapshot leader": SnapshotLeaderLockID}
	seen := map[int64]string{}

	for name, k := range keys {
		if other, dup := seen[k]; dup {
			t.Errorf("advisory lock key %d is used by both %q and %q", k, other, name)
		}

		seen[k] = name
	}
}
