package handler

import (
	"strings"
	"testing"
	"time"

	"vsf/internal/snapshot"
)

// F4: the snapshot section of /readyz is informational: failures and an old snapshot produce warnings, never problems.
func TestSnapshotReportWarningsOnly(t *testing.T) {
	now := time.Now()

	rep, warn := snapshotReport(snapshot.Status{
		Leader: true, SnapshotID: 7, CursorXID: "42", CursorSeq: 9, SnapshotAt: now.Add(-5 * time.Hour), Interval: time.Hour,
		Consecutive: 3, SaveFailures: 3, NextAttempt: now.Add(time.Minute), PendingSave: true, Fallbacks: 2,
	}, now)

	if rep["leader"] != true || rep["snapshot_id"] != int64(7) || rep["cursor"] != "42.9" || rep["pending_save"] != true ||
		rep["fallbacks"] != int64(2) || rep["save_failures"] != int64(3) {
		t.Fatalf("report %v", rep)
	}

	if !strings.Contains(warn["filter_snapshot_failing"], "3 consecutive") {
		t.Fatalf("missing failing warning: %v", warn)
	}

	if !strings.Contains(warn["filter_snapshot_old"], "5h") {
		t.Fatalf("missing old-snapshot warning: %v", warn)
	}

	// Healthy and fresh: no warnings.
	_, warn = snapshotReport(snapshot.Status{SnapshotID: 1, SnapshotAt: now.Add(-10 * time.Minute), Interval: time.Hour}, now)
	if len(warn) != 0 {
		t.Fatalf("healthy snapshot produced warnings: %v", warn)
	}
}
