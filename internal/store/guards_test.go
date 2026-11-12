package store

import (
	"context"
	"errors"
	"os"
	"testing"

	"vsf/internal/model"
	"vsf/internal/normalize"
)

// Store chưa có khóa mã hóa thì mọi thao tác chạm tới dữ liệu phải từ chối rõ ràng, không được ghi gì ở dạng thô.
func TestStoreWithoutSealerRefusesEverything(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping integration test")
	}

	ctx := context.Background()

	s, err := New(ctx, dsn, "", 2)
	if err != nil {
		t.Fatal(err)
	}

	defer s.Close()

	key := normalize.MakeKey(normalize.TypePhone, normalize.MatchExact, "+84901000001")

	if _, err := s.CreateEntry(ctx, key, model.EntryInput{}, actor); !errors.Is(err, errNoSealer) {
		t.Errorf("CreateEntry: %v", err)
	}

	if _, _, err := s.sealNoteSource("n", "s"); !errors.Is(err, errNoSealer) {
		t.Errorf("sealNoteSource: %v", err)
	}

	if _, err := s.VerifyKeys(ctx); !errors.Is(err, errNoSealer) {
		t.Errorf("VerifyKeys: %v", err)
	}

	if _, err := s.Rekey(ctx, actor, RekeyOptions{}); !errors.Is(err, errNoSealer) {
		t.Errorf("Rekey: %v", err)
	}

	if _, err := s.RotatePepper(ctx, actor, PepperRotateOptions{OldBlind: func(string, string, string) []byte { return nil }}); !errors.Is(err, errNoSealer) {
		t.Errorf("RotatePepper: %v", err)
	}

	if err := s.runURLPathMigration(ctx); err != nil {
		t.Errorf("the URL migration waits for the keys instead of failing: %v", err)
	}
}

func TestRotatePepperNeedsOldBlind(t *testing.T) {
	s := newTestStore(t)

	if _, err := s.RotatePepper(context.Background(), actor, PepperRotateOptions{}); err == nil {
		t.Fatal("OldBlind is required")
	}
}

func TestEntryWritesOnMissingRows(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.UpdateEntry(ctx, 999999, model.EntryInput{Category: "spam"}, actor); !errors.Is(err, ErrNotFound) {
		t.Errorf("updating a missing entry: %v", err)
	}

	if err := s.DeleteEntry(ctx, 999999, actor); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting a missing entry: %v", err)
	}

	k := mustKey(t, normalize.TypePhone, "", "0903000111")
	if _, err := s.CreateEntry(ctx, k, model.EntryInput{Category: "spam", RiskScore: 1}, actor); err != nil {
		t.Fatal(err)
	}

	if _, err := s.CreateEntry(ctx, k, model.EntryInput{Category: "spam", RiskScore: 1}, actor); !errors.Is(err, ErrDuplicate) {
		t.Errorf("a duplicate entry: %v", err)
	}
}
