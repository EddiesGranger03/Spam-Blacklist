package model

import (
	"errors"
	"strings"
	"testing"

	"vsf/internal/normalize"
)

func TestRoleLevelsAndPermissions(t *testing.T) {
	levels := map[Role]int{RoleViewer: 1, RoleEditor: 2, RoleAdmin: 3, "": 0, "root": 0, "ADMIN": 0}
	for r, want := range levels {
		if got := r.Level(); got != want {
			t.Errorf("Role(%q).Level() = %d, want %d", r, got, want)
		}

		if got := ValidRole(r); got != (want > 0) {
			t.Errorf("ValidRole(%q) = %v", r, got)
		}
	}

	cases := []struct {
		have, need Role
		want       bool
	}{
		{RoleAdmin, RoleViewer, true}, {RoleAdmin, RoleAdmin, true}, {RoleEditor, RoleAdmin, false},
		{RoleEditor, RoleEditor, true}, {RoleViewer, RoleEditor, false},
		// vai trò không hợp lệ không bao giờ có quyền, kể cả khi quyền yêu cầu cũng không hợp lệ
		{"", "", false}, {"root", RoleViewer, false}, {"root", "root", false},
	}

	for _, c := range cases {
		if got := c.have.AtLeast(c.need); got != c.want {
			t.Errorf("%q.AtLeast(%q) = %v, want %v", c.have, c.need, got, c.want)
		}
	}
}

func TestEntryInputValidate(t *testing.T) {
	ok := EntryInput{Category: "scam", RiskScore: 100, Source: strings.Repeat("s", 200), Note: strings.Repeat("n", 2000)}
	if err := ok.Validate(); err != nil {
		t.Fatalf("boundary values must be valid: %v", err)
	}

	empty := EntryInput{}
	if err := empty.Validate(); err != nil || empty.Category != "spam" {
		t.Fatalf("an empty category defaults to spam: %v %q", err, empty.Category)
	}

	for name, in := range map[string]EntryInput{
		"unknown category": {Category: "nope"},
		"negative risk":    {RiskScore: -1},
		"risk too high":    {RiskScore: 101},
		"source too long":  {Source: strings.Repeat("s", 201)},
		"note too long":    {Note: strings.Repeat("n", 2001)},
	} {
		in := in
		if err := in.Validate(); !errors.Is(err, normalize.ErrInvalid) {
			t.Errorf("%s: want an ErrInvalid error, got %v", name, err)
		}
	}
}
