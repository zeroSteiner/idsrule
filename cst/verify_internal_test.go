package cst

import (
	"strings"
	"testing"

	"github.com/zeroSteiner/idsrule/token"
)

// TestVerifyCorruptedBase checks the invariants Seal itself upholds, by
// corrupting a node's base after sealing it.
func TestVerifyCorruptedBase(t *testing.T) {
	src := []byte("ab")
	a := token.Token{Kind: token.Word, Start: 0, End: 1, Lit: "a"}
	tests := []struct {
		name    string
		corrupt func(b *base)
		want    string
	}{
		{"span ends before it starts", func(b *base) { b.span.End = -1 }, "ends before it starts"},
		{"empty node with a span", func(b *base) { b.kids = nil; b.span.End = 2 }, "has no children but a non-empty span"},
		{"first child starts late", func(b *base) { b.span.Start = -1 }, "first child starts at 0"},
		{"last child ends early", func(b *base) { b.span.End = 2 }, "last child ends at 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bad := &Bad{Tokens: []token.Token{a}}
			Seal(bad, src, 0, a)
			tt.corrupt(&bad.base)
			err := Verify(bad)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Verify() = %v, want error containing %q", err, tt.want)
			}
		})
	}
}
