package check

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/zeroSteiner/idsrule/diag"
)

// noop is a Run that reports nothing.
func noop(*Context) {}

func TestRegistryRegister(t *testing.T) {
	valid := Check{ID: "x-y1", Severity: diag.SeverityError, Doc: "d", Run: noop}
	tests := []struct {
		name    string
		c       Check
		wantErr []string // substrings; empty means success
	}{
		{name: "valid", c: valid},
		{name: "duplicate", c: valid, wantErr: []string{`"x-y1" is already registered`}},
		{name: "single word", c: Check{ID: "abc", Severity: diag.SeverityWarning, Doc: "d", Run: noop}},
		{name: "uppercase", c: Check{ID: "Bad", Severity: diag.SeverityError, Doc: "d", Run: noop}, wantErr: []string{`invalid check id "Bad"`}},
		{name: "underscore", c: Check{ID: "a_b", Severity: diag.SeverityError, Doc: "d", Run: noop}, wantErr: []string{"invalid check id"}},
		{name: "leading dash", c: Check{ID: "-a", Severity: diag.SeverityError, Doc: "d", Run: noop}, wantErr: []string{"invalid check id"}},
		{name: "trailing dash", c: Check{ID: "a-", Severity: diag.SeverityError, Doc: "d", Run: noop}, wantErr: []string{"invalid check id"}},
		{name: "double dash", c: Check{ID: "a--b", Severity: diag.SeverityError, Doc: "d", Run: noop}, wantErr: []string{"invalid check id"}},
		{name: "digit first", c: Check{ID: "1a", Severity: diag.SeverityError, Doc: "d", Run: noop}, wantErr: []string{"invalid check id"}},
		{name: "empty id", c: Check{ID: "", Severity: diag.SeverityError, Doc: "d", Run: noop}, wantErr: []string{`invalid check id ""`}},
		{name: "bad severity", c: Check{ID: "sev", Severity: "loud", Doc: "d", Run: noop}, wantErr: []string{`invalid severity "loud"`}},
		{name: "zero severity", c: Check{ID: "sev0", Doc: "d", Run: noop}, wantErr: []string{`invalid severity ""`}},
		{name: "empty doc", c: Check{ID: "doc", Severity: diag.SeverityError, Doc: " ", Run: noop}, wantErr: []string{"empty Doc"}},
		{name: "nil run", c: Check{ID: "run", Severity: diag.SeverityError, Doc: "d"}, wantErr: []string{"nil Run"}},
		{name: "everything wrong", c: Check{ID: "?"}, wantErr: []string{"invalid check id", "invalid severity", "empty Doc", "nil Run"}},
	}
	r := newRegistry()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := r.register(tt.c)
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("register(%+v) = %v, want nil", tt.c, err)
				}
				if got, ok := r.lookup(tt.c.ID); !ok || got.ID != tt.c.ID {
					t.Errorf("lookup(%q) = %+v, %v after register", tt.c.ID, got, ok)
				}
				return
			}
			if err == nil {
				t.Fatalf("register(%+v) = nil, want an error", tt.c)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("register(%+v) = %v, want it to contain %q", tt.c, err, want)
				}
			}
		})
	}
	if got := r.all(); len(got) != 2 || got[0].ID != "abc" || got[1].ID != "x-y1" {
		t.Errorf("all() = %v, want abc and x-y1", got)
	}
}

func TestRegisterPanics(t *testing.T) {
	before := IDs()
	tests := []struct {
		name string
		c    Check
	}{
		{name: "invalid id", c: Check{ID: "Not Valid", Severity: diag.SeverityError, Doc: "d", Run: noop}},
		{name: "duplicate of a registered check", c: Check{ID: "sid-missing", Severity: diag.SeverityWarning, Doc: "impostor", Run: noop}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("Register(%+v) did not panic", tt.c)
				}
			}()
			Register(tt.c)
		})
	}
	if after := IDs(); !slices.Equal(before, after) {
		t.Errorf("a failed Register changed the registry: %v -> %v", before, after)
	}
	if c, ok := Lookup("sid-missing"); !ok || c.Doc == "impostor" || c.Severity != diag.SeverityError {
		t.Errorf("Lookup(sid-missing) = %+v, %v after a duplicate Register", c, ok)
	}
}

func TestAll(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("All() is empty")
	}
	ids := IDs()
	if len(ids) != len(all) {
		t.Fatalf("IDs() has %d entries, All() %d", len(ids), len(all))
	}
	if !slices.IsSorted(ids) {
		t.Errorf("IDs() is not sorted: %v", ids)
	}
	if len(slices.Compact(slices.Clone(ids))) != len(ids) {
		t.Errorf("IDs() has duplicates: %v", ids)
	}
	for i, c := range all {
		if c.ID != ids[i] {
			t.Errorf("All()[%d].ID = %q, IDs()[%d] = %q", i, c.ID, i, ids[i])
		}
		if !idPattern.MatchString(c.ID) || !c.Severity.Valid() || strings.TrimSpace(c.Doc) == "" || c.Run == nil {
			t.Errorf("registered check %+v is invalid", c)
		}
		if strings.ContainsAny(c.Doc, "\n") {
			t.Errorf("check %q: Doc is not one line", c.ID)
		}
	}

	// All returns copies.
	all[0].Doc = "modified"
	if c, _ := Lookup(all[0].ID); c.Doc == "modified" {
		t.Error("modifying All()'s result changed the registry")
	}
}

func TestLookupKnown(t *testing.T) {
	for _, id := range IDs() {
		c, ok := Lookup(id)
		if !ok || c.ID != id {
			t.Errorf("Lookup(%q) = %+v, %v", id, c, ok)
		}
		if !Known(id) {
			t.Errorf("Known(%q) = false", id)
		}
	}
	for _, id := range []string{"", "nope", "sid-missing ", "SID-MISSING", "config-invalid"} {
		if Known(id) {
			t.Errorf("Known(%q) = true", id)
		}
		if _, ok := Lookup(id); ok {
			t.Errorf("Lookup(%q) succeeded", id)
		}
	}
}

// TestRegisteredSet pins the checks this package registers and their
// default severities and dialect needs.
func TestRegisteredSet(t *testing.T) {
	want := []struct {
		id           string
		sev          diag.Severity
		needsDialect bool
	}{
		{"content-snort3-modifiers", diag.SeverityError, false},
		{"continuation-trailing-whitespace", diag.SeverityWarning, false},
		{"dialect-unknown", diag.SeverityWarning, false},
		{"header-invalid-action", diag.SeverityError, true},
		{"header-invalid-address", diag.SeverityError, false},
		{"header-invalid-port", diag.SeverityError, false},
		{"header-invalid-protocol", diag.SeverityError, true},
		{"keyword-deprecated", diag.SeverityWarning, true},
		{"keyword-unknown", diag.SeverityWarning, false},
		{"keyword-wrong-dialect", diag.SeverityError, true},
		{"modifier-without-content", diag.SeverityError, true},
		{"msg-duplicate", diag.SeverityError, false},
		{"msg-missing", diag.SeverityError, false},
		{"msg-prefix", diag.SeverityWarning, false},
		{"option-duplicate", diag.SeverityError, false},
		{"rev-missing", diag.SeverityError, false},
		{"sid-duplicate", diag.SeverityError, false},
		{"sid-missing", diag.SeverityError, false},
		{"sid-out-of-range", diag.SeverityError, false},
		{"sid-placeholder-without-msg", diag.SeverityError, false},
		{"sticky-buffer-empty", diag.SeverityWarning, true},
		{"value-invalid", diag.SeverityError, true},
		{"value-unescaped-quote", diag.SeverityWarning, true},
	}
	ids := make([]string, len(want))
	for i, w := range want {
		ids[i] = w.id
		c, ok := Lookup(w.id)
		if !ok {
			t.Errorf("check %q is not registered", w.id)
			continue
		}
		if c.Severity != w.sev || c.NeedsDialect != w.needsDialect || c.Style {
			t.Errorf("check %q: severity %q needsDialect %v style %v, want %q %v false", w.id, c.Severity, c.NeedsDialect, c.Style, w.sev, w.needsDialect)
		}
	}
	if got := IDs(); !slices.Equal(got, ids) {
		t.Errorf("IDs() = %v, want %v", got, ids)
	}
}

func TestIDPattern(t *testing.T) {
	if idPattern.String() != `^[a-z][a-z0-9]*(-[a-z0-9]+)*$` {
		t.Errorf("idPattern = %s", idPattern)
	}
	ok := []string{"a", "a1", "sid-duplicate", "a-b-c", "x9-y9"}
	bad := []string{"", "A", "a_b", "-a", "a-", "a--b", "1a", "a b", "a-B"}
	for _, id := range ok {
		if !idPattern.MatchString(id) {
			t.Errorf("%q should match", id)
		}
	}
	for _, id := range bad {
		if idPattern.MatchString(id) {
			t.Errorf("%q should not match", id)
		}
	}
	if _, err := regexp.Compile(idPattern.String()); err != nil {
		t.Error(err)
	}
}
