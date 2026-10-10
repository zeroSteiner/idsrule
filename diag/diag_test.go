package diag_test

import (
	"slices"
	"testing"

	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/source"
)

func TestSeverityValid(t *testing.T) {
	tests := []struct {
		sev  diag.Severity
		want bool
	}{
		{diag.SeverityError, true},
		{diag.SeverityWarning, true},
		{"", false},
		{"info", false},
		{"Error", false},
	}
	for _, tt := range tests {
		t.Run(string(tt.sev), func(t *testing.T) {
			if got := tt.sev.Valid(); got != tt.want {
				t.Errorf("Severity(%q).Valid() = %v, want %v", tt.sev, got, tt.want)
			}
		})
	}
}

func TestDiagnosticString(t *testing.T) {
	tests := []struct {
		name string
		d    diag.Diagnostic
		want string
	}{
		{
			name: "full",
			d: diag.Diagnostic{
				File: "local.snort.rule", Line: 12, Column: 5,
				Severity: diag.SeverityError, Rule: "sid-duplicate",
				Message: "sid 1000001 already used",
			},
			want: "local.snort.rule:12:5: error [sid-duplicate] sid 1000001 already used",
		},
		{
			name: "zero",
			d:    diag.Diagnostic{},
			want: ":0:0:  [] ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.d.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDiagnosticHasFix(t *testing.T) {
	tests := []struct {
		name  string
		edits []source.TextEdit
		want  bool
	}{
		{"nil", nil, false},
		{"empty", []source.TextEdit{}, false},
		{"one", []source.TextEdit{{Span: source.Span{Start: 1, End: 2}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := diag.Diagnostic{Edits: tt.edits}
			if got := d.HasFix(); got != tt.want {
				t.Errorf("HasFix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuilderNew(t *testing.T) {
	src := []byte("alert tcp\n  msg:\"x\";\n)")
	b := diag.Builder{File: "f.rule", Lines: source.NewLineTable(src)}

	span := source.Span{Start: 12, End: 20} // `msg:"x";` on line 2
	d := b.New("msg-style", diag.SeverityWarning, span, "bad %s at %d", "msg", 7)

	want := diag.Diagnostic{
		File: "f.rule", Line: 2, Column: 3,
		Severity: diag.SeverityWarning, Rule: "msg-style",
		Message: "bad msg at 7",
		End:     source.Position{Line: 2, Column: 11},
		Span:    span,
	}
	if d.String() != want.String() || d.End != want.End || d.Span != want.Span || d.Edits != nil || d.Related != nil {
		t.Errorf("New() = %+v, want %+v", d, want)
	}
	if d.HasFix() {
		t.Error("New() produced a diagnostic with a fix")
	}
}

func TestBuilderNewNilLines(t *testing.T) {
	b := diag.Builder{File: "f.rule"}
	d := b.New("r", diag.SeverityError, source.Span{Start: 40, End: 50}, "m")
	if d.Line != 1 || d.Column != 1 || d.End != (source.Position{Line: 1, Column: 1}) {
		t.Errorf("nil Lines resolved to line %d col %d end %+v, want 1/1/{1 1}", d.Line, d.Column, d.End)
	}
}

func TestBuilderResolve(t *testing.T) {
	b := diag.Builder{File: "f.rule", Lines: source.NewLineTable([]byte("ab\ncd\nef"))}

	t.Run("fills empty file and positions", func(t *testing.T) {
		d := diag.Diagnostic{Span: source.Span{Start: 4, End: 7}}
		b.Resolve(&d)
		if d.File != "f.rule" || d.Line != 2 || d.Column != 2 || d.End != (source.Position{Line: 3, Column: 2}) {
			t.Errorf("Resolve() = %+v", d)
		}
	})
	t.Run("keeps explicit file and recomputes stale positions", func(t *testing.T) {
		d := diag.Diagnostic{File: "other.rule", Line: 99, Column: 99, Span: source.Span{Start: 0, End: 1}}
		b.Resolve(&d)
		if d.File != "other.rule" || d.Line != 1 || d.Column != 1 || d.End != (source.Position{Line: 1, Column: 2}) {
			t.Errorf("Resolve() = %+v", d)
		}
	})
}

func TestSort(t *testing.T) {
	mk := func(file string, line, col int, rule, msg string) diag.Diagnostic {
		return diag.Diagnostic{File: file, Line: line, Column: col, Rule: rule, Message: msg}
	}
	in := []diag.Diagnostic{
		mk("b", 3, 1, "z", "m"),
		mk("a", 1, 5, "b", "m"),
		mk("b", 1, 5, "a", "m"), // same line/col as above, earlier rule
		mk("a", 2, 1, "a", "second"),
		mk("a", 2, 1, "a", "first"),
		mk("c", 1, 1, "a", "m"),
		mk("a", 1, 5, "b", "m"), // identical key to the "a" entry: stable order keeps it after
	}
	want := []diag.Diagnostic{
		mk("c", 1, 1, "a", "m"),
		mk("b", 1, 5, "a", "m"),
		mk("a", 1, 5, "b", "m"),
		mk("a", 1, 5, "b", "m"),
		mk("a", 2, 1, "a", "first"),
		mk("a", 2, 1, "a", "second"),
		mk("b", 3, 1, "z", "m"),
	}
	diag.Sort(in)
	if !slices.EqualFunc(in, want, func(a, b diag.Diagnostic) bool { return a.String() == b.String() }) {
		t.Errorf("Sort() order:\n got %v\nwant %v", in, want)
	}
}

func TestSortStable(t *testing.T) {
	in := []diag.Diagnostic{
		{File: "second", Line: 1, Column: 1, Rule: "r", Message: "m"},
		{File: "first", Line: 1, Column: 1, Rule: "r", Message: "m"},
	}
	diag.Sort(in)
	if in[0].File != "second" || in[1].File != "first" {
		t.Errorf("Sort() reordered equal keys: %v", in)
	}
}
