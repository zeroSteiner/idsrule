package idsrule_test

import (
	"bytes"
	"testing"

	"github.com/zeroSteiner/idsrule"
	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/parser"
)

func TestParse(t *testing.T) {
	t.Run("positions resolved", func(t *testing.T) {
		src := []byte("# comment\nalert tcp any any -> any any (sid:1\n")
		f, diags := idsrule.Parse("x.rule", src)
		if f == nil || f.Path != "x.rule" || f.Text() != string(src) {
			t.Fatalf("Parse() = %+v", f)
		}
		if err := cst.Verify(f); err != nil {
			t.Fatal(err)
		}
		if len(diags) != 1 {
			t.Fatalf("diagnostics = %v, want one missing-semicolon", diags)
		}
		d := diags[0]
		if d.Rule != parser.RuleMissingSemicolon || d.Severity != idsrule.SeverityError {
			t.Errorf("diagnostic = %v", d)
		}
		if d.File != "x.rule" || d.Line != 2 || d.Column != 36 || d.End != (idsrule.Position{Line: 2, Column: 36}) {
			t.Errorf("diagnostic positions = file %q line %d column %d end %v", d.File, d.Line, d.Column, d.End)
		}
		if d.Span != (idsrule.Span{Start: 45, End: 45}) {
			t.Errorf("diagnostic span = %v", d.Span)
		}
		if got := d.String(); got != `x.rule:2:36: error [syntax-missing-semicolon] missing ';' after option "sid"` {
			t.Errorf("diagnostic String() = %q", got)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		f, diags := idsrule.Parse("empty.rule", nil)
		if f == nil || f.Path != "empty.rule" || len(f.Items) != 0 || len(f.Rules()) != 0 || len(diags) != 0 {
			t.Errorf("Parse(empty) = %+v, %v", f, diags)
		}
		if err := cst.Verify(f); err != nil {
			t.Error(err)
		}
	})

	t.Run("dialect agnostic", func(t *testing.T) {
		src := []byte("alert http any any -> any any (http.method; content:\"POST\"; nocase ; sid:1;)\nalerts\n")
		snort, sd := idsrule.Parse("a.snort.rule", src)
		suri, ud := idsrule.Parse("a.suricata.rule", src)
		var a, b bytes.Buffer
		_ = cst.Dump(&a, snort)
		_ = cst.Dump(&b, suri)
		if !bytes.Equal(a.Bytes(), b.Bytes()) {
			t.Errorf("trees differ between dialects:\n%s\n%s", a.String(), b.String())
		}
		if len(sd) != 1 || len(ud) != 1 || sd[0].Rule != ud[0].Rule || sd[0].Line != ud[0].Line || sd[0].Column != ud[0].Column {
			t.Errorf("diagnostics differ between dialects: %v, %v", sd, ud)
		}
		if snort.Path != "a.snort.rule" || suri.Path != "a.suricata.rule" {
			t.Errorf("paths = %q, %q", snort.Path, suri.Path)
		}
	})

	t.Run("sorted", func(t *testing.T) {
		src := []byte("alert tcp any any -> any any (sid:1; @@;)\nx\nalert tcp any any -> any any (msg:; sid:2)\n")
		_, diags := idsrule.Parse("s.rule", src)
		want := []string{parser.RuleBadOption, parser.RuleBadHeader, parser.RuleMissingValue, parser.RuleMissingSemicolon}
		if len(diags) != len(want) {
			t.Fatalf("diagnostics = %v, want %v", diags, want)
		}
		for i, d := range diags {
			if d.Rule != want[i] {
				t.Errorf("diagnostic %d = %s, want %s", i, d.Rule, want[i])
			}
			if i > 0 && (d.Line < diags[i-1].Line || d.Line == diags[i-1].Line && d.Column < diags[i-1].Column) {
				t.Errorf("diagnostic %d %s is out of order", i, d)
			}
		}
	})
}
