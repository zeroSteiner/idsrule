package idsrule_test

import (
	"fmt"
	"strconv"

	"github.com/zeroSteiner/idsrule"
)

// Severity, Finding and Finding.String are copied from the pr-validate
// tool, so that ExampleLint proves the adapter below compiles against the
// consumer's own types.
type Severity string

// The severities pr-validate reports.
const (
	SevError   Severity = "error"
	SevWarning Severity = "warning"
)

// Finding is one problem pr-validate reports.
type Finding struct {
	File     string
	Line     int
	Column   int
	Severity Severity
	Rule     string
	Service  string
	Message  string
}

// String renders f the way pr-validate prints it.
func (f Finding) String() string {
	svc := ""
	if f.Service != "" {
		svc = " service " + strconv.Quote(f.Service) + ":"
	}
	return fmt.Sprintf("%s:%d:%d: %s [%s]%s %s", f.File, f.Line, f.Column, f.Severity, f.Rule, svc, f.Message)
}

// lintRuleFile lints one rule file of the feed and converts the
// diagnostics into pr-validate findings. sids is shared by every file of
// one dialect, so that a sid used twice across the feed is reported.
// Keep it in sync with the copy in README.md.
func lintRuleFile(file string, data []byte, sids *idsrule.SIDIndex) []Finding {
	opts := idsrule.DefaultOptions()
	opts.Policy.SIDMin = 12_900_000
	opts.Policy.SIDMax = 12_999_999
	opts.Policy.PlaceholderBelow = 12_900_000
	opts.SIDs = sids
	var out []Finding
	for _, d := range idsrule.Lint(file, data, opts) {
		out = append(out, Finding{
			File:     d.File,
			Line:     d.Line,
			Column:   d.Column,
			Severity: Severity(d.Severity),
			Rule:     d.Rule,
			Message:  d.Message,
		})
	}
	return out
}

// ExampleLint lints a Snort 2 rule file through the pr-validate adapter:
// the first rule writes a content modifier the Snort 3 way, the second
// has no rev and uses a Suricata sticky buffer.
func ExampleLint() {
	src := []byte(`alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Example admin probe"; flow:to_server,established; content:"/admin", nocase; sid:12900001; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Example cgi probe"; flow:to_server,established; http.uri; content:"/cgi-bin/"; sid:12900002;)
`)
	snortSIDs := idsrule.NewSIDIndex() // one index for every .snort.rule file of the feed
	for _, f := range lintRuleFile("feed/example.snort.rule", src, snortSIDs) {
		fmt.Println(f)
	}
	// Output:
	// feed/example.snort.rule:1:117: error [content-snort3-modifiers] text after the closing quote ", nocase" is Snort 3 syntax; write it as separate options
	// feed/example.snort.rule:2:1: error [rev-missing] rule has no rev
	// feed/example.snort.rule:2:99: error [keyword-wrong-dialect] "http.uri" is a suricata keyword; use "http_uri"
}

// ExampleFix applies the autofixes of one Lint pass and lints the result
// again: both findings were fixable, so nothing is left.
func ExampleFix() {
	src := []byte(`alert tcp any any -> any 80 (msg:"Example"; content:"x", nocase; sid:1000001; rev:1;)`)
	opts := idsrule.DefaultOptions()
	opts.Checks.Style = true // style-missing-final-newline is a style check

	diags := idsrule.Lint("local.suricata.rule", src, opts)
	for _, d := range diags {
		fmt.Println(d)
	}
	out, applied, err := idsrule.Fix(src, diags)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%q\n", out)
	fmt.Println("applied:", applied)

	again := idsrule.Lint("local.suricata.rule", out, opts)
	fixable := 0
	for _, d := range again {
		if d.HasFix() {
			fixable++
		}
	}
	fmt.Printf("remaining: %d (%d fixable)\n", len(again), fixable)
	// Output:
	// local.suricata.rule:1:56: error [content-snort3-modifiers] text after the closing quote ", nocase" is Snort 3 syntax; write it as separate options
	// local.suricata.rule:1:86: warning [style-missing-final-newline] no newline at end of file
	// "alert tcp any any -> any 80 (msg:\"Example\"; content:\"x\"; nocase; sid:1000001; rev:1;)\n"
	// applied: 2
	// remaining: 0 (0 fixable)
}

// ExampleSIDIndex finds a sid declared in two files. The files are linted
// one after the other with one shared index: a.snort.rule, linted first,
// has nothing to compare against, and b.snort.rule reports the duplicate
// with a Related entry that points into a.snort.rule.
func ExampleSIDIndex() {
	a := []byte("alert tcp any any -> any any (msg:\"A\"; sid:1000001; rev:1;)\n")
	b := []byte("alert tcp any any -> any any (msg:\"B\"; sid:1000001; rev:1;)\n")

	// One index per dialect: a .snort.rule file and its .suricata.rule
	// counterpart carry the same sids by design, so the Snort files and
	// the Suricata files each need an index of their own.
	opts := idsrule.DefaultOptions()
	opts.SIDs = idsrule.NewSIDIndex()

	fmt.Println("a.snort.rule:", len(idsrule.Lint("a.snort.rule", a, opts)), "diagnostics")
	for _, d := range idsrule.Lint("b.snort.rule", b, opts) {
		if d.Rule != "sid-duplicate" {
			continue
		}
		fmt.Println(d)
		for _, r := range d.Related {
			fmt.Printf("  related: %s:%d:%d: %s\n", r.File, r.Line, r.Column, r.Message)
		}
	}
	// Output:
	// a.snort.rule: 0 diagnostics
	// b.snort.rule:1:40: error [sid-duplicate] duplicate sid 1000001: also declared in a.snort.rule
	//   related: a.snort.rule:1:40: also declared here
}

// ExampleParse parses one rule written over two lines with a line
// continuation. The tree keeps every byte of the source.
func ExampleParse() {
	src := []byte("alert tcp any any -> any any (msg:\"Two lines\"; \\\n    sid:1000001; rev:1;)\n")
	f, diags := idsrule.Parse("local.suricata.rule", src)
	fmt.Println("diagnostics:", len(diags))
	fmt.Println("rules:", len(f.Rules()))
	fmt.Println("sid:", f.Rules()[0].Option("sid").RawValue())
	fmt.Println("lossless:", f.Text() == string(src))
	// Output:
	// diagnostics: 0
	// rules: 1
	// sid: 1000001
	// lossless: true
}

// ExampleDialectFromFilename detects the dialect from the file name's
// suffix.
func ExampleDialectFromFilename() {
	for _, name := range []string{"feed/cve-2024-0001.snort.rule", "feed/cve-2024-0001.suricata.rule", "local.rules"} {
		fmt.Printf("%s: %s\n", name, idsrule.DialectFromFilename(name))
	}
	// Output:
	// feed/cve-2024-0001.snort.rule: snort2
	// feed/cve-2024-0001.suricata.rule: suricata
	// local.rules: unknown
}
