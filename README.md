# idsrule

[![ci](https://github.com/zeroSteiner/idsrule/actions/workflows/ci.yml/badge.svg)](https://github.com/zeroSteiner/idsrule/actions/workflows/ci.yml)

`idsrule` is a Go library for working with Suricata and Snort 2.9 rule
files. It parses rules losslessly, so a parsed file can be written back
byte for byte, comments and line continuations included, and layers
rule-aware checks (lints) and autofixes on top of that parse tree: every
finding points at exact bytes, and every fix edits only the bytes its
finding names. It is meant to be the rule-file half of a CI validator:
bytes in, findings out, with the caller owning file discovery and output.
The root package `github.com/zeroSteiner/idsrule` is a facade over the
smaller `source`, `diag`, `dialect`, `cst`, `parser`, `check` and `fix`
packages, so most callers need only that one import.

**Status: pre-1.0; the API may change before v1. [CHANGELOG.md](CHANGELOG.md) lists the releases.**

## Install

```sh
go get github.com/zeroSteiner/idsrule
```

The module needs Go 1.24 or later and has no dependencies outside the
standard library.

The repository is private, so the go command must be told to fetch it
directly from GitHub rather than through the public module proxy and
checksum database, and git needs credentials that can read it:

```sh
go env -w GOPRIVATE=github.com/zeroSteiner/idsrule
# then let git authenticate, for example over SSH:
git config --global url."git@github.com:".insteadOf "https://github.com/"
```

In CI, set `GOPRIVATE` in the job's environment and configure git with a
token that can read the repository before the first `go` command runs.
Workflows that GitHub runs for pull requests from forks get no secrets,
so they cannot fetch a private module at all: a consumer that takes
contributions through forks, as initial-access-community does, needs this
repository to be public or a vendored copy (`go mod vendor`) committed in
its own tree.

## Quick start

Lint every file named on the command line and fail when any has an error:

```go
package main

import (
	"fmt"
	"os"

	"github.com/zeroSteiner/idsrule"
)

func main() {
	opts := idsrule.DefaultOptions() // dialect from the file name, rev required
	failed := false
	for _, name := range os.Args[1:] {
		src, err := os.ReadFile(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		for _, d := range idsrule.Lint(name, src, opts) {
			fmt.Println(d.String())
			if d.Severity == idsrule.SeverityError {
				failed = true
			}
		}
	}
	if failed {
		os.Exit(1)
	}
}
```

Each finding prints as `file:line:column: severity [check-id] message`:

```text
local.snort.rule:1:117: error [content-snort3-modifiers] text after the closing quote ", nocase" is Snort 3 syntax; write it as separate options
```

Name the files `*.snort.rule` or `*.suricata.rule` (or `.rules`; a bare `local.rules` names no dialect) so
that the dialect is detected, or set `opts.Dialect`.

To apply the autofixes, lint, fix and repeat until a pass applies nothing:

```go
// fixFile returns src with every autofix applied.
func fixFile(name string, src []byte, opts idsrule.Options) ([]byte, error) {
	for range 10 { // one pass is normally enough; a skipped fix waits for the next
		out, applied, err := idsrule.Fix(src, idsrule.Lint(name, src, opts))
		if err != nil || applied == 0 {
			return src, err
		}
		src = out
	}
	return src, nil
}
```

[`example_test.go`](example_test.go) has runnable examples of linting,
fixing, finding sid duplicates across files and walking the parse tree
(`go test -run Example -v .`).

## Integrating with pr-validate

pr-validate (`tools/pr-validate` in initial-access-community) reports
problems as its own `Finding`, with a `Severity` of `"error"` or
`"warning"`; `idsrule`'s severities are the same two strings, so a
diagnostic converts field by field. `Service` stays empty: it names a
compose service, which a rule file does not have. This adapter lints one
rule file with the default options plus a sid policy: sids from
12,900,000 to 12,999,999, anything lower a placeholder (a draft, exempt
from the sid checks). The lower bound is the one the feed's sid script
starts from, and every sid in the current feed falls in the range; the
upper bound is an assumption, since the script's own constants disagree
with each other, so confirm the real range with the feed's maintainers.
Setting fields on `DefaultOptions` keeps the other defaults (a rev on
every rule, the spacing the style checks expect):

```go
// lintRuleFile lints one rule file of the feed and converts the
// diagnostics into pr-validate findings. sids is shared by every file of
// one dialect, so that a sid used twice across the feed is reported.
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
```

`ExampleLint` in [`example_test.go`](example_test.go) runs this same
function against a copy of pr-validate's `Finding` type; keep the two in
sync. The caller keeps one index per dialect:

```go
// lintFeed lints every rule file of the feed, with one SID index per
// dialect.
func lintFeed(files []string) ([]Finding, error) {
	sids := map[idsrule.Dialect]*idsrule.SIDIndex{
		idsrule.DialectSnort2:   idsrule.NewSIDIndex(),
		idsrule.DialectSuricata: idsrule.NewSIDIndex(),
	}
	var findings []Finding
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		findings = append(findings, lintRuleFile(file, data, sids[idsrule.DialectFromFilename(file)])...)
	}
	return findings, nil
}
```

Things to know when wiring it in:

- **One `SIDIndex` per dialect.** A `.snort.rule` file and its
  `.suricata.rule` counterpart carry the same sids by design, so sharing
  one index between them would report every pair as a duplicate. A file
  whose name gives no dialect gets a nil index here (no cross-file sid
  check) and a `dialect-unknown` warning.
- **Cross-file findings depend on lint order.** A file reports a sid only
  against the files linted before it, so the first of two files that share
  a sid stays silent. Lint the whole set a second time with the same
  indexes and keep only the second pass's findings to have both files
  report it.
- **pr-validate's CI must run `go run .`, not `go run validate.go`.** Given
  a file name, `go run` compiles only that one file of the multi-file
  `main` package, so the adapter (and the rest of the package) is left
  out.
- **pr-gate's path filter must include `feed/**/*.rule`.** It triggers only
  on `feed/**/README.md` and `feed/**/cve-*.go`, so a pull request that
  changes nothing but rule files never runs the validator.

## Concepts

**Lossless tree.** `Parse(file, src)` returns a `*idsrule.File`, the
concrete syntax tree of the `cst` package. Every byte of the source is in
it, comments, blank lines, whitespace, line continuations and even bytes
that do not parse, and the children of every node cover exactly the node's
span. So `f.Text() == string(src)` always holds, and the `Text()` of any
node is exactly its slice of the source. `f.Rules()`, `r.Options()`,
`r.Option("sid")` and `o.RawValue()` walk the tree; `o.LogicalValue()`
returns a value as the engines see it, line continuations spliced out, with
a function that maps offsets back to the source. Parsing never fails: a
malformed construct becomes a `syntax-*` diagnostic and the parser
recovers at the granularity of a header part, an option or a line, so one
bad rule never costs the rest of the file. The tree references `src` directly, so do not modify `src` after
parsing.

**Dialect-agnostic parse, dialect-aware checks.** The parser knows only
the grammar Snort 2.9 and Suricata share. What the options mean comes from
the keyword tables of the `dialect` package and is applied by the checks,
which run for one dialect: `Options.Dialect` or, when that is
`DialectUnknown`, the dialect detected from the file name (`*.snort.rule`,
`*.suricata.rule`, with their `.rules` spellings accepted too). A file whose dialect stays
unknown gets a `dialect-unknown` warning and the checks that need a dialect
are skipped.

**Options, Policy, Selection.** `Options` holds the dialect, the `Policy`,
the `Selection` and the optional `SIDIndex`; `DefaultOptions()` detects
the dialect, requires a rev and runs every non-style check. The `Policy`
says what the rules are held to: the sid range (`SIDMin`, `SIDMax`), the
placeholder threshold (`PlaceholderBelow`: a sid below it is a draft and
is exempt from the sid checks), whether a rev is required (`RequireRev`),
the msg prefix (`MsgPrefix`), how messages are normalized before
duplicates are compared (`NormalizeMsg`), and the style rules (`Style`).
The `Selection` says which checks run and how they report: every non-style
check runs by default, and `Enable`, `Disable`, `Style` and `Severity`
adjust that per run (`Disable` also removes a style check that `Style`
turned on; naming an id in both `Enable` and `Disable` is a
`config-invalid` error).

```go
// strictOptions holds a feed to a sid range and a msg prefix, treats
// deprecated keywords as errors and turns the style checks on.
func strictOptions() idsrule.Options {
	opts := idsrule.DefaultOptions()
	opts.Policy.SIDMin, opts.Policy.SIDMax = 12_900_000, 12_999_999
	opts.Policy.MsgPrefix = "ACME "
	opts.Checks.Style = true
	opts.Checks.Disable = []string{"style-continuation-indent"}
	opts.Checks.Severity = map[string]idsrule.Severity{"keyword-deprecated": idsrule.SeverityError}
	return opts
}
```

When the options do not validate (`Options.Validate`), `Lint` and `Check`
return a single `config-invalid` error at 1:1 instead of linting.

**Diagnostics.** A `Diagnostic` carries the `File`, the 1-based `Line` and
`Column` of its start (the column counts bytes, not characters), the `End`
position, the `Severity` (`error` or `warning`), the `Rule` (the check id,
or a `syntax-*` id or `config-invalid`) and the `Message`. `Span` is the
half-open byte range `[Start, End)` in the source that the finding is
about. `Edits`, when present, is the autofix as a list of text edits
(`HasFix` reports whether there is one). `Related` points at other
locations that explain the finding, such as the first declaration of a
duplicated sid, possibly in another file. `String()` renders
`file:line:column: severity [rule] message`.

## Checks

`idsrule.Lint(file, src, opts)` parses a file and runs the checks; the
result is the parser's `syntax-*` diagnostics and the checks' findings
together, sorted by position. `idsrule.Check` does the same on an
already-parsed `*File`, and `idsrule.CheckIDs()` lists the ids below. When
the options do not validate, both return a single `config-invalid` error at
1:1 instead; that id and the `syntax-*` ids are not checks and cannot be
selected.

| Check | Severity | Style | Needs dialect | Fix | Reports |
|---|---|---|---|---|---|
| `content-snort3-modifiers` | error | no | no | yes | a content value carries Snort 3 style modifiers after its closing quote |
| `continuation-trailing-whitespace` | warning | no | no | yes | spaces or tabs follow a line continuation's backslash |
| `dialect-unknown` | warning | no | no | no | the dialect is unknown, so the checks that need one were skipped |
| `header-invalid-action` | error | no | yes | no | the rule action is not one of the dialect's |
| `header-invalid-address` | error | no | no | no | an address is not any, a $variable, an IP literal with an optional /prefix, or a list of those (a group the parser rejected is left to its syntax diagnostic) |
| `header-invalid-port` | error | no | no | no | a port is not any, a $variable, a number, a range of 0 to 65535, or a list of those (a group the parser rejected is left to its syntax diagnostic) |
| `header-invalid-protocol` | error | no | yes | no | the protocol is not one of the dialect's names (compared without regard to case; protocol numbers are not accepted) |
| `keyword-deprecated` | warning | no | yes | no | an option keyword is deprecated in the file's dialect |
| `keyword-unknown` | warning | no | no | no | an option keyword is not known to any dialect |
| `keyword-wrong-dialect` | error | no | yes | no | an option keyword exists only in the other dialect |
| `modifier-without-content` | error | no | yes | no | a content modifier appears before any payload match of the rule, or a buffer transform or buffer test before any sticky buffer |
| `msg-duplicate` | error | no | no | no | two rules of the file have the same msg once normalized with Policy.NormalizeMsg |
| `msg-missing` | error | no | no | no | a rule has no msg option (a rule with a placeholder sid is left to sid-placeholder-without-msg) |
| `msg-prefix` | warning | no | no | no | a msg does not start with Policy.MsgPrefix (compared case-sensitively) |
| `option-duplicate` | error | no | no | no | a keyword that may appear only once in a rule appears again |
| `rev-missing` | error | no | no | no | a rule has no rev option while Policy.RequireRev is set |
| `sid-duplicate` | error | no | no | no | a sid is declared by more than one rule, in this file or, with a SIDIndex, in a file linted earlier |
| `sid-missing` | error | no | no | no | a rule has no sid option |
| `sid-out-of-range` | error | no | no | no | a sid is outside the range Policy.SIDMin to Policy.SIDMax |
| `sid-placeholder-without-msg` | error | no | no | no | a rule with a placeholder sid (below Policy.PlaceholderBelow) has no msg |
| `sticky-buffer-empty` | warning | no | yes | no | a sticky buffer is followed by another sticky buffer or the end of the rule with no payload match or buffer test in between (a transform alone does not use it) |
| `style-continuation-indent` | warning | yes | no | no | a continuation line of a rule is not indented like the rule's first continuation line, or like Policy.Style.ContinuationIndent when that is set (a line holding only the closing parenthesis is exempt) |
| `style-missing-final-newline` | warning | yes | no | yes | the file does not end with a newline |
| `style-rules-concatenated` | warning | yes | no | yes | a rule is followed by another rule on the same line |
| `style-space-after-colon` | warning | yes | no | yes | the whitespace between an option's colon and its value is not what Policy.Style.SpaceAfterColon demands: exactly one space, or none |
| `style-space-after-semicolon` | warning | yes | no | yes | the whitespace between an option's semicolon and the next option on the same line is not what Policy.Style.SpaceAfterSemicolon demands: exactly one space, or none |
| `style-trailing-whitespace` | warning | yes | no | yes | spaces or tabs end a line (those after a line continuation's backslash are left to continuation-trailing-whitespace) |
| `value-invalid` | error | no | yes | no | an option has a value it must not, lacks one it needs, or has one its keyword does not accept (sid 0 included: an error in Suricata, a warning in Snort 2) |
| `value-unescaped-quote` | warning | no | yes | no | a content or pcre value contains an odd number of unescaped double quotes |

Every non-style check runs by default; `Selection.Enable`, `Disable`,
`Style` and `Severity` adjust that per run, and the `Policy` in the options
sets what the sid, rev and msg checks hold the rules to (see
[Concepts](#concepts)). The checks marked "Needs dialect" are skipped, with
a `dialect-unknown` warning, when the file's dialect is unknown.

To find sid duplicates across files, share one `SIDIndex` through
`Options.SIDs` for every file that is linted, and keep one index per
dialect: a Snort file and its Suricata counterpart legitimately carry the
same sid, so they must not share an index. The index is kept up to date by
every `Lint` or `Check` call whatever checks are selected, and linting a
file again replaces its entries. Cross-file findings depend on the order
the files are linted in: a file reports a sid only against the files
linted before it, so the first of two files that share a sid stays silent
until it is linted again (a second pass over the set makes the findings
symmetric). They are deterministic only when the files are linted one
after another; concurrent calls sharing an index are race-free, but the
interleaving then decides which file reports.

The `style-*` checks are off by default; `Selection.Style` turns them all
on and `Selection.Enable` can name one. `Policy.Style` says what they hold
the rules to: `ContinuationIndent`, the indent of every continuation line
(empty, the default, accepts any indent as long as it is the same on every
continuation line of a rule), and `SpaceAfterColon` and
`SpaceAfterSemicolon`, whether a single space must, may or must not follow
an option's colon and semicolon (`SpacingRequire`, `SpacingAny`,
`SpacingForbid`; `DefaultPolicy` leaves the colon alone and requires the
space after the semicolon).

## Autofix

A check may attach an autofix to a finding as a list of text edits in
`Diagnostic.Edits`; `HasFix` reports whether a finding carries one, and the
Fix column of the table above lists the checks that do. `idsrule.Fix(src,
diags)` applies the fixes of a list of diagnostics to the source and returns
the new bytes and the number of diagnostics applied; `src` itself is never
modified. Diagnostics are taken in order, and a diagnostic's edits are
accepted only when every one of them lies within the source and is disjoint
from the edits already accepted; otherwise the whole diagnostic is skipped,
so two fixes that touch the same bytes never corrupt the file: the first one
wins and the other is left for the next pass. Re-`Lint` the result and `Fix`
it again to converge; a pass that applies nothing returns the source
unchanged. `Fix` expects the diagnostics in position order, as `Lint`
returns them. The `fix` package does the low-level work: `fix.Validate`
checks a list of edits and `fix.Apply` applies one to a document.

What the fixes do:

- `content-snort3-modifiers` rewrites the text after the closing quote as
  options of their own: `content:"x", nocase, depth 5;` becomes
  `content:"x"; nocase; depth:5;`, spaced as `Policy.Style` wants (no space
  after the semicolon when `SpaceAfterSemicolon` forbids one, a space after
  the colon when `SpaceAfterColon` requires one). Text that is not a
  comma-separated list of `name` or `name arg` modifiers, or that spans a
  line continuation, is reported without a fix.
- `continuation-trailing-whitespace` and `style-trailing-whitespace` delete
  the blanks, except blanks that end a file with no newline after them:
  those are left to the next fix.
- `style-space-after-colon` and `style-space-after-semicolon` insert,
  replace or delete the whitespace so that it matches the policy.
- `style-rules-concatenated` puts a newline between the two rules.
- `style-missing-final-newline` appends one, in place of any blanks that end
  the file.

A fix changes nothing beyond what its finding names: the result of fixing a
file parses into the same rules, with the same msg and sid in each, and
fixing it again changes nothing. The corpus test `TestCorpusFixRoundTrip`
holds every fix to that.

## Extending the dialect tables

What the checks know about keywords is data: each keyword is one row of a
table in the `dialect` package that says which dialects have it, where it
is deprecated and in favour of what, whether it takes a value and of which
grammar, what role it plays and whether it may repeat. Adding or correcting
a keyword is a one-row change, checked by the table invariant tests and the
corpus coverage tests. [`dialect/README.md`](dialect/README.md) describes
the fields, the invariants and the rule to follow when the documentation
is unclear (mark the keyword as existing in both dialects).

## Running the tests

```sh
go test -race ./...
```

`-short` skips the scale tests, which time the parser, the tree verifier
and the fix engine on large inputs to guard against quadratic paths:

```sh
go test -short ./...
```

Some tests exercise an external corpus of real rule files. Point
`IDSRULE_CORPUS` at a directory of `*.rule` files to run them; they are
skipped when the variable is unset:

```sh
IDSRULE_CORPUS=/path/to/rules go test -race ./...
```

When the variable is set, a misconfigured corpus fails rather than skips:
a value that is not a directory, or a directory with no `*.rule` files
directly in it, fails every corpus test. Every file name must carry its
dialect (`*.snort.rule` or `*.suricata.rule`). `TestCorpusLint` pins the
number of findings the reference corpus produces per check, so another
corpus will fail it while still exercising everything else.

The lexer and the parser have fuzz targets, `FuzzLex` and `FuzzParse`,
seeded with their test inputs and, when `IDSRULE_CORPUS` is set, with every
corpus file:

```sh
go test ./lexer -run='^$' -fuzz=FuzzLex -fuzztime=1m
go test ./parser -run='^$' -fuzz=FuzzParse -fuzztime=1m
```

CI runs `go vet` and `go test -race ./...` on Go 1.24 and 1.25,
`golangci-lint`, and a ten-second smoke run of each fuzz target.

## License

Apache-2.0; see [LICENSE](LICENSE).
