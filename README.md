# idsrule

`idsrule` is a Go library for working with Suricata and Snort 2.9 rule files.
It parses rules losslessly, so a parsed file can be written back byte for
byte, and layers rule-aware checks (lints) and autofixes on top of that
parse tree. The root package `github.com/zeroSteiner/idsrule` is a facade
over the smaller `source`, `diag`, `dialect` and `check` packages.

**Status: pre-alpha, API unstable.**

## Running the tests

```sh
go test -race ./...
```

Some tests exercise an external corpus of real rule files. Point
`IDSRULE_CORPUS` at a directory of `*.rule` files to run them; they are
skipped when the variable is unset:

```sh
IDSRULE_CORPUS=/path/to/rules go test -race ./...
```

## Checks

`idsrule.Lint(file, src, opts)` parses a file and runs the checks; the
result is the parser's `syntax-*` diagnostics and the checks' findings
together, sorted by position. `idsrule.Check` does the same on an
already-parsed `*File`, and `idsrule.CheckIDs()` lists the ids below. When
the options do not validate, both return a single `config-invalid` error at
1:1 instead; that id and the `syntax-*` ids are not checks and cannot be
selected.

| Check | Severity | Style | Needs dialect | Reports |
|---|---|---|---|---|
| `content-snort3-modifiers` | error | no | no | a content value carries Snort 3 style modifiers after its closing quote |
| `continuation-trailing-whitespace` | warning | no | no | spaces or tabs follow a line continuation's backslash |
| `dialect-unknown` | warning | no | no | the dialect is unknown, so the checks that need one were skipped |
| `header-invalid-action` | error | no | yes | the rule action is not one of the dialect's |
| `header-invalid-address` | error | no | no | an address is not any, a $variable, an IP literal with an optional /prefix, or a list of those (a group the parser rejected is left to its syntax diagnostic) |
| `header-invalid-port` | error | no | no | a port is not any, a $variable, a number, a range of 0 to 65535, or a list of those (a group the parser rejected is left to its syntax diagnostic) |
| `header-invalid-protocol` | error | no | yes | the protocol is not one of the dialect's names (compared without regard to case; protocol numbers are not accepted) |
| `keyword-deprecated` | warning | no | yes | an option keyword is deprecated in the file's dialect |
| `keyword-unknown` | warning | no | no | an option keyword is not known to any dialect |
| `keyword-wrong-dialect` | error | no | yes | an option keyword exists only in the other dialect |
| `modifier-without-content` | error | no | yes | a content modifier appears before any payload match of the rule, or a buffer transform or buffer test before any sticky buffer |
| `msg-duplicate` | error | no | no | two rules of the file have the same msg once normalized with Policy.NormalizeMsg |
| `msg-missing` | error | no | no | a rule has no msg option (a rule with a placeholder sid is left to sid-placeholder-without-msg) |
| `msg-prefix` | warning | no | no | a msg does not start with Policy.MsgPrefix (compared case-sensitively) |
| `option-duplicate` | error | no | no | a keyword that may appear only once in a rule appears again |
| `rev-missing` | error | no | no | a rule has no rev option while Policy.RequireRev is set |
| `sid-duplicate` | error | no | no | a sid is declared by more than one rule, in this file or, with a SIDIndex, in a file linted earlier |
| `sid-missing` | error | no | no | a rule has no sid option |
| `sid-out-of-range` | error | no | no | a sid is outside the range Policy.SIDMin to Policy.SIDMax |
| `sid-placeholder-without-msg` | error | no | no | a rule with a placeholder sid (below Policy.PlaceholderBelow) has no msg |
| `sticky-buffer-empty` | warning | no | yes | a sticky buffer is followed by another sticky buffer or the end of the rule with no payload match or buffer test in between (a transform alone does not use it) |
| `value-invalid` | error | no | yes | an option has a value it must not, lacks one it needs, or has one its keyword does not accept (sid 0 included: an error in Suricata, a warning in Snort 2) |
| `value-unescaped-quote` | warning | no | yes | a content or pcre value contains an odd number of unescaped double quotes |

Every non-style check runs by default; `Selection.Enable`, `Disable`,
`Style` and `Severity` adjust that per run. The `Policy` in the options
says what the rules are held to: the sid range, the placeholder threshold
(a sid below it is a draft and is exempt from the sid checks), whether a
rev is required, the msg prefix, and how messages are normalized before
duplicates are compared. The dialect is `Options.Dialect` or, when that is
`DialectUnknown`, detected from the file name (`*.snort.rule`,
`*.suricata.rule`, with `.rules` accepted too); a file whose dialect stays
unknown gets a `dialect-unknown` warning and the dialect-specific checks are
skipped. To find sid duplicates across files, share one `SIDIndex` through
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
