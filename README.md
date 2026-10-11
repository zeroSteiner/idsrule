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

The `style-*` checks are off by default; `Selection.Style` turns them all
on and `Selection.Enable` can name one. `Policy.Style` says what they hold
the rules to: `ContinuationIndent`, the indent of every continuation line
(empty, the default, accepts any indent as long as it is the same on every
continuation line of a rule), and `SpaceAfterColon` and
`SpaceAfterSemicolon`, whether a single space must, may or must not follow
an option's colon and semicolon (`DefaultPolicy` leaves the colon alone and
requires the space after the semicolon).

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
unchanged. The `fix` package does the low-level work: `fix.Validate` checks
a list of edits and `fix.Apply` applies one to a document.

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
