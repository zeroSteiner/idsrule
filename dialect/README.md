# Extending the dialect tables

Everything the checks know about rule option keywords is data in this
package: one `Keyword` row per keyword. Adding a keyword, or correcting
one, is a change to a row, not to the checks. This page says where the rows
live, what each field means, what the tests hold the rows to and how to
verify a change.

## Where the rows live

| File | Holds |
|---|---|
| `keywords_common.go` | `commonKeywords`: the keywords of both dialects (`Dialects: Both`) |
| `keywords_snort2.go` | `snort2Keywords`: the keywords only Snort 2.9 has (`Dialects: SetSnort2`) |
| `keywords_suricata.go` | `suricataKeywords`: the keywords only Suricata has (`Dialects: SetSuricata`), with the helpers `sticky`, `legacySticky`, `legacyModifier`, `appLayer`, `transform`, `uintMatch`, `enumMatch` and `directional` that build the common shapes, and `addedIn` and `withRole` that adjust one |
| `actions.go` | the rule actions of each dialect, and the Suricata release that added each new one |
| `protocols.go` | the header protocols of each dialect, compared without regard to case, split into packet and application-layer protocols, with the Suricata release that added each new one |
| `version.go` | `Version`, the releases of each dialect the tables describe |

The table a row goes in follows from its `Dialects`. Within a table the
rows are grouped by role under comments; put a new row with its kind.
`lookup.go` indexes the three tables by name at init and panics on a name
that appears twice, so a duplicate fails every test of a package that imports `dialect`.

A row looks like this:

```go
{Name: "http_uri", Dialects: Both, Deprecated: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleModifier, Repeatable: true, Successor: "http.uri"},
```

## The fields

| Field | Meaning | Read by |
|---|---|---|
| `Name` | The keyword as written in a rule, lower-case. Unique across all three tables. | every check that looks keywords up |
| `Dialects` | The dialects the keyword exists in: `SetSnort2`, `SetSuricata` or `Both`. | `keyword-wrong-dialect`; a keyword in neither table is `keyword-unknown` |
| `Deprecated` | The subset of `Dialects` in which the keyword is accepted but deprecated, such as the `http_*` content modifiers in Suricata. Zero when it is deprecated nowhere. | `keyword-deprecated` |
| `Value` | Whether the keyword takes a value: `NoValue` (`nocase;`), `Required` (`sid:1;`) or `Optional` (`fast_pattern;` or `fast_pattern:only;`). | `value-invalid` (a value where none is allowed, or none where one is required) |
| `Kind` | The grammar of the value, decoded by the `value` package: `KindUint`, `KindContent`, `KindFlow` and so on. `KindNone` exactly when `Value` is `NoValue`. `KindRaw` accepts any value; use it for a value whose grammar is not decoded. | `value-invalid`, `value-unescaped-quote`, `content-snort3-modifiers` |
| `Role` | What the keyword does: `RoleMeta`, `RolePayload`, `RoleModifier`, `RoleStickyBuffer`, `RoleTransform`, `RoleBufferTest`, `RoleFlow`, `RoleNonPayload`, `RolePostDetect`, `RoleAppLayer` or `RoleOther`. | `modifier-without-content`, `sticky-buffer-empty` |
| `Repeatable` | Whether the keyword may appear more than once in one rule. | `option-duplicate` |
| `Added`, `Removed` | The first release of the dialect that has the keyword, and the first that no longer accepts it: `Added: Suricata8` for `ftp.command`, `Removed: Suricata8` for `ssh.protoversion`. `AnyVersion` (unset) when every release the tables describe has it, or none has removed it. Set only on a keyword of one dialect, a dialect with versions (Suricata). The helper `addedIn` sets `Added`. | `keyword-version`; `keyword-deprecated` defers to it for a removed keyword |
| `Bits` | The width, 8, 16, 32 or 64, of the integer that Suricata's integer parser (`rust/src/detect/uint.rs`) reads the value into. Set only on a keyword that parser reads, whose `Kind` is `KindRelInt`, `KindUrilen` or `KindUintEnum`. `uintMatch` and `enumMatch` build such rows. | `value-invalid`, which in Suricata bounds the numbers and applies the parser's range and comparison checks |
| `Directional` | Whether the value may start with a Suricata 8 direction, `to_client` or `to_server`, and a `,` (`filesize:to_server,>100`). The rest of the value is of `Kind`. A sticky buffer whose whole value is a direction (`file.data:to_client`) uses `Value: Optional, Kind: KindDirection` instead. | `value-invalid` |
| `Replaces` | The equivalent keyword in the other dialect, set only on a row that exists in a single dialect: `http.uri` (Suricata) replaces `http_uri` (Snort 2). Empty when the other dialect has no equivalent. | `keyword-wrong-dialect`, which then says `use "http_uri"` |
| `Successor` | The keyword in the same dialect that supersedes this one, set only on a deprecated or removed row: `http.uri` for `http_uri` in Suricata. Empty when nothing replaces it one for one. | `keyword-deprecated` and `keyword-version`, which then say `use "http.uri"` |

`Replaces` and `Successor` answer different questions. `Replaces` points
across dialects ("what is this called in the other engine?") and only makes
sense on a keyword one dialect lacks; `Successor` points forward within a
dialect ("what should I write instead?") and only makes sense on a
deprecated keyword.

A new `ValueKind` is the one change that is code rather than data: it
needs a decoder in the `value` package, a case in `value.Validate` and a
name in `ValueKind.String`. Declare it before `KindRaw`: `ValueKind.Valid`
treats `KindRaw` as the last kind.

## When unsure, mark it `Both`

If the documentation does not settle whether a keyword exists in a
dialect, put it in `commonKeywords` with `Dialects: Both`. The two possible
mistakes do not cost the same:

- A keyword marked for one dialect that the other dialect also accepts
  makes `keyword-wrong-dialect` report an **error** on every valid rule of
  the other dialect that uses it, and an error fails the CI that runs the
  checks.
- A keyword marked `Both` that one dialect lacks only means that
  `keyword-wrong-dialect` misses it in that dialect. The rule is otherwise
  checked as before, and the engine still rejects it when it loads.

So `Both` errs on the side of no false errors. The same holds for
releases: when it is unclear which release added a keyword, leave `Added`
unset. An `Added` that is too late makes `keyword-version` report an
error on valid rules of the earlier release, while an unset one only
misses a rule that uses the keyword too early. Narrow it to one dialect
once the engine's documentation or source confirms it. The same reasoning
applies to the other fields that drive errors: a `Kind` stricter than the
engine makes `value-invalid` reject valid values (prefer `KindRaw` when in
doubt), and a keyword wrongly marked not `Repeatable` makes
`option-duplicate` reject valid rules.

## What the tests enforce

`TestTableInvariants` (in `tables_test.go`) holds every row to these
rules:

- `Name` is non-empty, lower-case, contains no blank or any of `:;,()"'`,
  and appears only once.
- `Dialects` is not empty and has no bit outside `Both`; `Deprecated` is a
  subset of `Dialects`.
- `Value`, `Kind` and `Role` are defined values, and `Value` is `NoValue`
  exactly when `Kind` is `KindNone`.
- A row whose `Value` is `Optional` has a `Kind` that accepts the empty
  value.
- A `RoleStickyBuffer` row is `Repeatable`.
- `KindDirection` is only the `Optional` value of a Suricata-only sticky
  buffer, and `Directional` is only set on a Suricata-only row whose
  value is `Required` and not a `KindDirection`.
- A `RoleTransform` or `RoleBufferTest` row exists only in Suricata and is
  `Repeatable`, and a buffer test takes a value.
- `Replaces` is set only on a single-dialect row, does not name the row
  itself, and names a keyword of the other dialect.
- `Successor` is set only on a deprecated or removed row, does not name
  the row itself, and names a keyword that exists, and is not deprecated,
  in every dialect the row is deprecated in and in the release that
  removed the row.
- `Added` and `Removed` are set only on a Suricata-only row, name
  releases the tables describe, `Added` is not the oldest release, and
  `Added` comes before `Removed`.
- `Bits` is 8, 16, 32 or 64, on a `KindRelInt`, `KindUrilen` or
  `KindUintEnum` row that Suricata has.
- `Lookup` finds the row in exactly the dialects of `Dialects`.

Next to it, `TestTableContents` spot-checks rows the rest of the module
relies on, `TestLegacyHTTPModifiers` checks the `http_*` content modifiers
against their `http.*` sticky-buffer successors, and `TestKeywords` checks
that the per-dialect listings are sorted and add up. If you change a row
that one of these names, update the test with it and say why in the
commit.

## How to verify a change

```sh
go test ./dialect
```

runs the tests above. Then run the whole module, with the corpus if you
have it, since the checks read the tables:

```sh
go test ./...
IDSRULE_CORPUS=/path/to/rules go test ./...
```

With the corpus set, three tests check the tables against real rules:
`TestCorpusKeywordCoverage` (every keyword a corpus rule uses is known in
the dialect of its file), `TestCorpusDialectCrossCheck` (no corpus keyword
is known only to the other dialect, which would mean a row has the wrong
`Dialects`) and `TestCorpusValuesDecode` (every corpus option value decodes
with its keyword's `Kind`). `TestCorpusLint` pins the findings the corpus
produces, so a row that changes what the checks report shows up there too.
