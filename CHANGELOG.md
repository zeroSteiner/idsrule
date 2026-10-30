# Changelog

All notable changes to this module are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this module adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before v1 the API may change in any minor release.

## [Unreleased]

### Breaking changes

- The new `keyword-version` check (error) is on by default. Even with no
  version set it reports, as an error, a keyword that no Suricata release
  the tables describe accepts: `http2.header`, gone since Suricata 7.0.
  It also warns about `ssh.protoversion`, `ssh.softwareversion`, `luajit`
  and `mqtt.connack.return_code`, which Suricata 8.0 no longer accepts.
- The keywords `ip.hdr`, `krb5.weak_encryption` and
  `mqtt.connack.reason_code` are gone from the Suricata table: no Suricata
  release has them, so rules that use them are now `keyword-unknown`.
  `krb5.weak_encryption` is an app-layer event
  (`app-layer-event:krb5.weak_encryption`), and the MQTT alias is
  `mqtt.connack.return_code`.
- `ssh.protoversion` and `ssh.softwareversion` are deprecated in Suricata
  (successors `ssh.proto` and `ssh.software`), so `keyword-deprecated`
  reports them when the version is 7.0.
- `dialect.Keyword.Successor` may now be set on a removed keyword as well
  as on a deprecated one.
- A sticky buffer may take a value: the table invariant that a
  `RoleStickyBuffer` row takes no value is gone. Code that assumed it
  must handle `frame` (a required value) and the Suricata 8 directions.
- `dialect.KindRaw` moved up by one: `dialect.KindDirection` is
  declared before it. Code that stored `ValueKind` numbers must re-map
  them.
- `file_data` takes an optional, undecoded value (Snort 2.9's `mime`,
  Suricata 8's direction). `file.data`, `file.name`, `file.magic`, the
  `http.accept*`, `http.connection`, `http.content_len`,
  `http.content_type`, `http.location`, `http.referer` and `http.server`
  buffers, and their legacy `http_*` forms, take an optional
  `KindDirection`.
- `quic.version` is a sticky buffer, as in both Suricata 7 and 8. It no
  longer takes a value, so `quic.version:1` is now a `value-invalid`
  error.

### Added

- Suricata versions. `dialect.Version` names a release of a dialect's
  engine: `dialect.Suricata7`, `dialect.Suricata8`, `dialect.NewVersion`
  and `dialect.ParseVersion` (`"8"`, `"8.0"`, `"any"`). `AnyVersion`, the
  zero value, holds rules to what any release accepts.
  - `Dialect.Versions` and `Dialect.HasVersion` list a dialect's releases.
  - `Options.Version` (with the facade's `Version`, `VersionAny`,
    `VersionSuricata7`, `VersionSuricata8` and `ParseVersion`) and
    `check.Context.Version` choose the release. `Options.Validate` rejects
    a release that the dialect, or with `DialectUnknown` every dialect,
    lacks. A file whose detected dialect lacks the release is checked as
    `VersionAny`.
  - Keyword rows record the release that added them (`Keyword.Added`) and
    the one that removed them (`Keyword.Removed`), and `Keyword.In` says
    whether a release has a keyword. Eighteen keywords are marked as added
    in 8.0: `absent`, `from_base64`, `dns.answer.name`, the FTP keywords,
    `smtp.helo`, `smtp.mail_from`, `smtp.rcpt_to`,
    `mqtt.connect.protocol_string`, and the `flow.pkts_*` and
    `flow.bytes_*` counters.
- `keyword-version` check (error): a keyword that the release of the
  dialect being linted does not have, either because it came later
  (`"ftp.command" requires suricata 8.0 or later`) or because it was
  removed (`"luajit" was removed in suricata 8.0; use "lua"`). With no
  release set, a keyword that a later release removed is a warning.
- Suricata 8 directions. `dialect.KindDirection` (`to_client` or
  `to_server`) is the optional value of the sticky buffers that may name
  one (`file.data:to_client`). `dialect.Keyword.Directional` marks a
  keyword whose value may start with a direction and a `,`
  (`filesize:to_server,>100`). `value.ParseDirection` and
  `value.CutDirection` decode them. `value-invalid` reports a direction
  when the version is 7.0.
- `frame` (Suricata 7 and later): the sticky buffer that selects a
  frame, `frame:ssh.record.hdr`. It was unknown, so a `bsize` or
  `endswith` after it was also a `modifier-without-content` error.
- `content-depth-too-short` check (error): a `depth` or `within` smaller
  than the content it modifies, measured on the decoded pattern (escapes
  and `|hex|` bytes count once each), so it can never match; Suricata
  drops such a rule and Snort 2.9 refuses to start. As in both engines, the
  modifier applies to the latest content whatever options come between.
  Values given as a variable are skipped.

### Fixed

- `keyword-unknown` no longer reports the FTP keywords Suricata 8 added:
  the sticky buffers `ftp.command`, `ftp.command_data`, `ftp.reply` and
  `ftp.completion_code`, and `ftp.dynamic_port`, `ftp.mode` and
  `ftp.reply_received`, which take a value.
- `value-invalid` accepts the integer syntax Suricata 8 reads for its
  integer keywords (`dsize`, `bsize`, `filesize`, `urilen`, `itype`,
  `flow.age` and the like): hex numbers (`0x1f`), size units (`10kb`,
  `3MiB`), negated ranges (`!1-6`) and bitmask tests (`&0xc0=0x80`,
  `&0x40!=0`). It reports a bitmask test whose value has bits outside its
  mask, which Suricata rejects as never matching. `value.RelInt` gains the
  operators `!-`, `!<>`, `&=` and `&!=`. Snort 2.9 reads none of these
  forms, and the keywords both dialects share now accept them in Snort 2.9
  rules too.

## [0.1.0] - 2026-10-11

The first release: a lossless parser for Suricata and Snort 2.9 rule files,
with rule-aware checks and autofixes built on it. Go 1.24 or later; no
dependencies outside the standard library.

### Added

- **Root package** `idsrule`, a facade over the packages below: `Parse`,
  `Lint`, `Check`, `Fix`, `CheckIDs`, `DialectFromFilename`, `NewSIDIndex`,
  `Options` with `DefaultOptions` and `Validate`, `RuleConfigInvalid`
  (`config-invalid`, the single error returned for options that do not
  validate), and aliases for the types callers need (`File`, `Diagnostic`,
  `Related`, `Severity`, `Span`, `Position`, `TextEdit`, `Dialect`,
  `Policy`, `StylePolicy`, `Spacing`, `Selection`, `SIDIndex`, `SIDRef`).
  Runnable examples, including an adapter to the finding type of the
  pr-validate tool.
- **Lexer** (`lexer`): a mode-driven tokenizer that keeps every byte, trivia
  included, in exactly one token, so the token stream reproduces the input.
  It never fails; its one diagnostic is `syntax-unterminated-string`.
- **Parser and syntax tree** (`parser`, `cst`): a lossless concrete syntax
  tree whose nodes tile the source, so `File.Text()` returns the input byte
  for byte whatever it was, and a recovering recursive-descent parser that
  never fails: a malformed construct is reported and recovered from at the
  granularity of a header part, an option or a line, so one broken rule
  does not take the rules after it down with it. Parsing is
  dialect-agnostic.
  Syntax diagnostics: `syntax-bad-header`, `syntax-unbalanced-bracket`,
  `syntax-missing-open-paren`, `syntax-missing-close-paren`,
  `syntax-missing-semicolon`, `syntax-empty-option`, `syntax-missing-value`,
  `syntax-bad-option`, `syntax-trailing-text` and
  `syntax-unterminated-string`. `cst.Verify` checks the structural
  invariants of a tree and `cst.Dump` prints one.
- **Dialect tables** (`dialect`): 347 option keywords as data, 110 in
  Snort 2.9 and 312 in Suricata (75 in both, 35 only in Snort 2.9, 237 only
  in Suricata). Each row gives the dialects the keyword exists in, where it
  is deprecated (44 keywords, all in Suricata) and its successor there,
  whether and what kind of value it takes, its role, whether it may repeat,
  and its equivalent in the other dialect. Also the rule actions (8 in
  Snort 2.9, 7 in Suricata) and header protocols (4 in Snort 2.9, 52 in
  Suricata) of each dialect, and dialect detection from file names
  (`*.snort.rule`, `*.suricata.rule`, and their `.rules` spellings).
- **Value decoders** (`value`): typed decoders for option values, each
  error carrying a byte offset into the value: content (negation, escapes,
  `|hex|` blocks), pcre (both of Snort's forms), unsigned integers,
  integers or byte_extract variables, relational integers and ranges,
  urilen, quoted strings, identifiers, flow, flowbits, reference, metadata,
  threshold and detection_filter, base64_decode, fast_pattern, isdataat
  and comma-separated lists.
- **Checks** (`check`): a registry of checks, each with an id, a default
  severity, a style flag, a dialect requirement and a one-line doc; a
  `Policy` (sid range, placeholder threshold, required rev, msg prefix and
  normalization, style rules), a `Selection` (enable, disable, style,
  severity overrides) and a `SIDIndex` that finds duplicate sids across
  files. The 29 checks:
  `content-snort3-modifiers`, `continuation-trailing-whitespace`,
  `dialect-unknown`, `header-invalid-action`, `header-invalid-address`,
  `header-invalid-port`, `header-invalid-protocol`, `keyword-deprecated`,
  `keyword-unknown`, `keyword-wrong-dialect`, `modifier-without-content`,
  `msg-duplicate`, `msg-missing`, `msg-prefix`, `option-duplicate`,
  `rev-missing`, `sid-duplicate`, `sid-missing`, `sid-out-of-range`,
  `sid-placeholder-without-msg`, `sticky-buffer-empty`,
  `style-continuation-indent`, `style-missing-final-newline`,
  `style-rules-concatenated`, `style-space-after-colon`,
  `style-space-after-semicolon`, `style-trailing-whitespace`,
  `value-invalid` and `value-unescaped-quote`. The six `style-*` checks are
  off by default.
- **Fix engine** (`fix`, `idsrule.Fix`): `fix.Validate` and `fix.Apply`
  apply text edits that lie within the source and do not overlap, without
  modifying the input; `idsrule.Fix` takes diagnostics in order and applies
  each one's edits only when all of them fit among those already accepted,
  so conflicting fixes are never half-applied; linting and fixing the
  result again applies what a pass skipped. Seven checks carry fixes: `content-snort3-modifiers`,
  `continuation-trailing-whitespace`, `style-missing-final-newline`,
  `style-rules-concatenated`, `style-space-after-colon`,
  `style-space-after-semicolon` and `style-trailing-whitespace`.
- **Tests**: golden fixtures for the parser and every check and fix, fuzz
  targets `FuzzLex` and `FuzzParse`, scale tests (skipped with `-short`),
  and corpus tests that run when `IDSRULE_CORPUS` names a directory of rule
  files. On the reference corpus (64 files, 118 rules) every file parses
  with no diagnostics and round-trips byte for byte, every keyword is known
  in its file's dialect, all 1857 option values decode, and fixing every
  file keeps each rule's msg and sid and leaves nothing fixable.

### Engine-fidelity notes

Where Snort 2.9 and Suricata behave in a way that is easy to get wrong,
the module follows the engines:

- Options split on an unescaped `;` regardless of quotes: double quotes do
  not protect a `;`, so `content:"a;b";` ends the content after `a`. Write
  `\;` instead.
- The last `)` on a logical line closes the rule; any other `)` is part of
  an option value.
- A trailing `\` always continues the line, even when the byte before it
  is another backslash.
- Line continuations outside rules are trivia, as both engines splice
  continued lines before they parse them.
- Protocols are a fixed table of names per dialect, compared without
  regard to case; a protocol number is not accepted.
- Suricata's buffer transforms (such as `url_decode`) and buffer tests
  (`bsize`, `absent`) apply to the active sticky buffer and must follow
  one.

[Unreleased]: https://github.com/zeroSteiner/idsrule/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/zeroSteiner/idsrule/releases/tag/v0.1.0
