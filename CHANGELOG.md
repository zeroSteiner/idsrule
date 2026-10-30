# Changelog

All notable changes to this module are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this module adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before v1 the API may change in any minor release.

## [Unreleased]

## [0.3.0] - 2026-10-30

Suricata 8 support. The tables now cover every keyword Suricata 7.0 and
8.0 register, rules can be held to one release with `Options.Version`,
the parser reads the Suricata 8 header syntax, and `Policy.Firewall`
covers firewall rule files. This release has breaking changes, listed
first.

### Breaking changes

- The new `keyword-version` check (error) is on by default. Even with no
  version set it reports, as an error, a keyword that no Suricata release
  the tables describe accepts: `http2.header`, gone since Suricata 7.0.
  It also warns about `ssh.protoversion`, `ssh.softwareversion`, `luajit`
  and `mqtt.connack.return_code`, which Suricata 8.0 no longer accepts.
- The new `content-md5-invalid` check (error) is on by default. A content
  in `ja3.hash`, `ja3s.hash`, `ssh.hassh`, `ssh.hassh.server` or
  `quic.cyu.hash` that is not 32 bytes is an error, as Suricata 7 and 8
  refuse the rule. One with a byte that is not a hex digit is a warning
  (an error with the version set to 8.0).
- The keywords `ip.hdr`, `krb5.weak_encryption` and
  `mqtt.connack.reason_code` are gone from the Suricata table: no Suricata
  release has them, so rules that use them are now `keyword-unknown`.
  `krb5.weak_encryption` is an app-layer event
  (`app-layer-event:krb5.weak_encryption`), and the MQTT alias is
  `mqtt.connack.return_code`.
- `ssh.protoversion` and `ssh.softwareversion` are deprecated in Suricata
  (successors `ssh.proto` and `ssh.software`), so `keyword-deprecated`
  reports them unless the version is 8.0, which has no such keywords
  (`keyword-version` reports them there). The two checks run
  independently: with no version set, both warn.
- `dialect.Keyword.Successor` may now be set on a removed keyword as well
  as on a deprecated one.
- A sticky buffer may take a value: the table invariant that a
  `RoleStickyBuffer` row takes no value is gone. Code that assumed it
  must handle `frame` (a required value) and the Suricata 8 directions.
- `dialect.KindRaw` moved up by four: `dialect.KindDirection`,
  `KindTos`, `KindQuotedUint` and `KindUintEnum` are declared before it.
  Code that stored `ValueKind` numbers must re-map them.
- `value.RelInt` gains `Forms`, so a `RelInt` literal compared with
  `==` must set it. `RelInt.A` and `RelInt.B` are `uint64`, not `int64`,
  because Suricata reads integers up to 64 bits.
- In Suricata, `value-invalid` now applies the checks of Suricata's
  integer parser to the keywords it reads with that parser (those whose
  `Keyword.Bits` is set):
  - a number too large for the keyword's width is an error
    (`itype:300`);
  - so is a range with no number strictly between its bounds
    (`dsize:5-6`; Suricata's ranges exclude them);
  - and so is a comparison no number satisfies, or every number does
    (`dsize:<0`, `itype:>255`).
  Snort 2.9's ranges include their bounds, so its rules are not held to
  these checks.
- `dns.opcode` and `rfb.secresult` are `Repeatable`, since Suricata takes
  several conditions on one field, so `option-duplicate` no longer
  reports them.
- `tos` is `KindTos`, the `[!]N` or `[!]xHH` form both engines read, not
  `KindRelInt`, so `tos:<5` is now an error. `id`, `icmp_id` and
  `icmp_seq` are `KindQuotedUint`, and `rfb.secresult` is `KindUintEnum`.
- `file_data` takes an optional value. Its table kind is `KindRaw`, and
  `value-invalid` checks the value per dialect: `mime` in Snort 2.9, and
  a direction in Suricata 8 (none in 7.0). `file.data`, `file.name`, `file.magic`, the
  `http.accept*`, `http.connection`, `http.content_len`,
  `http.content_type`, `http.location`, `http.referer` and `http.server`
  buffers, and their legacy `http_*` forms, take an optional
  `KindDirection`.
- `quic.version` is a sticky buffer, as in both Suricata 7 and 8. It no
  longer takes a value, so `quic.version:1` is now a `value-invalid`
  error.
- The parser reads Suricata 8 headers that it used to report as
  `syntax-bad-header`. The checks now report them where they do not
  belong.
  - `cst.Header` gains `MoreActions` and `ActionCommas` for a firewall
    rule's action list (`accept:hook,alert`).
  - Scopes and hooks stay in their tokens: `Action.Lit` may be
    `"drop:flow"` and `Proto.Lit` may be `"http1:request_line"`.
  - `Dir` may be `"=>"`.
  - An address or port list without brackets
    (`10.0.0.0/8,!10.1.0.0/16`) is a `cst.List` with `Missing` brackets;
    see `List.Bracketed`.
- `parser.IsAction` accepts `config` and `accept`, and an action with a
  scope (`drop:flow`). A line that starts with one of them is parsed as
  a rule, except a line that starts with the bare word `config` and has
  no direction (`->`, `<>`, `=>`) before its first `(`. That is a
  configuration directive (Snort's `config classification: ...`), and it
  is still one `syntax-bad-header`.
- `config` and `accept` are Suricata actions (`Dialect.Actions`), and
  `doh2` a Suricata protocol.

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
- Suricata 8 rule headers.
  - Action scopes: `drop`, `pass` and the `reject` actions take `packet`
    or `flow`, `config` takes `packet`, and `accept` takes `packet`,
    `flow`, `tx` or `hook`.
  - The `config` action (Suricata 7 and later).
  - Protocol hooks: `http1:request_line`, `dns:request_complete`,
    `http1:<request_headers`, `tcp:all`.
  - The transactional `=>` direction.
  - Address and port lists without brackets.
  - `header-invalid-action`, `header-invalid-protocol` and the new
    `header-invalid-direction` check (error) report each of these where
    the dialect or release lacks it. They also report a scope the action
    does not take, a packet hook that is not `flow_start`, `pre_flow`,
    `pre_stream` or `all`, and a malformed application hook.
  - `header-invalid-address` and `header-invalid-port` report a list
    without brackets in Snort 2.9.
- `Policy.Firewall` marks Suricata files as Suricata 8 firewall rule
  files. Only there is the `accept` action valid, and only there may a
  rule list several actions. `header-invalid-action` holds these rules to
  what Suricata requires:
  - the first action is `accept`, `config`, `drop` or `reject`, and the
    others are `alert` or `pass`;
  - `pass` comes only after `accept`, and inherits only `packet` or
    `flow`;
  - the rule gives a scope, and every scope agrees.
  `header-invalid-direction` reports `=>` in a firewall rule.
- `Dialect.ActionAdded`, `Dialect.ProtocolAdded` and
  `Dialect.IsPacketProtocol`. `doh2` is new, and `ldap`, `mdns`, `pop3`
  and `websocket` are marked as added in Suricata 8.0.
- `threshold: type backoff` (Suricata 8). `multiplier` takes the place
  of `seconds`, and `ParseThreshold` enforces Suricata's rules: the
  multiplier is 2 to 65535, the count 1 to 65535, the track `by_flow`,
  and `seconds` is not allowed. Suricata 8 also reads `multiplier` with
  the other types. `value.Threshold` gains `Multiplier` and
  `HasMultiplier`. Snort 2.9, and Suricata with the version set to 7.0,
  still reject both.
  This was the most visible gap: 44 of the rules Suricata 8.0.8 ships
  failed `value-invalid`.
- `tos:x10`, Suricata's hex form (`value.ParseTos`, `KindTos`), and quoted
  numbers in `id:"123"`, `icmp_id` and `icmp_seq`
  (`value.ParseQuotedUint`, `KindQuotedUint`). Quoted numbers stay an
  error in Snort 2.9.
- `KindUintEnum` and `value.ParseUintEnum`: a Suricata 8 integer that may
  be given by name, `rfb.secresult:!fail`. A name is a letter or `_`
  followed by letters, digits and `_`. Suricata 7 reads only the name.
- `value.RelIntForm`, `RelInt.Forms` and `RelInt.Suricata7` say which
  integer forms a value uses, and whether Suricata 7 reads them.
- `content-md5-invalid` check (error). It reports a content in an MD5
  buffer (`ja3.hash`, `ja3s.hash`, `ssh.hassh`, `ssh.hassh.server`,
  `quic.cyu.hash`) that is not 32 bytes, which Suricata refuses. It also
  reports one with a byte that is not a hex digit: it never matches, and
  Suricata 8 refuses it (a warning before 8.0 or with no release set).
- The rest of Suricata's keywords: the tables now have every keyword
  Suricata 7.0.12 and 8.0.8 register, apart from internal and demo ones
  (`__filestore__postmatch__`, `__flowvar__postmatch__`, `template*`).
  This adds 125 keywords, 98 of them new in 8.0 and marked so:
  - whole families: `email.*`, `ldap.*`, `sdp.*`, `enip.*`, `ntp.*`,
    `mdns.*`, `websocket.*`, `vlan.*`;
  - the DNS v2 buffers (`dns.queries.rrname` and the like),
    `dns.rcode`, `dns.rrtype`, and the new SIP header buffers;
  - `tls.alpn`, `tls.subjectaltname`, `pgsql.query`, `smb.version`,
    `snmp.trap_type`, `tcp.wscale`, `tcp.session`, `flow.pkts`,
    `flow.bytes`, `flow.elephant`, `app-layer-state` and `entropy`;
  - the transforms `domain`, `tld`, `gunzip`, `zlib_deflate` and
    `luaxform`.
  The other 27 were already missing for Suricata 7: the checksum
  keywords (`ipv4-csum` and the like, used by Suricata's own
  `decoder-events.rules`), `flowvar`, `pktvar`, `alert`,
  `nfq_set_mark`, `ip.src`, `ip.dst`, `tcp.ack`, `tcp.seq`,
  `tcp.window`, `nfs.version`, `tls_store`, and the aliases
  `dnp3.func`, `dnp3.ind`, `dnp3.obj`, `http.uri.normalized`,
  `ja4_hash` and `ssh-hassh*`. A value Suricata reads with its integer
  parser is `KindRelInt`, or `KindUintEnum` where names are allowed,
  with its width. Other values are undecoded.
- `dialect.Keyword.Bits`: the width of the integer Suricata's integer
  parser reads a keyword's value into. It is set on every keyword that
  parser reads (`dsize`, `itype`, `bsize`, `filesize`, the new `enip.*`
  numbers, ...).

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
  operators `!-`, `!<>`, `&=` and `&!=`.
  - The forms are accepted only on keywords that Suricata reads with its
    integer parser (`Keyword.Bits`). `window`, `fragoffset` and
    `tcp.window` have parsers of their own and still take plain decimal
    numbers.
  - Snort 2.9 reads none of these forms, and Suricata 7 reads only kb, mb
    and gb on a plain number. Both still reject the rest, and the message
    now names the form.

## [0.2.0] - 2026-10-13

### Added

- `content-depth-too-short` check (error): a `depth` or `within` smaller
  than the content it modifies, measured on the decoded pattern (escapes
  and `|hex|` bytes count once each), so it can never match; Suricata
  drops such a rule and Snort 2.9 refuses to start. As in both engines, the
  modifier applies to the latest content whatever options come between.
  Values given as a variable are skipped.

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

[Unreleased]: https://github.com/zeroSteiner/idsrule/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/zeroSteiner/idsrule/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/zeroSteiner/idsrule/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/zeroSteiner/idsrule/releases/tag/v0.1.0
