// Package idsrule parses, checks and fixes Suricata and Snort 2.9 rule
// files.
//
// It works in three layers, each built on the one before:
//
//   - [Parse] builds a lossless concrete syntax tree, a [File]. Every
//     byte of the source, comments, whitespace and line continuations
//     included, is in the tree, so its Text method returns the source
//     unchanged. Parsing is dialect-agnostic, never fails and recovers from
//     errors, which it reports as syntax-* diagnostics.
//   - [Check] runs rule-aware checks over a tree and [Lint] parses
//     and checks in one call. The checks know the dialect, taken from
//     [Options] or the file name; they hold the rules to a [Policy], run as
//     a [Selection] chooses, and report [Diagnostic] values with exact byte
//     spans. [CheckIDs] lists them, and a [SIDIndex] shared across files
//     finds duplicate sids in a whole rule set.
//   - [Fix] applies the autofixes that some diagnostics carry as text
//     edits and touches nothing else. Lint the result again to converge.
//
// The module is tested against a corpus of real rule files: every file
// parses with no diagnostics into a tree whose text is the file byte for
// byte, and fixing a file keeps every rule with its msg and sid. Those
// tests run when IDSRULE_CORPUS names a directory of *.rule files, are
// skipped when it is unset, and fail when it names anything else;
// README.md has the details.
//
// This package is a facade: it re-exports what most callers need from the
// smaller packages of the module, which are source (spans, positions, text
// edits), diag (diagnostics), dialect (the keyword tables), value (option
// value decoders), check (the checks, the policy and the selection), cst
// (the tree), token (the token kinds), lexer, parser and fix.
//
// The examples show a lint through an adapter to another tool's finding
// type, a fix pass, sid duplicates across files, the parse tree and
// dialect detection from file names.
//
// The API may change before v1; CHANGELOG.md lists the releases.
package idsrule
