// Package idsrule is a lossless parser for Suricata and Snort 2.9 rule files
// with rule-aware checks built on top of it.
//
// Lossless means a parsed file keeps every byte of its source, comments,
// whitespace and line continuations included, so it can be written back
// unchanged and so that checks can report exact byte spans and offer edits
// that touch nothing else.
//
// This root package is a facade: it re-exports the types from the smaller
// packages that make up the module so that most callers need only one
// import.
//
//   - [github.com/zeroSteiner/idsrule/source] holds byte spans, positions,
//     text edits and the line table that maps between them.
//   - [github.com/zeroSteiner/idsrule/diag] defines diagnostics.
//   - [github.com/zeroSteiner/idsrule/dialect] names the rule languages and
//     detects them from filenames.
//   - [github.com/zeroSteiner/idsrule/check] holds the policy, the check
//     selection and the cross-file SID index.
//
// # Corpus tests
//
// Some tests run against an external corpus of real rule files. Set the
// IDSRULE_CORPUS environment variable to a directory of *.rule files to
// enable them; they are skipped when it is unset:
//
//	IDSRULE_CORPUS=/path/to/rules go test ./...
//
// The module is pre-alpha and its API is not yet stable.
package idsrule
