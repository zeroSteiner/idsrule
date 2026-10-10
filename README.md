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
