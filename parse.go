package idsrule

import (
	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/parser"
)

// File is an alias for [cst.File], the lossless syntax tree of a rule file.
type File = cst.File

// Parse parses src as a rules file named file. It never returns a nil
// *File: whatever the input, the tree reproduces src byte for byte and the
// errors in it are reported as diagnostics, with the syntax-* rule ids of
// [parser] and the lexer and with File, Line, Column and End resolved.
// Parsing is dialect-agnostic.
//
// The tree references src directly rather than copying it, so the caller
// must not modify src after parsing.
func Parse(file string, src []byte) (*File, []Diagnostic) {
	f, diags := parser.Parse(src)
	f.Path = file
	b := diag.Builder{File: file, Lines: f.Lines()}
	for i := range diags {
		b.Resolve(&diags[i])
	}
	diag.Sort(diags)
	return f, diags
}
