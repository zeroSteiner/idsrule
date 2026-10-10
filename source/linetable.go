package source

import (
	"bytes"
	"fmt"
	"sort"
)

// Position is a 1-based line and column in a source document.
//
// Column counts bytes, not runes: the column of a byte is one more than the
// number of bytes between it and the start of its line.
type Position struct {
	Line, Column int
}

// LineTable maps byte offsets in a source document to line/column positions.
//
// Build one with NewLineTable; it costs O(n) once and then answers Position
// queries in O(log lines). The zero value (and a nil *LineTable) describes an
// empty document.
type LineTable struct {
	starts []int // starts[i] is the offset at which 1-based line i+1 begins
	size   int   // length of the source in bytes
}

var newline = []byte{'\n'}

// NewLineTable scans src once and records the offset following every '\n'.
func NewLineTable(src []byte) *LineTable {
	starts := make([]int, 1, bytes.Count(src, newline)+1)
	for i, c := range src {
		if c == '\n' {
			starts = append(starts, i+1)
		}
	}
	return &LineTable{starts: starts, size: len(src)}
}

// Position returns the line and column of the byte at offset off.
//
// off is clamped to [0, len(src)]; off == len(src) is valid and names the
// position just past the last byte. A '\r' that precedes a '\n' belongs to
// the line it ends and gets a column of its own, as does the '\n' itself.
// For an empty document every offset maps to {1, 1}.
func (t *LineTable) Position(off int) Position {
	if t == nil || len(t.starts) == 0 {
		return Position{Line: 1, Column: 1}
	}
	if off < 0 {
		off = 0
	}
	if off > t.size {
		off = t.size
	}
	// The line containing off is the last one whose start is <= off.
	line := sort.SearchInts(t.starts, off+1) - 1
	return Position{Line: line + 1, Column: off - t.starts[line] + 1}
}

// NumLines returns the number of lines in the document, defined as the
// number of '\n' bytes plus one. An empty document has one line and "a\n"
// has two: the second line is empty but still counts.
func (t *LineTable) NumLines() int {
	if t == nil || len(t.starts) == 0 {
		return 1
	}
	return len(t.starts)
}

// LineStart returns the byte offset at which the 1-based line begins.
// It panics if line is outside [1, NumLines()].
func (t *LineTable) LineStart(line int) int {
	if line < 1 || line > t.NumLines() {
		panic(fmt.Sprintf("source: line %d out of range [1, %d]", line, t.NumLines()))
	}
	if t == nil || len(t.starts) == 0 {
		return 0
	}
	return t.starts[line-1]
}
