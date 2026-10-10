package source

import (
	"testing"
)

func TestSpan(t *testing.T) {
	tests := []struct {
		name  string
		span  Span
		len   int
		empty bool
	}{
		{"zero", Span{}, 0, true},
		{"point", Span{Start: 3, End: 3}, 0, true},
		{"one byte", Span{Start: 3, End: 4}, 1, false},
		{"range", Span{Start: 10, End: 25}, 15, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.span.Len(); got != tt.len {
				t.Errorf("Len() = %d, want %d", got, tt.len)
			}
			if got := tt.span.Empty(); got != tt.empty {
				t.Errorf("Empty() = %v, want %v", got, tt.empty)
			}
		})
	}
}

func TestTextEditZeroValue(t *testing.T) {
	var e TextEdit
	if !e.Span.Empty() {
		t.Errorf("zero TextEdit span %+v is not empty", e.Span)
	}
	if e.NewText != "" {
		t.Errorf("zero TextEdit NewText = %q, want empty", e.NewText)
	}
}

func TestLineTablePosition(t *testing.T) {
	tests := []struct {
		name string
		src  string
		off  int
		want Position
	}{
		{"empty/0", "", 0, Position{1, 1}},
		{"empty/negative", "", -5, Position{1, 1}},
		{"empty/past end", "", 10, Position{1, 1}},
		{"no newline/first", "a", 0, Position{1, 1}},
		{"no newline/end", "a", 1, Position{1, 2}},
		{"lf/first", "a\nb", 0, Position{1, 1}},
		{"lf/newline byte", "a\nb", 1, Position{1, 2}},
		{"lf/second line", "a\nb", 2, Position{2, 1}},
		{"lf/end", "a\nb", 3, Position{2, 2}},
		{"crlf/cr", "a\r\nb", 1, Position{1, 2}},
		{"crlf/lf", "a\r\nb", 2, Position{1, 3}},
		{"crlf/second line", "a\r\nb", 3, Position{2, 1}},
		{"trailing newline/end", "a\n", 2, Position{2, 1}},
		{"blank lines/third newline", "a\n\n\nb", 3, Position{3, 1}},
		{"blank lines/after", "a\n\n\nb", 4, Position{4, 1}},
		{"clamp/negative", "a\nb", -5, Position{1, 1}},
		{"clamp/past end", "a\nb", 13, Position{2, 2}},
		{"multibyte column is bytes", "é\nb", 2, Position{1, 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lt := NewLineTable([]byte(tt.src))
			if got := lt.Position(tt.off); got != tt.want {
				t.Errorf("NewLineTable(%q).Position(%d) = %+v, want %+v", tt.src, tt.off, got, tt.want)
			}
		})
	}
}

func TestLineTableNumLines(t *testing.T) {
	tests := []struct {
		src  string
		want int
	}{
		{"", 1},
		{"a", 1},
		{"a\n", 2},
		{"a\nb", 2},
		{"a\r\nb", 2},
		{"a\n\n", 3},
		{"\n", 2},
	}
	for _, tt := range tests {
		t.Run(tt.src, func(t *testing.T) {
			if got := NewLineTable([]byte(tt.src)).NumLines(); got != tt.want {
				t.Errorf("NewLineTable(%q).NumLines() = %d, want %d", tt.src, got, tt.want)
			}
		})
	}
}

func TestLineTableLineStart(t *testing.T) {
	lt := NewLineTable([]byte("ab\ncde\n\nf"))
	want := []int{0, 3, 7, 8}
	if n := lt.NumLines(); n != len(want) {
		t.Fatalf("NumLines() = %d, want %d", n, len(want))
	}
	for i, off := range want {
		if got := lt.LineStart(i + 1); got != off {
			t.Errorf("LineStart(%d) = %d, want %d", i+1, got, off)
		}
	}
	for _, line := range []int{-1, 0, 5, 100} {
		assertPanics(t, func() { lt.LineStart(line) })
	}
}

func TestLineTableZeroValue(t *testing.T) {
	var tables = map[string]*LineTable{
		"zero": {},
		"nil":  nil,
	}
	for name, lt := range tables {
		t.Run(name, func(t *testing.T) {
			if got := lt.Position(3); got != (Position{1, 1}) {
				t.Errorf("Position(3) = %+v, want {1 1}", got)
			}
			if got := lt.NumLines(); got != 1 {
				t.Errorf("NumLines() = %d, want 1", got)
			}
			if got := lt.LineStart(1); got != 0 {
				t.Errorf("LineStart(1) = %d, want 0", got)
			}
			assertPanics(t, func() { lt.LineStart(2) })
		})
	}
}

func assertPanics(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Error("expected a panic")
		}
	}()
	f()
}
