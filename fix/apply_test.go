package fix_test

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/zeroSteiner/idsrule/fix"
	"github.com/zeroSteiner/idsrule/source"
)

// edit builds a TextEdit.
func edit(start, end int, text string) source.TextEdit {
	return source.TextEdit{Span: source.Span{Start: start, End: end}, NewText: text}
}

func TestApply(t *testing.T) {
	tests := []struct {
		name  string
		src   string
		edits []source.TextEdit
		want  string
		err   error
	}{
		{"no edits", "hello", nil, "hello", nil},
		{"insert", "hello", []source.TextEdit{edit(2, 2, "XX")}, "heXXllo", nil},
		{"delete", "hello", []source.TextEdit{edit(1, 3, "")}, "hlo", nil},
		{"replace", "hello", []source.TextEdit{edit(1, 4, "ipp")}, "hippo", nil},
		{"replace all", "hello", []source.TextEdit{edit(0, 5, "bye")}, "bye", nil},
		{"insert at start", "abc", []source.TextEdit{edit(0, 0, ">")}, ">abc", nil},
		{"insert at end", "abc", []source.TextEdit{edit(3, 3, "\n")}, "abc\n", nil},
		{"adjacent", "abcdef", []source.TextEdit{edit(0, 2, "X"), edit(2, 4, "Y")}, "XYef", nil},
		{"insertion before a replacement at the same offset", "abcdef", []source.TextEdit{edit(2, 4, "R"), edit(2, 2, "I")}, "abIRef", nil},
		{"insertion after a deletion ending at the same offset", "abcdef", []source.TextEdit{edit(2, 2, "I"), edit(0, 2, "")}, "Icdef", nil},
		{"two insertions at one offset keep their order", "ab", []source.TextEdit{edit(1, 1, "X"), edit(1, 1, "Y")}, "aXYb", nil},
		{"out of order", "abcdef", []source.TextEdit{edit(4, 5, "E"), edit(0, 1, "A"), edit(2, 3, "C")}, "AbCdEf", nil},
		{"empty source", "", []source.TextEdit{edit(0, 0, "x")}, "x", nil},
		{"overlap", "abcdef", []source.TextEdit{edit(0, 3, "X"), edit(2, 4, "Y")}, "", fix.ErrOverlap},
		{"same span twice", "abcdef", []source.TextEdit{edit(1, 3, "X"), edit(1, 3, "Y")}, "", fix.ErrOverlap},
		{"nested", "abcdef", []source.TextEdit{edit(0, 6, "X"), edit(2, 3, "Y")}, "", fix.ErrOverlap},
		{"insertion inside a replacement", "abcdef", []source.TextEdit{edit(1, 4, "X"), edit(2, 2, "Y")}, "", fix.ErrOverlap},
		{"end before start", "abcdef", []source.TextEdit{edit(3, 1, "")}, "", fix.ErrBounds},
		{"end one past the document", "abcdef", []source.TextEdit{edit(6, 7, "")}, "", fix.ErrBounds},
		{"insertion past the document", "abcdef", []source.TextEdit{edit(7, 7, "")}, "", fix.ErrBounds},
		{"negative start", "abcdef", []source.TextEdit{edit(-1, 0, "")}, "", fix.ErrBounds},
		{"bounds are checked before overlap", "abcdef", []source.TextEdit{edit(0, 3, ""), edit(2, 9, "")}, "", fix.ErrBounds},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := []byte(tt.src)
			given := slices.Clone(tt.edits)
			if err := fix.Validate(src, tt.edits); !errors.Is(err, tt.err) {
				t.Errorf("Validate() = %v, want %v", err, tt.err)
			}
			got, err := fix.Apply(src, tt.edits)
			if !errors.Is(err, tt.err) {
				t.Fatalf("Apply() error = %v, want %v", err, tt.err)
			}
			if tt.err != nil {
				if got != nil {
					t.Errorf("Apply() = %q with an error, want nil", got)
				}
				return
			}
			if string(got) != tt.want {
				t.Errorf("Apply() = %q, want %q", got, tt.want)
			}
			if string(src) != tt.src {
				t.Errorf("Apply() modified src: %q", src)
			}
			if !slices.Equal(tt.edits, given) {
				t.Errorf("Apply() reordered the edits in place: %v", tt.edits)
			}
		})
	}
}

func TestApply_NoEditsCopies(t *testing.T) {
	src := []byte("hello")
	got, err := fix.Apply(src, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, src) {
		t.Fatalf("Apply() = %q, want %q", got, src)
	}
	if &got[0] == &src[0] {
		t.Error("Apply() returned a slice aliasing src")
	}
	got[0] = 'j'
	if string(src) != "hello" {
		t.Errorf("writing to the result changed src: %q", src)
	}
}

func TestApply_ErrorsNameTheEdit(t *testing.T) {
	err := fix.Validate([]byte("abc"), []source.TextEdit{edit(1, 9, "")})
	if err == nil || !strings.Contains(err.Error(), "[1,9)") {
		t.Errorf("Validate() = %v, want an error naming [1,9)", err)
	}
	err = fix.Validate([]byte("abc"), []source.TextEdit{edit(0, 2, ""), edit(1, 3, "")})
	if err == nil || !strings.Contains(err.Error(), "[0,2) and [1,3)") {
		t.Errorf("Validate() = %v, want an error naming [0,2) and [1,3)", err)
	}
}

// TestApply_Random applies ten thousand random disjoint edits, given in a
// random order, and compares the result with applying them one at a time
// from the back of the document.
func TestApply_Random(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	src := make([]byte, 60_000)
	for i := range src {
		src[i] = byte('a' + rng.IntN(26))
	}
	const n = 10_000
	edits := make([]source.TextEdit, 0, n)
	pos := 0
	for len(edits) < n {
		pos += 1 + rng.IntN(4) // at least one untouched byte between edits
		size := rng.IntN(3)
		if pos+size > len(src) {
			t.Fatalf("source too short: %d edits placed", len(edits))
		}
		text := strings.Repeat(string(rune('A'+rng.IntN(26))), rng.IntN(4))
		edits = append(edits, edit(pos, pos+size, text))
		pos += size
	}

	want := slices.Clone(src)
	for i := len(edits) - 1; i >= 0; i-- {
		e := edits[i]
		want = slices.Concat(want[:e.Span.Start], []byte(e.NewText), want[e.Span.End:])
	}

	rng.Shuffle(len(edits), func(i, j int) { edits[i], edits[j] = edits[j], edits[i] })
	got, err := fix.Apply(src, edits)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Apply() differs from the reference (lengths %d and %d)", len(got), len(want))
	}
}
