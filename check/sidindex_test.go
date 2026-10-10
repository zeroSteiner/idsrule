package check_test

import (
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/zeroSteiner/idsrule/check"
)

func TestSIDIndexAddLookup(t *testing.T) {
	x := check.NewSIDIndex()
	if got := x.Lookup(1); got != nil {
		t.Errorf("Lookup on empty index = %v, want nil", got)
	}
	if got := x.Len(); got != 0 {
		t.Errorf("Len() on empty index = %d, want 0", got)
	}

	a := check.SIDRef{File: "a.rule", Line: 1, Column: 1}
	b := check.SIDRef{File: "b.rule", Line: 7, Column: 3}
	x.Add(1, a)
	x.Add(1, b)
	x.Add(2, a)

	if got, want := x.Lookup(1), []check.SIDRef{a, b}; !slices.Equal(got, want) {
		t.Errorf("Lookup(1) = %v, want %v", got, want)
	}
	if got, want := x.Lookup(2), []check.SIDRef{a}; !slices.Equal(got, want) {
		t.Errorf("Lookup(2) = %v, want %v", got, want)
	}
	if got := x.Lookup(3); got != nil {
		t.Errorf("Lookup(3) = %v, want nil", got)
	}
	if got := x.Len(); got != 2 {
		t.Errorf("Len() = %d, want 2", got)
	}
}

func TestSIDIndexLookupReturnsCopy(t *testing.T) {
	x := check.NewSIDIndex()
	orig := check.SIDRef{File: "a.rule", Line: 1, Column: 1}
	x.Add(1, orig)

	got := x.Lookup(1)
	got[0].File = "mutated.rule"
	got = append(got, check.SIDRef{File: "extra.rule"})
	_ = got

	if again := x.Lookup(1); !slices.Equal(again, []check.SIDRef{orig}) {
		t.Errorf("mutating Lookup's result changed the index: %v", again)
	}
	if got := x.Lookup(1); &got[0] == &x.Lookup(1)[0] {
		t.Error("Lookup returned the same backing array twice")
	}
}

func TestSIDIndexForget(t *testing.T) {
	x := check.NewSIDIndex()
	a1 := check.SIDRef{File: "a.rule", Line: 1}
	a2 := check.SIDRef{File: "a.rule", Line: 9}
	b := check.SIDRef{File: "b.rule", Line: 2}
	x.Add(1, a1)
	x.Add(1, b)
	x.Add(1, a2)
	x.Add(2, a1)
	x.Add(3, b)

	x.Forget("missing.rule")
	if got := x.Len(); got != 3 {
		t.Fatalf("Len() after forgetting an unknown file = %d, want 3", got)
	}

	x.Forget("a.rule")
	if got, want := x.Lookup(1), []check.SIDRef{b}; !slices.Equal(got, want) {
		t.Errorf("Lookup(1) after Forget = %v, want %v", got, want)
	}
	if got := x.Lookup(2); got != nil {
		t.Errorf("Lookup(2) after Forget = %v, want nil (sid dropped)", got)
	}
	if got, want := x.Lookup(3), []check.SIDRef{b}; !slices.Equal(got, want) {
		t.Errorf("Lookup(3) after Forget = %v, want %v", got, want)
	}
	if got := x.Len(); got != 2 {
		t.Errorf("Len() after Forget = %d, want 2", got)
	}

	x.Forget("b.rule")
	if got := x.Len(); got != 0 {
		t.Errorf("Len() after forgetting every file = %d, want 0", got)
	}
}

func TestSIDIndexZeroValue(t *testing.T) {
	var x check.SIDIndex
	if got := x.Lookup(1); got != nil {
		t.Errorf("zero Lookup = %v, want nil", got)
	}
	if got := x.Len(); got != 0 {
		t.Errorf("zero Len() = %d, want 0", got)
	}
	x.Forget("a.rule")

	ref := check.SIDRef{File: "a.rule", Line: 1, Column: 1}
	x.Add(5, ref)
	if got, want := x.Lookup(5), []check.SIDRef{ref}; !slices.Equal(got, want) {
		t.Errorf("Lookup(5) = %v, want %v", got, want)
	}
	if got := x.Len(); got != 1 {
		t.Errorf("Len() = %d, want 1", got)
	}
}

func TestSIDIndexConcurrent(t *testing.T) {
	const (
		goroutines = 50
		iterations = 200
		sid        = 42
	)
	x := check.NewSIDIndex()
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			file := fmt.Sprintf("file-%d.rule", g)
			for i := range iterations {
				x.Add(sid, check.SIDRef{File: file, Line: i + 1, Column: 1})
				for _, ref := range x.Lookup(sid) {
					if ref.Line < 1 {
						t.Errorf("Lookup returned a bogus ref %+v", ref)
					}
				}
				x.Forget(file)
				x.Len()
			}
		}()
	}
	wg.Wait()

	if got := x.Len(); got != 0 {
		t.Errorf("Len() after every goroutine forgot its file = %d, want 0", got)
	}
	if got := x.Lookup(sid); got != nil {
		t.Errorf("Lookup(%d) after every goroutine forgot its file = %v, want nil", sid, got)
	}
}
