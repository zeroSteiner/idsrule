package check

import (
	"slices"
	"sync"
)

// SIDRef records where a sid was declared.
type SIDRef struct {
	File         string
	Line, Column int
}

// SIDIndex maps sids to every place they are declared, across files, so the
// duplicate-sid check can work on a whole rule set. The zero value is ready
// to use and every method is safe for concurrent use.
type SIDIndex struct {
	mu   sync.Mutex
	refs map[uint64][]SIDRef
}

// NewSIDIndex returns an empty index.
func NewSIDIndex() *SIDIndex {
	return &SIDIndex{refs: make(map[uint64][]SIDRef)}
}

// Add records that sid is declared at ref.
func (x *SIDIndex) Add(sid uint64, ref SIDRef) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.refs == nil {
		x.refs = make(map[uint64][]SIDRef)
	}
	x.refs[sid] = append(x.refs[sid], ref)
}

// Lookup returns a copy of the references recorded for sid, in insertion
// order, or nil if the sid is absent. Mutating the result does not affect
// the index.
func (x *SIDIndex) Lookup(sid uint64) []SIDRef {
	x.mu.Lock()
	defer x.mu.Unlock()
	refs := x.refs[sid]
	if refs == nil {
		return nil
	}
	return slices.Clone(refs)
}

// Forget removes every reference recorded for file. A sid left with no
// references is dropped from the index.
func (x *SIDIndex) Forget(file string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	for sid, refs := range x.refs {
		kept := slices.DeleteFunc(refs, func(r SIDRef) bool { return r.File == file })
		if len(kept) == 0 {
			delete(x.refs, sid)
			continue
		}
		x.refs[sid] = kept
	}
}

// Len returns the number of distinct sids in the index.
func (x *SIDIndex) Len() int {
	x.mu.Lock()
	defer x.mu.Unlock()
	return len(x.refs)
}
