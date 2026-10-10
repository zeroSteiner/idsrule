package check

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// idPattern is the shape of a check id: kebab-case, starting with a letter.
var idPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

// registry holds checks by id. The package-level one is filled by the
// init functions of this package; tests may build their own.
type registry struct {
	mu     sync.RWMutex
	checks map[string]Check
}

// newRegistry returns an empty registry.
func newRegistry() *registry {
	return &registry{checks: make(map[string]Check)}
}

// global is the registry the exported functions operate on.
var global = newRegistry()

// register validates c and adds it to r.
func (r *registry) register(c Check) error {
	var errs []error
	if !idPattern.MatchString(c.ID) {
		errs = append(errs, fmt.Errorf("invalid check id %q", c.ID))
	}
	if !c.Severity.Valid() {
		errs = append(errs, fmt.Errorf("check %q: invalid severity %q", c.ID, c.Severity))
	}
	if strings.TrimSpace(c.Doc) == "" {
		errs = append(errs, fmt.Errorf("check %q: empty Doc", c.ID))
	}
	if c.Run == nil {
		errs = append(errs, fmt.Errorf("check %q: nil Run", c.ID))
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.checks[c.ID]; dup {
		return fmt.Errorf("check %q is already registered", c.ID)
	}
	r.checks[c.ID] = c
	return nil
}

// all returns every check in r sorted by ID.
func (r *registry) all() []Check {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Check, 0, len(r.checks))
	for _, id := range slices.Sorted(maps.Keys(r.checks)) {
		out = append(out, r.checks[id])
	}
	return out
}

// lookup returns the check registered under id.
func (r *registry) lookup(id string) (Check, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.checks[id]
	return c, ok
}

// Register adds c to the set of checks [Run] knows. It is meant to be
// called from init functions and panics when c is invalid: an ID that is
// not kebab-case or is already registered, an undefined Severity, an
// empty Doc or a nil Run.
func Register(c Check) {
	if err := global.register(c); err != nil {
		panic("check: " + err.Error())
	}
}

// All returns every registered check sorted by ID. The slice and the
// checks in it are copies; modifying them does not affect the registry.
func All() []Check { return global.all() }

// Lookup returns the check registered under id.
func Lookup(id string) (Check, bool) { return global.lookup(id) }

// Known reports whether a check is registered under id. It has the
// signature [Selection.Validate] expects.
func Known(id string) bool {
	_, ok := global.lookup(id)
	return ok
}

// IDs returns the ids of every registered check, sorted.
func IDs() []string {
	checks := global.all()
	ids := make([]string, len(checks))
	for i, c := range checks {
		ids[i] = c.ID
	}
	return ids
}
