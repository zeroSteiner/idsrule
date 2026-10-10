package check

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/zeroSteiner/idsrule/diag"
)

// Selection chooses which checks run and how their findings are reported.
// Check ids are kebab-case strings such as "sid-duplicate".
type Selection struct {
	// Enable lists checks to run in addition to the defaults.
	Enable []string
	// Disable lists checks that must not run.
	Disable []string
	// Style turns on the cosmetic checks, which are off by default.
	Style bool
	// Severity overrides the severity individual checks report with.
	Severity map[string]diag.Severity
}

// Validate reports every inconsistency in s. It fails when an id is both
// enabled and disabled, when a Severity override is not a valid severity,
// and, if known is non-nil, when any id in Enable, Disable or Severity is
// one known does not recognize. A nil known skips that last test.
func (s Selection) Validate(known func(id string) bool) error {
	var errs []error

	disabled := make(map[string]bool, len(s.Disable))
	for _, id := range s.Disable {
		disabled[id] = true
	}
	for _, id := range s.Enable {
		if disabled[id] {
			errs = append(errs, fmt.Errorf("check %q is both enabled and disabled", id))
		}
	}

	severityIDs := slices.Sorted(maps.Keys(s.Severity))
	for _, id := range severityIDs {
		if sev := s.Severity[id]; !sev.Valid() {
			errs = append(errs, fmt.Errorf("invalid severity %q for check %q", sev, id))
		}
	}

	if known != nil {
		reported := make(map[string]bool)
		for _, ids := range [][]string{s.Enable, s.Disable, severityIDs} {
			for _, id := range ids {
				if reported[id] || known(id) {
					continue
				}
				reported[id] = true
				errs = append(errs, fmt.Errorf("unknown check id %q", id))
			}
		}
	}

	return errors.Join(errs...)
}
