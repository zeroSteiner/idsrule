//go:build !race

package cst_test

// raceEnabled reports whether the race detector is on. It makes
// allocation-heavy code several times slower, so time budgets in tests are
// scaled by raceSlowdown when it is.
const raceEnabled = false
