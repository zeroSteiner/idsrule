//go:build race

package parser

// raceEnabled reports whether the race detector is on. It makes
// allocation-heavy code several times slower, so time budgets in tests are
// scaled by raceSlowdown when it is.
const raceEnabled = true
