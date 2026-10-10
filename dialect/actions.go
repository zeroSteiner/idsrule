package dialect

import "slices"

// snort2Actions are the rule actions of Snort 2.9, in the manual's order.
var snort2Actions = []string{"alert", "log", "pass", "activate", "dynamic", "drop", "reject", "sdrop"}

// suricataActions are the rule actions of Suricata, in the manual's order.
var suricataActions = []string{"alert", "pass", "drop", "reject", "rejectsrc", "rejectdst", "rejectboth"}

// Actions returns the rule actions of d in the order the dialect's manual
// lists them, or the sorted union of every dialect's actions for Unknown
// and for a dialect outside the defined range. The slice is the caller's.
func (d Dialect) Actions() []string {
	switch d {
	case Snort2:
		return slices.Clone(snort2Actions)
	case Suricata:
		return slices.Clone(suricataActions)
	case Unknown:
	}
	return union(snort2Actions, suricataActions)
}

// IsAction reports whether s is a rule action of d; for Unknown or an
// undefined dialect, of any dialect.
func (d Dialect) IsAction(s string) bool {
	return slices.Contains(d.Actions(), s)
}

// union returns the sorted set of the strings of every list.
func union(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}
