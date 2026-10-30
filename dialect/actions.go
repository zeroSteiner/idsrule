package dialect

import (
	"slices"
	"strings"
)

// snort2Actions are the rule actions of Snort 2.9, in the manual's order.
var snort2Actions = []string{"alert", "log", "pass", "activate", "dynamic", "drop", "reject", "sdrop"}

// suricataActions are the rule actions of Suricata, in the manual's order.
// accept, Suricata 8's, is valid only in firewall rules.
var suricataActions = []string{"alert", "pass", "drop", "reject", "rejectsrc", "rejectdst", "rejectboth", "config", "accept"}

// suricataActionsAdded are the Suricata actions that not every release the
// tables describe has, with the release that added them.
var suricataActionsAdded = map[string]Version{"accept": Suricata8}

// ActionAdded returns the release of d that added the action name, or
// AnyVersion when every release the tables describe has it or it is not
// one of d's actions. The name is compared without regard to case.
func (d Dialect) ActionAdded(name string) Version {
	if d != Suricata {
		return AnyVersion
	}
	return suricataActionsAdded[strings.ToLower(name)]
}

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
// undefined dialect, of any dialect. The comparison ignores case, as both
// engines do.
func (d Dialect) IsAction(s string) bool {
	return containsFold(d.Actions(), s)
}

// containsFold reports whether list holds s, compared without regard to
// case.
func containsFold(list []string, s string) bool {
	return slices.ContainsFunc(list, func(item string) bool { return strings.EqualFold(item, s) })
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
