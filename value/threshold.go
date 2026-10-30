package value

import "fmt"

// Threshold is a decoded threshold or detection_filter value.
type Threshold struct {
	// Type is limit, threshold or both; empty for a detection_filter.
	Type string
	// Track is by_src, by_dst, by_rule, by_both or by_flow.
	Track string
	// Count is the number of matches.
	Count int64
	// Seconds is the length of the window; zero for type backoff.
	Seconds int64
	// Multiplier is the factor by which a backoff threshold grows; zero
	// for the other types.
	Multiplier int64
	// HasType reports whether a type was given.
	HasType bool
	// HasMultiplier reports whether a multiplier was given, which
	// Suricata 8 reads with any type.
	HasMultiplier bool
}

// thresholdTypes are the values of the type key, Suricata 8's backoff
// included.
var thresholdTypes = map[string]bool{"limit": true, "threshold": true, "both": true, "backoff": true}

// thresholdTracks are the values of the track key, Suricata's included.
var thresholdTracks = map[string]bool{"by_src": true, "by_dst": true, "by_rule": true, "by_both": true, "by_flow": true}

// ParseThreshold decodes a threshold or detection_filter value: the items
// "type limit|threshold|both|backoff",
// "track by_src|by_dst|by_rule|by_both|by_flow", "count N", "seconds N"
// and "multiplier N", comma-separated, in any order, each at most once.
// type is optional, as detection_filter has none; track and count are
// required. Suricata 8's type backoff takes multiplier, from 2 to 65535,
// instead of seconds, a count from 1 to 65535 and only track by_flow;
// every other value takes seconds, and multiplier only with a type.
func ParseThreshold(s string) (Threshold, error) {
	var t Threshold
	seen := make(map[string]bool)
	for _, p := range splitComma(s) {
		p = trim(p)
		if p.text == "" {
			return Threshold{}, errAt(p.off, "empty threshold item")
		}
		key, val := keyValue(p)
		if seen[key.text] {
			return Threshold{}, errAt(key.off, fmt.Sprintf("duplicate %q", key.text))
		}
		seen[key.text] = true
		switch key.text {
		case "type":
			if !thresholdTypes[val.text] {
				return Threshold{}, errAt(val.off, fmt.Sprintf("unknown threshold type %q", val.text))
			}
			t.Type, t.HasType = val.text, true
		case "track":
			if !thresholdTracks[val.text] {
				return Threshold{}, errAt(val.off, fmt.Sprintf("unknown track %q", val.text))
			}
			t.Track = val.text
		case "count", "seconds", "multiplier":
			n, err := parseDigits(val)
			if err != nil {
				return Threshold{}, err
			}
			switch key.text {
			case "count":
				t.Count = n
			case "seconds":
				t.Seconds = n
			default:
				t.Multiplier, t.HasMultiplier = n, true
			}
		default:
			return Threshold{}, errAt(key.off, fmt.Sprintf("unknown threshold key %q", key.text))
		}
	}
	required := []string{"track", "count", "seconds"}
	if t.Type == "backoff" {
		required = []string{"track", "count", "multiplier"}
	}
	for _, key := range required {
		if !seen[key] {
			return Threshold{}, errAt(len(s), "missing "+key)
		}
	}
	switch {
	case t.Type == "backoff" && seen["seconds"]:
		return Threshold{}, errAt(0, "type backoff takes multiplier, not seconds")
	case t.Type == "backoff" && t.Track != "by_flow":
		return Threshold{}, errAt(0, "type backoff takes only track by_flow")
	case t.Type == "backoff" && (t.Count < 1 || t.Count > 65535):
		return Threshold{}, errAt(0, "type backoff takes a count from 1 to 65535")
	case t.Type == "backoff" && (t.Multiplier < 2 || t.Multiplier > 65535):
		return Threshold{}, errAt(0, "type backoff takes a multiplier from 2 to 65535")
	case seen["multiplier"] && !t.HasType:
		return Threshold{}, errAt(0, "multiplier needs a type")
	}
	return t, nil
}
