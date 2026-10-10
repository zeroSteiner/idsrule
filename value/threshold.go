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
	// Seconds is the length of the window.
	Seconds int64
	// HasType reports whether a type was given.
	HasType bool
}

// thresholdTypes are the values of the type key.
var thresholdTypes = map[string]bool{"limit": true, "threshold": true, "both": true}

// thresholdTracks are the values of the track key, Suricata's included.
var thresholdTracks = map[string]bool{"by_src": true, "by_dst": true, "by_rule": true, "by_both": true, "by_flow": true}

// ParseThreshold decodes a threshold or detection_filter value: the items
// "type limit|threshold|both", "track by_src|by_dst|by_rule|by_both|by_flow",
// "count N" and "seconds N", comma-separated, in any order, each at most
// once. type is optional, as detection_filter has none; the others are
// required.
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
		case "count", "seconds":
			n, err := parseDigits(val)
			if err != nil {
				return Threshold{}, err
			}
			if key.text == "count" {
				t.Count = n
			} else {
				t.Seconds = n
			}
		default:
			return Threshold{}, errAt(key.off, fmt.Sprintf("unknown threshold key %q", key.text))
		}
	}
	for _, key := range []string{"track", "count", "seconds"} {
		if !seen[key] {
			return Threshold{}, errAt(len(s), "missing "+key)
		}
	}
	return t, nil
}
