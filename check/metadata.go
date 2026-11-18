package check

import (
	"strings"

	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/dialect"
	"github.com/zeroSteiner/idsrule/source"
)

func init() {
	Register(Check{
		ID:           "metadata-entry-dropped",
		Severity:     diag.SeverityWarning,
		NeedsDialect: true,
		Doc:          "a Suricata metadata entry is empty or has no value after a space (a lone key such as \"variant\", or a key and value separated by a tab), which Suricata drops without a word, so it never reaches the alert's metadata",
		Run:          checkMetadataEntryDropped,
	})
}

// droppedEntry is a metadata entry Suricata skips: off and n are its
// offset and length in the option's logical value, text its trimmed text.
type droppedEntry struct {
	off, n int
	text   string
}

// droppedMetadataEntries returns the entries of the metadata value s that
// Suricata's DetectMetadataParse skips. It splits s at every ',' and drops
// an entry that is empty, as strtok_r does, or, once the blanks before it
// are skipped, has no ' ' or nothing but blanks after its first ' ': the
// key ends at the first space, never at a tab.
func droppedMetadataEntries(s string) []droppedEntry {
	var out []droppedEntry
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != ',' {
			continue
		}
		entry := s[start:i]
		lead := len(entry) - len(strings.TrimLeft(entry, " \t"))
		text := strings.TrimRight(entry[lead:], " \t")
		_, val, found := strings.Cut(entry[lead:], " ")
		if !found || strings.TrimLeft(val, " \t") == "" {
			out = append(out, droppedEntry{off: start + lead, n: len(text), text: text})
		}
		start = i + 1
	}
	return out
}

func checkMetadataEntryDropped(ctx *Context) {
	if ctx.Dialect != dialect.Suricata {
		return
	}
	for _, r := range ctx.Tree.Rules() {
		for _, o := range r.OptionsNamed("metadata") {
			logical, at := o.LogicalValue()
			if logical == "" {
				continue // syntax-missing-value reports it
			}
			for _, e := range droppedMetadataEntries(logical) {
				span := entrySpan(o, at, e)
				switch {
				case e.text == "":
					ctx.Report(span, "empty metadata entry; Suricata drops it")
				case strings.ContainsRune(e.text, '\t'):
					ctx.Report(span, "metadata entry %q separates its key and value with a tab; Suricata splits them only at a space, so it drops the entry", e.text)
				default:
					ctx.Report(span, "metadata entry %q has no value; Suricata drops it (an entry is a key, a space and a value)", e.text)
				}
			}
		}
	}
}

// entrySpan is the source span of entry e of o's logical value, mapped
// with at; an empty entry gets the one-byte span of the ',' or the end of
// the value that follows it.
func entrySpan(o *cst.Option, at func(int) int, e droppedEntry) source.Span {
	start := at(e.off)
	if e.n == 0 {
		return source.Span{Start: start, End: min(start+1, o.ValueSpan().End)}
	}
	return source.Span{Start: start, End: at(e.off+e.n-1) + 1}
}
