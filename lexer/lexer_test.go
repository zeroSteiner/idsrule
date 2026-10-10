package lexer_test

import (
	"bytes"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/lexer"
	"github.com/zeroSteiner/idsrule/source"
	"github.com/zeroSteiner/idsrule/token"
)

// tk is an expected token: its kind and exact text. Offsets follow from the
// texts, so the tests derive them rather than spelling them out.
type tk struct {
	kind token.Kind
	lit  string
}

// lexTest is one hazard: an input, the exact tokens it must lex to, and the
// spans of the unterminated-string diagnostics it must produce.
type lexTest struct {
	name  string
	src   string
	want  []tk
	diags []source.Span
}

// seq concatenates token sequences, so that the common rule header need not
// be spelled out in every case.
func seq(parts ...[]tk) []tk {
	var out []tk
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

var (
	ws    = tk{token.Whitespace, " "}
	nl    = tk{token.Newline, "\n"}
	eof   = tk{token.EOF, ""}
	lp    = tk{token.LParen, "("}
	rp    = tk{token.RParen, ")"}
	colon = tk{token.Colon, ":"}
	semi  = tk{token.Semicolon, ";"}
	lc    = tk{token.LineContinuation, "\\\n"}
	sid1  = []tk{{token.Keyword, "sid"}, colon, {token.Value, "1"}, semi}

	// header is "alert tcp any any -> any any " up to the '('.
	header = []tk{
		{token.Word, "alert"}, ws, {token.Word, "tcp"}, ws, {token.Word, "any"}, ws,
		{token.Word, "any"}, ws, {token.Word, "->"}, ws, {token.Word, "any"}, ws,
		{token.Word, "any"}, ws,
	}
)

// lexTests are the hazards. Every one is also a fuzz seed.
var lexTests = []lexTest{
	{
		name: "empty",
		src:  "",
		want: []tk{eof},
	},
	{
		name: "only_newline",
		src:  "\n",
		want: []tk{nl, eof},
	},
	{
		name: "minimal_rule",
		src:  "alert tcp any any -> any any (sid:1;)\n",
		want: seq(header, []tk{lp}, sid1, []tk{rp, nl, eof}),
	},
	{
		name: "no_final_newline",
		src:  "alert tcp any any -> any any (sid:1;)",
		want: seq(header, []tk{lp}, sid1, []tk{rp, eof}),
	},
	{
		name: "crlf",
		src:  "alert tcp any any -> any any (sid:1;)\r\n",
		want: seq(header, []tk{lp}, sid1, []tk{rp, {token.Newline, "\r\n"}, eof}),
	},
	{
		name: "header_groups",
		src:  "alert tcp ![10.0.0.0/8,10.1.0.0/16] [80:90,!85,1024:] -> $HOME_NET any (sid:1;)\n",
		want: seq([]tk{
			{token.Word, "alert"}, ws, {token.Word, "tcp"}, ws,
			{token.Bang, "!"}, {token.LBracket, "["}, {token.Word, "10.0.0.0/8"}, {token.Comma, ","},
			{token.Word, "10.1.0.0/16"}, {token.RBracket, "]"}, ws,
			{token.LBracket, "["}, {token.Word, "80:90"}, {token.Comma, ","}, {token.Bang, "!"},
			{token.Word, "85"}, {token.Comma, ","}, {token.Word, "1024:"}, {token.RBracket, "]"}, ws,
			{token.Word, "->"}, ws, {token.Word, "$HOME_NET"}, ws, {token.Word, "any"}, ws, lp,
		}, sid1, []tk{rp, nl, eof}),
	},
	{
		name: "header_bidir",
		src:  "alert udp any any <> any 53 (sid:1;)\n",
		want: seq([]tk{
			{token.Word, "alert"}, ws, {token.Word, "udp"}, ws, {token.Word, "any"}, ws,
			{token.Word, "any"}, ws, {token.Word, "<>"}, ws, {token.Word, "any"}, ws,
			{token.Word, "53"}, ws, lp,
		}, sid1, []tk{rp, nl, eof}),
	},
	{
		name: "comment_line",
		src:  "# c\n",
		want: []tk{{token.Comment, "# c"}, nl, eof},
	},
	{
		name: "comment_line_indented",
		src:  "  # c\n",
		want: []tk{{token.Whitespace, "  "}, {token.Comment, "# c"}, nl, eof},
	},
	{
		name: "hash_not_at_line_start",
		src:  "alert tcp any any -> any any (sid:1;) # c\n",
		want: seq(header, []tk{lp}, sid1, []tk{rp, ws, {token.Word, "#"}, ws, {token.Word, "c"}, nl, eof}),
	},
	{
		name: "semicolon_in_string",
		src:  "(pcre:\"/a(?:\x5c;|%3b)/\"; sid:1;)",
		want: seq([]tk{lp, {token.Keyword, "pcre"}, colon, {token.Value, "\"/a(?:\x5c;|%3b)/\""}, semi, ws}, sid1, []tk{rp, eof}),
	},
	{
		name: "parens_in_string",
		src:  "(msg:\"x (y)\"; pcre:\"/(?:a)/\"; sid:1;)",
		want: seq([]tk{
			lp, {token.Keyword, "msg"}, colon, {token.Value, "\"x (y)\""}, semi, ws,
			{token.Keyword, "pcre"}, colon, {token.Value, "\"/(?:a)/\""}, semi, ws,
		}, sid1, []tk{rp, eof}),
	},
	{
		name: "escaped_quote",
		src:  "(content:\"name=\\\"meta\\\"\";)",
		want: []tk{lp, {token.Keyword, "content"}, colon, {token.Value, "\"name=\\\"meta\\\"\""}, semi, rp, eof},
	},
	{
		name: "escaped_backslash_then_quote",
		src:  "(content:\"a\\\\\";)",
		want: []tk{lp, {token.Keyword, "content"}, colon, {token.Value, "\"a\\\\\""}, semi, rp, eof},
	},
	{
		name: "hex_block",
		src:  "(content:\"|89|HDF|0d 0a 1a 0a|\";)",
		want: []tk{lp, {token.Keyword, "content"}, colon, {token.Value, "\"|89|HDF|0d 0a 1a 0a|\""}, semi, rp, eof},
	},
	{
		name: "content_negated",
		src:  "(content:!\"Cookie\"; nocase;)",
		want: []tk{
			lp, {token.Keyword, "content"}, colon, {token.Value, "!\"Cookie\""}, semi, ws,
			{token.Keyword, "nocase"}, semi, rp, eof,
		},
	},
	{
		name: "snort3_comma_modifier",
		src:  "(content:\"x\", nocase;)",
		want: []tk{lp, {token.Keyword, "content"}, colon, {token.Value, "\"x\", nocase"}, semi, rp, eof},
	},
	{
		name: "leading_ws_in_value",
		src:  "(metadata: deployment Datacenter, deployment SSLDecrypt;)",
		want: []tk{
			lp, {token.Keyword, "metadata"}, colon, ws,
			{token.Value, "deployment Datacenter, deployment SSLDecrypt"}, semi, rp, eof,
		},
	},
	{
		name: "trailing_ws_before_semicolon",
		src:  "(sid:1 ;)",
		want: []tk{lp, {token.Keyword, "sid"}, colon, {token.Value, "1"}, ws, semi, rp, eof},
	},
	{
		name: "empty_value",
		src:  "(msg:;)",
		want: []tk{lp, {token.Keyword, "msg"}, colon, semi, rp, eof},
	},
	{
		name: "continuation_in_body",
		src:  "alert tcp any any -> any any ( \\\n    msg:\"x\"; \\\n    sid:1; \\\n)\n",
		want: seq(header, []tk{
			lp, ws, lc, {token.Whitespace, "    "},
			{token.Keyword, "msg"}, colon, {token.Value, "\"x\""}, semi, ws,
			lc, {token.Whitespace, "    "},
		}, sid1, []tk{ws, lc, rp, nl, eof}),
	},
	{
		name: "continuation_no_space_before",
		src:  "(distance:0;\\\n  within:4;)",
		want: []tk{
			lp, {token.Keyword, "distance"}, colon, {token.Value, "0"}, semi,
			lc, {token.Whitespace, "  "},
			{token.Keyword, "within"}, colon, {token.Value, "4"}, semi, rp, eof,
		},
	},
	{
		name: "continuation_in_header",
		src:  "alert tcp any any -> \\\n  any any (sid:1;)\n",
		want: seq([]tk{
			{token.Word, "alert"}, ws, {token.Word, "tcp"}, ws, {token.Word, "any"}, ws,
			{token.Word, "any"}, ws, {token.Word, "->"}, ws, lc, {token.Whitespace, "  "},
			{token.Word, "any"}, ws, {token.Word, "any"}, ws, lp,
		}, sid1, []tk{rp, nl, eof}),
	},
	{
		name: "continuation_inside_string",
		src:  "(msg:\"abc \\\n    def\";)",
		want: []tk{
			lp, {token.Keyword, "msg"}, colon, {token.Value, "\"abc "},
			lc, {token.Whitespace, "    "},
			{token.Value, "def\""}, semi, rp, eof,
		},
	},
	{
		name: "continuation_trailing_ws",
		src:  "(sid:1; \\   \n)",
		want: seq([]tk{lp}, sid1, []tk{ws, {token.LineContinuation, "\\   \n"}, rp, eof}),
	},
	{
		name: "continuation_crlf",
		src:  "(sid:1; \\\r\n)",
		want: seq([]tk{lp}, sid1, []tk{ws, {token.LineContinuation, "\\\r\n"}, rp, eof}),
	},
	{
		name: "backslash_at_eof",
		src:  "(sid:1;\\",
		want: seq([]tk{lp}, sid1, []tk{{token.Bad, "\\"}, eof}),
	},
	{
		name: "backslash_escape_outside_string",
		src:  "(reference:url,a\x5c;b;)",
		want: []tk{lp, {token.Keyword, "reference"}, colon, {token.Value, "url,a\x5c;b"}, semi, rp, eof},
	},
	{
		name: "lone_rparen_line",
		src:  "(sid:1; \\\n)\n",
		want: seq([]tk{lp}, sid1, []tk{ws, lc, rp, nl, eof}),
	},
	{
		name: "rparen_concat",
		src:  "(sid:1;)alert tcp any any -> any any (sid:2;)\n",
		want: seq([]tk{lp}, sid1, []tk{rp}, header, []tk{
			lp, {token.Keyword, "sid"}, colon, {token.Value, "2"}, semi, rp, nl, eof,
		}),
	},
	{
		name: "value_rparen_terminator",
		src:  "(sid:1)\n",
		want: []tk{lp, {token.Keyword, "sid"}, colon, {token.Value, "1"}, rp, nl, eof},
	},
	{
		name: "value_rparen_terminator_eof",
		src:  "(sid:1)",
		want: []tk{lp, {token.Keyword, "sid"}, colon, {token.Value, "1"}, rp, eof},
	},
	{
		name: "value_rparen_terminator_trailing_ws",
		src:  "(sid:1)  \n",
		want: []tk{lp, {token.Keyword, "sid"}, colon, {token.Value, "1"}, rp, {token.Whitespace, "  "}, nl, eof},
	},
	{
		name: "value_rparen_not_terminator",
		src:  "(reference:url,x.com/a(b);)",
		want: []tk{lp, {token.Keyword, "reference"}, colon, {token.Value, "url,x.com/a(b)"}, semi, rp, eof},
	},
	{
		name:  "unterminated_string",
		src:   "(msg:\"abc\nalert",
		want:  []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "\"abc"}, nl, {token.Word, "alert"}, eof},
		diags: []source.Span{{Start: 5, End: 9}},
	},
	{
		name:  "quote_at_eof",
		src:   "(msg:\"",
		want:  []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "\""}, eof},
		diags: []source.Span{{Start: 5, End: 6}},
	},
	{
		name: "bare_newline_in_body",
		src:  "(sid:1;\nalert",
		want: seq([]tk{lp}, sid1, []tk{nl, {token.Word, "alert"}, eof}),
	},
	{
		name: "bad_in_body",
		src:  "( @@ sid:1;)",
		want: seq([]tk{lp, ws, {token.Bad, "@@"}, ws}, sid1, []tk{rp, eof}),
	},
	{
		name: "keyword_charset",
		src:  "(http.method; app-layer-protocol:http; base64_decode;)",
		want: []tk{
			lp, {token.Keyword, "http.method"}, semi, ws,
			{token.Keyword, "app-layer-protocol"}, colon, {token.Value, "http"}, semi, ws,
			{token.Keyword, "base64_decode"}, semi, rp, eof,
		},
	},
	{
		name: "tabs",
		src:  "alert\ttcp any any -> any any (\tsid:1;\t)\n",
		want: seq([]tk{
			{token.Word, "alert"}, {token.Whitespace, "\t"}, {token.Word, "tcp"}, ws, {token.Word, "any"}, ws,
			{token.Word, "any"}, ws, {token.Word, "->"}, ws, {token.Word, "any"}, ws, {token.Word, "any"}, ws,
			lp, {token.Whitespace, "\t"},
		}, sid1, []tk{{token.Whitespace, "\t"}, rp, nl, eof}),
	},
	{
		name: "unbalanced_pipe",
		src:  "(content:\"|89\";)",
		want: []tk{lp, {token.Keyword, "content"}, colon, {token.Value, "\"|89\""}, semi, rp, eof},
	},
	{
		name: "non_ascii",
		src:  "(msg:\"héllo\";)",
		want: []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "\"héllo\""}, semi, rp, eof},
	},

	// A trailing '\' is a continuation even when the byte before it is
	// another '\': the engines look for it before any escape processing.
	{
		name: "double_backslash_then_newline_is_continuation_in_string",
		src:  "(a:\"b\\\\\nx\";)",
		want: []tk{lp, {token.Keyword, "a"}, colon, {token.Value, "\"b\\"}, lc, {token.Value, "x\""}, semi, rp, eof},
	},
	{
		name: "double_backslash_then_newline_is_continuation_out_of_string",
		src:  "(a:b\\\\\nx;)",
		want: []tk{lp, {token.Keyword, "a"}, colon, {token.Value, "b\\"}, lc, {token.Value, "x"}, semi, rp, eof},
	},
	{
		name: "double_backslash_then_newline_is_continuation_in_header",
		src:  "a\\\\\nb",
		want: []tk{{token.Word, "a\\"}, lc, {token.Word, "b"}, eof},
	},
	{
		name: "double_backslash_then_newline_is_continuation_in_body",
		src:  "(\\\\\nsid:1;)",
		want: seq([]tk{lp, {token.Bad, "\\"}, lc}, sid1, []tk{rp, eof}),
	},
	{
		name: "triple_backslash_then_newline_is_pair_then_continuation",
		src:  "(a:b\\\\\\\nx;)",
		want: []tk{lp, {token.Keyword, "a"}, colon, {token.Value, "b\\\\"}, lc, {token.Value, "x"}, semi, rp, eof},
	},

	// A ')' ends the value only when it is the last ')' on the logical line,
	// continuations included.
	{
		name: "rparen_then_continuation_then_blank_line",
		src:  "(sid:1) \\\n\n",
		want: []tk{lp, {token.Keyword, "sid"}, colon, {token.Value, "1"}, rp, ws, lc, nl, eof},
	},
	{
		name: "rparen_with_later_rparen_after_continuation",
		src:  "(sid:1) \\\n rev:1;)\n",
		want: []tk{
			lp, {token.Keyword, "sid"}, colon, {token.Value, "1) "}, lc, ws,
			{token.Value, "rev:1"}, semi, rp, nl, eof,
		},
	},
	{
		name: "rparen_then_hash",
		src:  "(sid:1) # c\n",
		want: []tk{lp, {token.Keyword, "sid"}, colon, {token.Value, "1"}, rp, ws, {token.Word, "#"}, ws, {token.Word, "c"}, nl, eof},
	},
	{
		name: "rparen_then_word",
		src:  "(sid:1)x\n",
		want: []tk{lp, {token.Keyword, "sid"}, colon, {token.Value, "1"}, rp, {token.Word, "x"}, nl, eof},
	},
	{
		name: "rparen_pairs_then_blanks",
		src:  "(a:) ) ) )   \n",
		want: []tk{lp, {token.Keyword, "a"}, colon, {token.Value, ") ) )"}, ws, rp, {token.Whitespace, "   "}, nl, eof},
	},

	// A continuation leaves atLineStart alone, so a '#' right after one at
	// the start of the input still opens a comment, as in Suricata.
	{
		name: "continuation_then_hash_at_file_start",
		src:  "\\\n#c\n",
		want: []tk{lc, {token.Comment, "#c"}, nl, eof},
	},
}

// moreLexTests cover the lexer's own judgment calls beyond the hazard list.
var moreLexTests = []lexTest{
	{
		name: "comment_at_eof",
		src:  "# c",
		want: []tk{{token.Comment, "# c"}, eof},
	},
	{
		name: "comment_keeps_trailing_backslash",
		src:  "# c \\\nalert",
		want: []tk{{token.Comment, "# c \\"}, nl, {token.Word, "alert"}, eof},
	},
	{
		name: "comment_before_crlf",
		src:  "# c\r\n",
		want: []tk{{token.Comment, "# c"}, {token.Newline, "\r\n"}, eof},
	},
	{
		name: "hash_after_continuation_is_not_a_comment",
		src:  "alert \\\n# c\n",
		want: []tk{{token.Word, "alert"}, ws, lc, {token.Word, "#"}, ws, {token.Word, "c"}, nl, eof},
	},
	{
		name: "hash_in_body_is_bad",
		src:  "(# c;)",
		want: []tk{lp, {token.Bad, "#"}, ws, {token.Keyword, "c"}, semi, rp, eof},
	},
	{
		name: "lone_cr_is_whitespace_in_header",
		src:  "alert\rtcp \r (sid:1;)",
		want: seq([]tk{
			{token.Word, "alert"}, {token.Whitespace, "\r"}, {token.Word, "tcp"}, {token.Whitespace, " \r "}, lp,
		}, sid1, []tk{rp, eof}),
	},
	{
		name: "lone_cr_is_whitespace_in_body",
		src:  "(\rsid:1;\r)",
		want: seq([]tk{lp, {token.Whitespace, "\r"}}, sid1, []tk{{token.Whitespace, "\r"}, rp, eof}),
	},
	{
		name: "lone_cr_is_a_value_byte",
		src:  "(msg:a\rb;)",
		want: []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "a\rb"}, semi, rp, eof},
	},
	{
		name: "lone_cr_in_comment",
		src:  "# a\rb\n",
		want: []tk{{token.Comment, "# a\rb"}, nl, eof},
	},
	{
		name: "backslash_in_word",
		src:  "a\\b \\",
		want: []tk{{token.Word, "a\\b"}, ws, {token.Word, "\\"}, eof},
	},
	{
		name: "continuation_at_file_start",
		src:  "\\\n  alert",
		want: []tk{lc, {token.Whitespace, "  "}, {token.Word, "alert"}, eof},
	},
	{
		name: "bad_run_stops_at_colon",
		src:  "(sid@:1;)",
		want: []tk{lp, {token.Keyword, "sid"}, {token.Bad, "@"}, colon, {token.Value, "1"}, semi, rp, eof},
	},
	{
		name: "bad_run_stops_at_keyword_byte",
		src:  "(\\(\"x\";)",
		want: []tk{lp, {token.Bad, "\\(\""}, {token.Keyword, "x"}, {token.Bad, "\""}, semi, rp, eof},
	},
	{
		name: "bad_then_rparen",
		src:  "(@)",
		want: []tk{lp, {token.Bad, "@"}, rp, eof},
	},
	{
		name: "trailing_blank_split_stops_at_escape_pair",
		src:  "(msg:a\\  ;)",
		want: []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "a\\ "}, ws, semi, rp, eof},
	},
	{
		name: "trailing_blank_before_newline",
		src:  "(msg:abc  \n",
		want: []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "abc"}, {token.Whitespace, "  "}, nl, eof},
	},
	{
		name: "trailing_blank_before_eof",
		src:  "(msg:abc\t",
		want: []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "abc"}, {token.Whitespace, "\t"}, eof},
	},
	{
		name:  "unterminated_string_keeps_its_blanks",
		src:   "(msg:\"abc  \n",
		want:  []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "\"abc  "}, nl, eof},
		diags: []source.Span{{Start: 5, End: 11}},
	},
	{
		name:  "unterminated_string_across_continuation",
		src:   "(msg:\"ab \\\n cd\nx",
		want:  []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "\"ab "}, lc, ws, {token.Value, "cd"}, nl, {token.Word, "x"}, eof},
		diags: []source.Span{{Start: 5, End: 14}},
	},
	{
		name:  "unterminated_string_before_crlf",
		src:   "(msg:\"a\r\n",
		want:  []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "\"a"}, {token.Newline, "\r\n"}, eof},
		diags: []source.Span{{Start: 5, End: 7}},
	},
	{
		name:  "two_unterminated_strings",
		src:   "(a:\"\n(b:\"",
		want:  []tk{lp, {token.Keyword, "a"}, colon, {token.Value, "\""}, nl, lp, {token.Keyword, "b"}, colon, {token.Value, "\""}, eof},
		diags: []source.Span{{Start: 3, End: 4}, {Start: 8, End: 9}},
	},
	{
		name: "escape_pair_hides_quote_outside_string",
		src:  "(msg:a\\\"b;)",
		want: []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "a\\\"b"}, semi, rp, eof},
	},
	{
		name: "backslash_cr_in_value",
		src:  "(msg:a\\\r;)",
		want: []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "a\\\r"}, semi, rp, eof},
	},
	{
		name: "backslash_at_eof_in_value",
		src:  "(msg:a\\",
		want: []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "a\\"}, eof},
	},
	{
		name: "backslash_blanks_eof_is_not_a_continuation",
		src:  "(msg:a\\  ",
		want: []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "a\\ "}, ws, eof},
	},
	{
		name: "rparen_with_later_rparen_is_a_value_byte",
		src:  "(msg:a) \\\n;)",
		want: []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "a) "}, lc, semi, rp, eof},
	},
	{
		name: "rparen_before_lone_cr_closes",
		src:  "(msg:a)\r",
		want: []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "a"}, rp, {token.Whitespace, "\r"}, eof},
	},
	{
		name: "rparen_at_eol_ends_value_even_in_string",
		src:  "(msg:\"a)\nx",
		want: []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "\"a"}, rp, nl, {token.Word, "x"}, eof},
	},
	{
		name: "escaped_rparen_is_still_the_last_rparen",
		src:  "(msg:a) b\\)\n",
		want: []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "a) b\\)"}, nl, eof},
	},
	{
		name: "semicolon_ends_value_even_in_string",
		src:  "(msg:\"a;b\";)",
		want: []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "\"a"}, semi, {token.Keyword, "b"}, {token.Bad, "\""}, semi, rp, eof},
	},
	{
		name: "odd_quotes_then_semicolon",
		src:  "(pcre:\"/content\"\x5cS*?:.*(x)/\"; sid:1;)",
		want: seq([]tk{lp, {token.Keyword, "pcre"}, colon, {token.Value, "\"/content\"\x5cS*?:.*(x)/\""}, semi, ws}, sid1, []tk{rp, eof}),
	},
	{
		name: "open_string_keeps_blanks_before_semicolon",
		src:  "(msg:\"a ;)",
		want: []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "\"a "}, semi, rp, eof},
	},
	{
		name: "string_state_resets_after_semicolon",
		src:  "(a:\";b:c\n",
		want: []tk{lp, {token.Keyword, "a"}, colon, {token.Value, "\""}, semi, {token.Keyword, "b"}, colon, {token.Value, "c"}, nl, eof},
	},
	{
		name: "value_newline_resets_to_header",
		src:  "(msg:a\n(b;)",
		want: []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "a"}, nl, lp, {token.Keyword, "b"}, semi, rp, eof},
	},
	{
		name: "value_only_whitespace_before_semicolon",
		src:  "(msg: ;)",
		want: []tk{lp, {token.Keyword, "msg"}, colon, ws, semi, rp, eof},
	},
	{
		name: "value_only_whitespace_before_newline",
		src:  "(msg: \n",
		want: []tk{lp, {token.Keyword, "msg"}, colon, ws, nl, eof},
	},
	{
		name: "continuation_then_rparen_closes_value",
		src:  "(msg:a \\\n)\n",
		want: []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "a "}, lc, rp, nl, eof},
	},
	{
		name: "value_continuation_without_blanks_after",
		src:  "(msg:a\\\nb;)",
		want: []tk{lp, {token.Keyword, "msg"}, colon, {token.Value, "a"}, lc, {token.Value, "b"}, semi, rp, eof},
	},
	{
		name: "stray_rparen_in_header",
		src:  ") alert",
		want: []tk{rp, ws, {token.Word, "alert"}, eof},
	},
	{
		name: "semicolon_rparen_header_word",
		src:  "(sid:1;)alert",
		want: seq([]tk{lp}, sid1, []tk{rp, {token.Word, "alert"}, eof}),
	},
	{
		name: "crlf_in_body_resets",
		src:  "(sid:1;\r\nalert",
		want: seq([]tk{lp}, sid1, []tk{{token.Newline, "\r\n"}, {token.Word, "alert"}, eof}),
	},
	{
		name: "non_ascii_in_header_word",
		src:  "alért tcp",
		want: []tk{{token.Word, "alért"}, ws, {token.Word, "tcp"}, eof},
	},
	{
		name: "non_ascii_in_body_is_bad",
		src:  "(é;)",
		want: []tk{lp, {token.Bad, "é"}, semi, rp, eof},
	},
	{
		name: "last_rparen_scan_spans_two_rules",
		src:  "(a:x)\n(b:y)\n",
		want: []tk{
			lp, {token.Keyword, "a"}, colon, {token.Value, "x"}, rp, nl,
			lp, {token.Keyword, "b"}, colon, {token.Value, "y"}, rp, nl, eof,
		},
	},
}

func TestLex(t *testing.T) {
	for _, tt := range lexTests {
		t.Run(tt.name, func(t *testing.T) { runLexTest(t, tt) })
	}
}

func TestLexMore(t *testing.T) {
	for _, tt := range moreLexTests {
		t.Run(tt.name, func(t *testing.T) { runLexTest(t, tt) })
	}
}

func runLexTest(t *testing.T, tt lexTest) {
	t.Helper()
	src := []byte(tt.src)
	got, diags := lexer.Lex(src)
	checkInvariants(t, src, got, diags)

	want := make([]token.Token, 0, len(tt.want))
	off := 0
	for _, w := range tt.want {
		want = append(want, token.Token{Kind: w.kind, Start: off, End: off + len(w.lit), Lit: w.lit})
		off += len(w.lit)
	}
	if off != len(src) {
		t.Fatalf("test case is inconsistent: expected texts cover %d bytes, input has %d", off, len(src))
	}
	if !slices.Equal(got, want) {
		t.Errorf("Lex(%q) tokens:\n got %v\nwant %v", tt.src, got, want)
	}

	var gotSpans []source.Span
	for _, d := range diags {
		gotSpans = append(gotSpans, d.Span)
	}
	if !slices.Equal(gotSpans, tt.diags) {
		t.Errorf("Lex(%q) diagnostic spans = %v, want %v", tt.src, gotSpans, tt.diags)
	}
}

func TestLexDiagnosticShape(t *testing.T) {
	src := []byte("(msg:\"abc\nalert")
	_, diags := lexer.Lex(src)
	if len(diags) != 1 {
		t.Fatalf("Lex() produced %d diagnostics, want 1", len(diags))
	}
	got := diags[0]
	want := diag.Diagnostic{
		Severity: diag.SeverityError,
		Rule:     lexer.RuleUnterminatedString,
		Message:  "unterminated string",
		Span:     source.Span{Start: 5, End: 9},
	}
	if got.String() != want.String() || got.Span != want.Span || got.End != want.End ||
		got.File != "" || got.Edits != nil || got.Related != nil {
		t.Errorf("diagnostic = %+v, want %+v", got, want)
	}
	if got.Line != 0 || got.Column != 0 || got.End != (source.Position{}) {
		t.Errorf("diagnostic positions should be left for the caller to resolve, got %+v", got)
	}

	// The caller resolves positions through the file's line table.
	b := diag.Builder{File: "f.rule", Lines: source.NewLineTable(src)}
	b.Resolve(&got)
	if got.File != "f.rule" || got.Line != 1 || got.Column != 6 || got.End != (source.Position{Line: 1, Column: 10}) {
		t.Errorf("resolved diagnostic = %+v", got)
	}
}

func TestLexDoesNotAliasInput(t *testing.T) {
	src := []byte("alert tcp any any -> any any (msg:\"x\"; sid:1;)\n")
	toks, _ := lexer.Lex(src)
	before := make([]string, len(toks))
	for i, tok := range toks {
		before[i] = tok.Lit
	}
	for i := range src {
		src[i] = 'Z'
	}
	for i, tok := range toks {
		if tok.Lit != before[i] {
			t.Fatalf("token %d changed from %q to %q when the input was overwritten", i, before[i], tok.Lit)
		}
	}
}

// Pathological inputs for the last-')' scan: many ')' in one value, with
// and without blanks, must lex in linear time.
func parensThenBlanks(n int) []byte {
	return []byte("(a:" + strings.Repeat(")", n) + strings.Repeat(" ", n) + "\n")
}

func parenBlankPairs(n int) []byte {
	return []byte("(a:" + strings.Repeat(") ", n) + "\n")
}

func parensOnly(n int) []byte {
	return []byte("(a:" + strings.Repeat(")", n) + "\n")
}

func TestLexPathologicalParens(t *testing.T) {
	tests := []struct {
		name string
		src  []byte
	}{
		{"parens_then_blanks_1k", parensThenBlanks(1000)},
		{"paren_blank_pairs_1k", parenBlankPairs(1000)},
		{"parens_1M", parensOnly(1 << 20)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			toks, diags := lexer.Lex(tt.src)
			checkInvariants(t, tt.src, toks, diags)
			// Exactly one RParen, at the last ')', right after the Value
			// (or the Whitespace split off its end).
			var rparens []int
			for i, tok := range toks {
				if tok.Kind == token.RParen {
					rparens = append(rparens, i)
				}
			}
			if len(rparens) != 1 {
				t.Fatalf("got %d RParen tokens, want 1", len(rparens))
			}
			i := rparens[0]
			if want := bytes.LastIndexByte(tt.src, ')'); toks[i].Start != want {
				t.Errorf("RParen at %d, want the last ')' at %d", toks[i].Start, want)
			}
			if prev := toks[i-1].Kind; prev != token.Value && prev != token.Whitespace {
				t.Errorf("token before RParen is %s, want value or whitespace", prev)
			}
		})
	}
}

func BenchmarkLex(b *testing.B) {
	rule := "alert tcp any any -> any any ( \\\n" +
		"    msg:\"VULNCHECK CVE-2021-21315 systeminformation Command Injection\"; \\\n" +
		"    flow:established,to_server; \\\n" +
		"    content:\"GET\"; http_method; \\\n" +
		"    content:\"/api/getServices?\"; depth: 17; http_uri; \\\n" +
		"    pcre:\"/\\/api\\/getServices\\x3f[^\\s]*name(%5[Bb]%5[Dd]|\\x5b\\x5d)=(%24%28|\\$\\(|%60|`)/Ui\"; \\\n" +
		"    reference:cve,CVE-2021-21315; \\\n" +
		"    classtype:web-application-attack; \\\n" +
		"    sid:12900059; rev:1; \\\n" +
		"    metadata: deployment Datacenter, deployment SSLDecrypt;)\n"
	benches := []struct {
		name string
		src  []byte
	}{
		{"rules_1k", []byte(strings.Repeat(rule, 1000))},
		{"parens_then_blanks_1k", parensThenBlanks(1000)},
		{"parens_then_blanks_100k", parensThenBlanks(100000)},
		{"paren_blank_pairs_1k", parenBlankPairs(1000)},
		{"paren_blank_pairs_100k", parenBlankPairs(100000)},
		{"parens_64k", parensOnly(1 << 16)},
		{"parens_1M", parensOnly(1 << 20)},
	}
	for _, bm := range benches {
		b.Run(bm.name, func(b *testing.B) {
			b.SetBytes(int64(len(bm.src)))
			for b.Loop() {
				lexer.Lex(bm.src)
			}
		})
	}
}

var (
	keywordRE      = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	whitespaceRE   = regexp.MustCompile(`^[ \t\r]+$`)
	continuationRE = regexp.MustCompile(`^\\[ \t]*\r?\n$`)
)

// runKinds are the kinds that are maximal runs: two tokens of the same run
// kind never sit next to each other.
var runKinds = map[token.Kind]bool{
	token.Whitespace: true, token.Word: true, token.Bad: true, token.Keyword: true, token.Value: true,
}

// checkInvariants asserts everything Lex promises for any input: the tokens
// tile src exactly, their texts are the bytes they cover, the stream ends in
// a zero-width EOF, every kind has the shape its definition gives it, runs
// are maximal, Missing is never emitted, every diagnostic is a well-formed
// unterminated-string error that starts at a quote and ends at a newline or
// the end of src, and lexing again gives the same result. It returns true
// when every check passed.
func checkInvariants(t testing.TB, src []byte, toks []token.Token, diags []diag.Diagnostic) bool {
	t.Helper()
	ok := true
	fail := func(format string, args ...any) {
		t.Helper()
		ok = false
		t.Errorf(format, args...)
	}

	if len(toks) == 0 {
		fail("Lex(%q) returned no tokens, want at least EOF", src)
		return false
	}
	last := toks[len(toks)-1]
	if last.Kind != token.EOF || last.Start != len(src) || last.End != len(src) || last.Lit != "" {
		fail("last token is %v, want EOF at %d", last, len(src))
	}
	if toks[0].Start != 0 {
		fail("first token %v does not start at 0", toks[0])
	}
	var buf bytes.Buffer
	for i, tok := range toks {
		if tok.Start < 0 || tok.End > len(src) || tok.Start > tok.End {
			fail("token %d %v has offsets outside [0, %d]", i, tok, len(src))
			continue
		}
		if tok.Lit != string(src[tok.Start:tok.End]) {
			fail("token %d %v: Lit differs from src[%d:%d] %q", i, tok, tok.Start, tok.End, src[tok.Start:tok.End])
		}
		if tok.Kind != token.EOF && tok.End <= tok.Start {
			fail("token %d %v is empty", i, tok)
		}
		if i+1 < len(toks) && tok.End != toks[i+1].Start {
			fail("token %d %v does not abut token %d %v", i, tok, i+1, toks[i+1])
		}
		if i > 0 && runKinds[tok.Kind] && toks[i-1].Kind == tok.Kind {
			fail("token %d %v follows another %s: runs must be maximal", i, tok, tok.Kind)
		}
		if bad := checkShape(tok); bad != "" {
			fail("token %d %v: %s", i, tok, bad)
		}
		buf.WriteString(tok.Lit)
	}
	if !bytes.Equal(buf.Bytes(), src) {
		fail("tokens concatenate to %q, want %q", buf.Bytes(), src)
	}
	if toks[len(toks)-1].Kind == token.EOF {
		for i, tok := range toks[:len(toks)-1] {
			if tok.Kind == token.EOF {
				fail("token %d %v: EOF before the end of the stream", i, tok)
			}
		}
	}

	for i, d := range diags {
		if d.Rule != lexer.RuleUnterminatedString {
			fail("diagnostic %d has rule %q, want %q", i, d.Rule, lexer.RuleUnterminatedString)
		}
		if d.Severity != diag.SeverityError {
			fail("diagnostic %d has severity %q, want %q", i, d.Severity, diag.SeverityError)
		}
		if d.Span.Start < 0 || d.Span.End > len(src) || d.Span.Start >= d.Span.End {
			fail("diagnostic %d has span %+v, want a non-empty span inside [0, %d]", i, d.Span, len(src))
			continue
		}
		if src[d.Span.Start] != '"' {
			fail("diagnostic %d span %+v starts at %q, want the opening quote", i, d.Span, src[d.Span.Start])
		}
		if end := d.Span.End; end != len(src) && src[end] != '\n' && !bytes.HasPrefix(src[end:], []byte("\r\n")) {
			fail("diagnostic %d span %+v ends at %q, want a newline or the end of the input", i, d.Span, src[end])
		}
	}

	toks2, diags2 := lexer.Lex(buf.Bytes())
	if !slices.Equal(toks, toks2) {
		fail("lexing the concatenated tokens gave different tokens:\nfirst  %v\nsecond %v", toks, toks2)
	}
	if !slices.EqualFunc(diags, diags2, sameDiag) {
		fail("lexing the concatenated tokens gave different diagnostics:\nfirst  %v\nsecond %v", diags, diags2)
	}
	return ok
}

// checkShape returns why tok's text does not fit its kind, or "" if it does.
func checkShape(tok token.Token) string {
	lit := tok.Lit
	switch tok.Kind {
	case token.EOF:
		if lit != "" {
			return "EOF is not empty"
		}
	case token.Newline:
		if lit != "\n" && lit != "\r\n" {
			return `Newline is not "\n" or "\r\n"`
		}
	case token.Whitespace:
		if !whitespaceRE.MatchString(lit) {
			return "Whitespace outside [ \\t\\r]+"
		}
	case token.LineContinuation:
		if !continuationRE.MatchString(lit) {
			return `LineContinuation is not \ [ \t]* newline`
		}
	case token.Comment:
		if !strings.HasPrefix(lit, "#") || strings.Contains(lit, "\n") {
			return "Comment does not start with # or contains a newline"
		}
	case token.Word:
		if strings.ContainsAny(lit, " \t\r\n[],!()") {
			return "Word contains a stop byte"
		}
	case token.Keyword:
		if !keywordRE.MatchString(lit) {
			return "Keyword outside [A-Za-z0-9_.-]+"
		}
	case token.Value:
		if strings.Contains(lit, "\n") {
			return "Value contains a newline"
		}
	case token.Bad:
		if strings.ContainsAny(lit, ";): \t\r\n") {
			return "Bad contains a byte Body mode expects"
		}
	case token.Bang, token.LBracket, token.RBracket, token.Comma, token.LParen,
		token.RParen, token.Colon, token.Semicolon:
		if len(lit) != 1 {
			return "punctuation is not a single byte"
		}
	case token.Missing:
		return "the lexer emitted Missing"
	default:
		return "unknown kind"
	}
	return ""
}

func sameDiag(a, b diag.Diagnostic) bool {
	return a.Rule == b.Rule && a.Severity == b.Severity && a.Message == b.Message && a.Span == b.Span
}
