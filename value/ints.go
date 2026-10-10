package value

import (
	"strconv"
	"strings"
)

// ParseUint decodes an unsigned decimal integer: digits only, no sign, no
// blanks. A value that does not fit in 64 bits is an error.
func ParseUint(s string) (uint64, error) {
	if s == "" {
		return 0, errAt(0, "expected a number")
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return 0, errAt(i, "expected a digit")
		}
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, errAt(0, "number too large")
	}
	return v, nil
}

// IntOrVar is a decoded integer or variable reference: exactly one of
// Value and Var is meaningful, Var being empty for a number.
type IntOrVar struct {
	// Value is the number when Var is empty.
	Value int64
	// Var is the variable as written, "$NAME" or a bare byte_extract
	// variable "NAME".
	Var string
}

// ParseIntOrVar decodes a signed decimal integer, with an optional '-' or
// '+', or a variable reference: "$NAME", or a bare name that starts with a
// letter or '_', as both engines write byte_extract variables. Names are
// letters, digits and '_'.
func ParseIntOrVar(s string) (IntOrVar, error) {
	if s == "" {
		return IntOrVar{}, errAt(0, "expected a number or variable")
	}
	if s[0] == '$' || isLetter(s[0]) || s[0] == '_' {
		if s == "$" {
			return IntOrVar{}, errAt(1, "expected a variable name")
		}
		for i := 1; i < len(s); i++ {
			if c := s[i]; !isLetter(c) && !isDigit(c) && c != '_' {
				return IntOrVar{}, errAt(i, "invalid character in variable name")
			}
		}
		return IntOrVar{Var: s}, nil
	}
	i := 0
	if s[0] == '-' || s[0] == '+' {
		i = 1
	}
	if i == len(s) {
		return IntOrVar{}, errAt(i, "expected a digit")
	}
	for j := i; j < len(s); j++ {
		if !isDigit(s[j]) {
			return IntOrVar{}, errAt(j, "expected a digit")
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return IntOrVar{}, errAt(0, "number too large")
	}
	return IntOrVar{Value: v}, nil
}

// RelInt is a decoded relational integer: a number with an optional
// operator, or a range.
type RelInt struct {
	// Op is "" for a plain number, one of "<", ">", "<=", ">=", "=", "!"
	// for a comparison, or "<>" or "-" for a range of A and B. The
	// engines disagree on whether a range includes its bounds, so the
	// range operator is kept as written.
	Op string
	// A is the number, or the lower bound of a range.
	A int64
	// B is the upper bound of a range; zero otherwise.
	B int64
}

// relOps are the comparison operators, longest first so that "<=" is not
// read as "<".
var relOps = []string{"<=", ">=", "!=", "<", ">", "=", "!"}

// ParseRelInt decodes a relational integer: N, <N, >N, <=N, >=N, =N, !N
// (also written !=N), or the ranges N<>M and N-M. Blanks around the
// operators are allowed. The numbers are unsigned; a range whose lower
// bound is not below its upper bound is an error.
func ParseRelInt(s string) (RelInt, error) {
	var r RelInt
	i := skipBlanks(s, 0)
	for _, op := range relOps {
		if strings.HasPrefix(s[i:], op) {
			r.Op = op
			i += len(op)
			break
		}
	}
	if r.Op == "!=" {
		r.Op = "!"
	}
	i = skipBlanks(s, i)
	a, n, err := number(s, i)
	if err != nil {
		return RelInt{}, err
	}
	r.A = a
	i = skipBlanks(s, i+n)
	if i == len(s) {
		return r, nil
	}
	if r.Op != "" {
		return RelInt{}, errAt(i, "unexpected text after number")
	}
	switch {
	case strings.HasPrefix(s[i:], "<>"):
		r.Op = "<>"
		i += 2
	case s[i] == '-':
		r.Op = "-"
		i++
	default:
		return RelInt{}, errAt(i, "unexpected text after number")
	}
	i = skipBlanks(s, i)
	bOff := i
	b, n, err := number(s, i)
	if err != nil {
		return RelInt{}, err
	}
	r.B = b
	if i = skipBlanks(s, i+n); i != len(s) {
		return RelInt{}, errAt(i, "unexpected text after range")
	}
	if r.A >= r.B {
		return RelInt{}, errAt(bOff, "range upper bound must be greater than its lower bound")
	}
	return r, nil
}

// number decodes the run of digits at s[i:] and returns its value and
// length.
func number(s string, i int) (int64, int, error) {
	n := 0
	for i+n < len(s) && isDigit(s[i+n]) {
		n++
	}
	if n == 0 {
		return 0, 0, errAt(i, "expected a number")
	}
	v, err := parseDigits(part{s[i : i+n], i})
	return v, n, err
}

// Urilen is a decoded urilen value.
type Urilen struct {
	RelInt
	// Buffer is "norm" or "raw" when the value named the buffer to
	// measure, and empty otherwise.
	Buffer string
}

// ParseUrilen decodes a urilen value: a relational integer as ParseRelInt
// reads it, then optionally ",norm" or ",raw", with blanks around the comma
// allowed. Anything else after the comma is an error.
func ParseUrilen(s string) (Urilen, error) {
	comma := strings.IndexByte(s, ',')
	if comma < 0 {
		r, err := ParseRelInt(s)
		if err != nil {
			return Urilen{}, err
		}
		return Urilen{RelInt: r}, nil
	}
	r, err := ParseRelInt(s[:comma])
	if err != nil {
		return Urilen{}, err
	}
	buf := trim(part{s[comma+1:], comma + 1})
	if buf.text != "norm" && buf.text != "raw" {
		return Urilen{}, errAt(buf.off, `expected "norm" or "raw"`)
	}
	return Urilen{RelInt: r, Buffer: buf.text}, nil
}
