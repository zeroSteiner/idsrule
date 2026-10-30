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
// operator, a range, or a bitmask test.
type RelInt struct {
	// Op is "" for a plain number; one of "<", ">", "<=", ">=", "=", "!"
	// for a comparison; "<>" or "-" for a range of A and B, or "!<>" or
	// "!-" for the numbers outside it; or "&=" or "&!=" for the test that
	// the value ANDed with the mask A is, or is not, B. The engines
	// disagree on whether a range includes its bounds, so the range
	// operator is kept as written.
	Op string
	// A is the number, the lower bound of a range or the mask of a
	// bitmask test.
	A int64
	// B is the upper bound of a range or the value a bitmask test
	// compares with; zero otherwise.
	B int64
}

// relOps are the comparison operators, longest first so that "<=" is not
// read as "<".
var relOps = []string{"<=", ">=", "!=", "<", ">", "=", "!"}

// ParseRelInt decodes a relational integer as either engine writes it: N,
// <N, >N, <=N, >=N, =N, !N (also written !=N), the ranges N<>M and N-M,
// and what Suricata 8 adds to them: the negated ranges !N<>M and !N-M, the
// bitmask tests &M=N and &M!=N, and numbers written in hex ("0x1f") or
// with a size unit ("10kb"; see uintValue). Blanks around the operators
// are allowed. The numbers are unsigned. A range whose lower bound is not
// below its upper bound is an error, and so is a bitmask test whose value
// has bits outside its mask, which Suricata rejects as never matching.
func ParseRelInt(s string) (RelInt, error) {
	var r RelInt
	i := skipBlanks(s, 0)
	if i < len(s) && s[i] == '&' {
		return parseBitmask(s, i+1)
	}
	for _, op := range relOps {
		if strings.HasPrefix(s[i:], op) {
			r.Op = op
			i += len(op)
			break
		}
	}
	i = skipBlanks(s, i)
	a, n, err := uintValue(s, i)
	if err != nil {
		return RelInt{}, err
	}
	r.A = a
	i = skipBlanks(s, i+n)
	if i == len(s) {
		if r.Op == "!=" {
			r.Op = "!"
		}
		return r, nil
	}
	// Only a bare '!' may precede a range, negating it.
	if r.Op != "" && r.Op != "!" {
		return RelInt{}, errAt(i, "unexpected text after number")
	}
	switch {
	case strings.HasPrefix(s[i:], "<>"):
		r.Op += "<>"
		i += 2
	case s[i] == '-':
		r.Op += "-"
		i++
	default:
		return RelInt{}, errAt(i, "unexpected text after number")
	}
	i = skipBlanks(s, i)
	bOff := i
	b, n, err := uintValue(s, i)
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

// parseBitmask decodes the rest of a bitmask test, "M=N" or "M!=N", from
// s[i:], just after its '&'.
func parseBitmask(s string, i int) (RelInt, error) {
	i = skipBlanks(s, i)
	a, n, err := uintValue(s, i)
	if err != nil {
		return RelInt{}, err
	}
	r := RelInt{Op: "&=", A: a}
	i = skipBlanks(s, i+n)
	switch {
	case strings.HasPrefix(s[i:], "!="):
		r.Op = "&!="
		i += 2
	case strings.HasPrefix(s[i:], "="):
		i++
	default:
		return RelInt{}, errAt(i, `expected "=" or "!=" after the mask`)
	}
	i = skipBlanks(s, i)
	bOff := i
	b, n, err := uintValue(s, i)
	if err != nil {
		return RelInt{}, err
	}
	r.B = b
	if i = skipBlanks(s, i+n); i != len(s) {
		return RelInt{}, errAt(i, "unexpected text after bitmask")
	}
	if b&a != b {
		return RelInt{}, errAt(bOff, "bitmask value has bits outside the mask, so it can never match")
	}
	return r, nil
}

// sizeUnits are the unit suffixes Suricata 8 accepts after a decimal
// number, matched without regard to case.
var sizeUnits = []struct {
	name string
	mult int64
}{
	{"kib", 1 << 10}, {"kb", 1 << 10},
	{"mib", 1 << 20}, {"mb", 1 << 20},
	{"gib", 1 << 30}, {"gb", 1 << 30},
}

// uintValue decodes the number at s[i:] as Suricata 8 reads one, "0x"
// followed by hex digits or decimal digits with an optional size unit,
// and returns its value and the length of its text. Snort 2.9 reads only
// the plain decimal digits.
func uintValue(s string, i int) (int64, int, error) {
	if strings.HasPrefix(s[i:], "0x") {
		n := 2
		for i+n < len(s) && isHex(s[i+n]) {
			n++
		}
		// "0x" with no hex digit after it is the number 0 followed by
		// an 'x', which the caller rejects.
		if n > 2 {
			v, err := strconv.ParseInt(s[i+2:i+n], 16, 64)
			if err != nil {
				return 0, 0, errAt(i, "number too large")
			}
			return v, n, nil
		}
	}
	v, n, err := number(s, i)
	if err != nil {
		return 0, 0, err
	}
	rest := s[i+n:]
	for _, u := range sizeUnits {
		if len(rest) >= len(u.name) && strings.EqualFold(rest[:len(u.name)], u.name) {
			if v > maxInt64/u.mult {
				return 0, 0, errAt(i, "number too large")
			}
			return v * u.mult, n + len(u.name), nil
		}
	}
	return v, n, nil
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
