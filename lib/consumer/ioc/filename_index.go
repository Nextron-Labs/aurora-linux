package ioc

import (
	"regexp/syntax"
	"slices"
	"strings"
	"unicode/utf8"
)

// filenameIndex avoids running every filename IOC regex on every value.
// Most IOC regexes contain a literal that any match must include (for
// example "\\msdcsvc.dat"). The index finds which of those literals occur in
// a value with one pass over the value's trigrams; only the regexes whose
// literal occurs (plus the few without a usable literal) are evaluated.
// Matching stays exact: the index only skips regexes that cannot match.
type filenameIndex struct {
	// byTrigram maps the first 3 bytes of a lowercased literal to the
	// entries requiring it.
	byTrigram map[[3]byte][]indexedLiteral
	// always lists the entries without a usable literal (alternations,
	// literals shorter than 3 bytes, ...): they are always evaluated.
	always []int
}

type indexedLiteral struct {
	lit   string // lowercased
	entry int
}

const minIndexedLiteral = 3

func newFilenameIndex(entries []filenameIOCEntry) *filenameIndex {
	idx := &filenameIndex{byTrigram: map[[3]byte][]indexedLiteral{}}
	for i, e := range entries {
		lits := requiredLiterals(e.rawPattern)
		if lits == nil {
			idx.always = append(idx.always, i)
			continue
		}
		for _, lit := range lits {
			k := [3]byte{lit[0], lit[1], lit[2]}
			idx.byTrigram[k] = append(idx.byTrigram[k], indexedLiteral{lit: lit, entry: i})
		}
	}
	return idx
}

// candidates returns, in ascending order, the entries that may match value,
// or all=true when every entry must be evaluated. buf is reused.
func (idx *filenameIndex) candidates(value string, buf []int) (list []int, all bool) {
	if !isASCII(value) {
		// Unicode case folding can make a regex match bytes that differ
		// from its lowercased literal (e.g. U+017F folds to 's'): no
		// shortcut, evaluate everything.
		return buf[:0], true
	}
	buf = append(buf[:0], idx.always...)
	lower := asciiLower(value)
	for p := 0; p+minIndexedLiteral <= len(lower); p++ {
		list, ok := idx.byTrigram[[3]byte{lower[p], lower[p+1], lower[p+2]}]
		if !ok {
			continue
		}
		for _, il := range list {
			if strings.HasPrefix(lower[p:], il.lit) {
				buf = append(buf, il.entry)
			}
		}
	}
	slices.Sort(buf)
	return slices.Compact(buf), false
}

// requiredLiterals returns lowercased literals such that every match of
// pattern contains at least one of them, or nil if no such set with
// members of at least minIndexedLiteral ASCII bytes can be derived.
// Lowercasing makes the set usable for both case-sensitive and (?i)
// patterns (a superset check; the regex decides).
func requiredLiterals(pattern string) []string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	set := literalSet(re.Simplify())
	if minLen(set) < minIndexedLiteral {
		return nil
	}
	out := make([]string, 0, len(set))
	for _, l := range set {
		if !isASCII(l) {
			return nil
		}
		out = append(out, asciiLower(l))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// requiredLiteral is the single-literal form (tests, diagnostics).
func requiredLiteral(pattern string) string {
	if l := requiredLiterals(pattern); len(l) == 1 {
		return l[0]
	}
	return ""
}

const maxLiteralSet = 16

// literalSet returns strings such that any match of re contains one of
// them (nil: unknown).
func literalSet(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{string(re.Rune)}
	case syntax.OpCapture, syntax.OpPlus:
		return literalSet(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return literalSet(re.Sub[0])
		}
	case syntax.OpAlternate:
		var out []string
		for _, s := range re.Sub {
			l := literalSet(s)
			if l == nil {
				return nil
			}
			out = append(out, l...)
		}
		if len(out) > maxLiteralSet {
			return nil
		}
		return out
	case syntax.OpConcat:
		var best []string
		for _, s := range re.Sub {
			if l := literalSet(s); l != nil && minLen(l) > minLen(best) {
				best = l
			}
		}
		return best
	}
	return nil
}

func minLen(set []string) int {
	if len(set) == 0 {
		return 0
	}
	m := len(set[0])
	for _, s := range set[1:] {
		m = min(m, len(s))
	}
	return m
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}
