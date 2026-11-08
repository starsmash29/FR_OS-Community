package pyyaml

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The reader (yaml.reader.Reader) for a str input, and the scanner
// (yaml.scanner.Scanner), method for method. Python's IndexError past the
// end can't happen for a str input: the buffer ends in '\0' and every
// scan stops there.

func printable(r rune) bool {
	return r == '\t' || r == '\n' || r == '\r' || (r >= 0x20 && r <= 0x7e) || r == 0x85 ||
		(r >= 0xa0 && r <= 0xd7ff) || (r >= 0xe000 && r <= 0xfffd) || (r >= 0x10000 && r <= 0x10ffff)
}

const (
	breakz    = "\x00\r\n\u0085  "
	blankz    = "\x00 \t\r\n\u0085  "
	spaceBrkz = "\x00 \r\n\u0085  "
	brk       = "\r\n\u0085  "
)

func in(r rune, set string) bool { return strings.ContainsRune(set, r) }

func isAlnumDash(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '-' || r == '_'
}

func isHex(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'A' && r <= 'F') || (r >= 'a' && r <= 'f')
}

type tokenKind int

const (
	tStreamStart tokenKind = iota
	tStreamEnd
	tDirective
	tDocumentStart
	tDocumentEnd
	tBlockSequenceStart
	tBlockMappingStart
	tBlockEnd
	tFlowSequenceStart
	tFlowMappingStart
	tFlowSequenceEnd
	tFlowMappingEnd
	tKey
	tValue
	tBlockEntry
	tFlowEntry
	tAlias
	tAnchor
	tTag
	tScalar
)

var tokenIDs = [...]string{
	"<stream start>", "<stream end>", "<directive>", "<document start>", "<document end>",
	"<block sequence start>", "<block mapping start>", "<block end>", "[", "{", "]", "}",
	"?", ":", "-", ",", "<alias>", "<anchor>", "<tag>", "<scalar>",
}

type token struct {
	kind       tokenKind
	start, end Mark
	value      string // alias, anchor, scalar; directive name
	// tag: handle (hasHandle false for None) and suffix
	handle    string
	hasHandle bool
	suffix    string
	// directive values
	major, minor int
	tagHandle    string
	tagPrefix    string
	plain        bool
	style        rune // 0 for None
}

func (t *token) id() string { return tokenIDs[t.kind] }

type simpleKey struct {
	tokenNumber         int
	required            bool
	index, line, column int
	mark                Mark
}

type scanner struct {
	// reader
	name                string
	buffer              []rune
	pointer             int
	index, line, column int

	done               bool
	flowLevel          int
	tokens             []*token
	tokensTaken        int
	indent             int
	indents            []int
	allowSimpleKey     bool
	possibleSimpleKeys map[int]*simpleKey
}

func newScanner(text string) (*scanner, error) {
	if !utf8.ValidString(text) {
		return nil, &LimitError{"config: the text is not valid UTF-8"}
	}
	runes := []rune(text)
	for i, r := range runes {
		if !printable(r) {
			return nil, &ReaderError{Name: "<unicode string>", Position: i, Character: r}
		}
	}
	s := &scanner{
		name:               "<unicode string>",
		buffer:             append(runes, 0),
		indent:             -1,
		allowSimpleKey:     true,
		possibleSimpleKeys: map[int]*simpleKey{},
	}
	s.fetchStreamStart()
	return s, nil
}

// Reader.

func (s *scanner) peek(i int) rune { return s.buffer[s.pointer+i] }

func (s *scanner) prefix(n int) string {
	end := s.pointer + n
	if end > len(s.buffer) {
		end = len(s.buffer)
	}
	return string(s.buffer[s.pointer:end])
}

func (s *scanner) forward(n int) {
	for ; n > 0; n-- {
		ch := s.buffer[s.pointer]
		s.pointer++
		s.index++
		if ch == '\n' || ch == 0x85 || ch == 0x2028 || ch == 0x2029 || (ch == '\r' && s.buffer[s.pointer] != '\n') {
			s.line++
			s.column = 0
		} else if ch != 0xfeff {
			s.column++
		}
	}
}

func (s *scanner) mark() Mark {
	return Mark{Name: s.name, Index: s.index, Line: s.line, Column: s.column, buffer: s.buffer, pointer: s.pointer, valid: true}
}

func (s *scanner) fail(context string, contextMark Mark, format string, args ...any) {
	panic(Errorf(context, contextMark, s.mark(), format, args...))
}

// Public methods.

func (s *scanner) checkToken(kinds ...tokenKind) bool {
	for s.needMoreTokens() {
		s.fetchMoreTokens()
	}
	if len(s.tokens) > 0 {
		if len(kinds) == 0 {
			return true
		}
		for _, k := range kinds {
			if s.tokens[0].kind == k {
				return true
			}
		}
	}
	return false
}

func (s *scanner) peekToken() *token {
	for s.needMoreTokens() {
		s.fetchMoreTokens()
	}
	if len(s.tokens) > 0 {
		return s.tokens[0]
	}
	return nil
}

func (s *scanner) getToken() *token {
	for s.needMoreTokens() {
		s.fetchMoreTokens()
	}
	if len(s.tokens) > 0 {
		s.tokensTaken++
		t := s.tokens[0]
		s.tokens = s.tokens[1:]
		return t
	}
	return nil
}

func (s *scanner) needMoreTokens() bool {
	if s.done {
		return false
	}
	if len(s.tokens) == 0 {
		return true
	}
	s.staleSimpleKeys()
	n, ok := s.nextPossibleSimpleKey()
	return ok && n == s.tokensTaken
}

func (s *scanner) fetchMoreTokens() {
	s.scanToNextToken()
	s.staleSimpleKeys()
	s.unwindIndent(s.column)
	ch := s.peek(0)
	switch {
	case ch == 0:
		s.fetchStreamEnd()
	case ch == '%' && s.checkDirective():
		s.fetchDirective()
	case ch == '-' && s.checkDocumentIndicator("---"):
		s.fetchDocumentIndicator(tDocumentStart)
	case ch == '.' && s.checkDocumentIndicator("..."):
		s.fetchDocumentIndicator(tDocumentEnd)
	case ch == '[':
		s.fetchFlowCollectionStart(tFlowSequenceStart)
	case ch == '{':
		s.fetchFlowCollectionStart(tFlowMappingStart)
	case ch == ']':
		s.fetchFlowCollectionEnd(tFlowSequenceEnd)
	case ch == '}':
		s.fetchFlowCollectionEnd(tFlowMappingEnd)
	case ch == ',':
		s.fetchFlowEntry()
	case ch == '-' && s.checkBlockEntry():
		s.fetchBlockEntry()
	case ch == '?' && s.checkKey():
		s.fetchKey()
	case ch == ':' && s.checkValue():
		s.fetchValue()
	case ch == '*':
		s.fetchAnchor(tAlias)
	case ch == '&':
		s.fetchAnchor(tAnchor)
	case ch == '!':
		s.fetchTag()
	case ch == '|' && s.flowLevel == 0:
		s.fetchBlockScalar('|')
	case ch == '>' && s.flowLevel == 0:
		s.fetchBlockScalar('>')
	case ch == '\'':
		s.fetchFlowScalar('\'')
	case ch == '"':
		s.fetchFlowScalar('"')
	case s.checkPlain():
		s.fetchPlain()
	default:
		s.fail("while scanning for the next token", Mark{}, "found character %s that cannot start any token", pyRepr(string(ch)))
	}
}

// Simple keys.

func (s *scanner) nextPossibleSimpleKey() (int, bool) {
	found := false
	min := 0
	for _, k := range s.possibleSimpleKeys {
		if !found || k.tokenNumber < min {
			min, found = k.tokenNumber, true
		}
	}
	return min, found
}

func (s *scanner) staleSimpleKeys() {
	// Only a key at flow level 0 can be required, so the order of the
	// levels doesn't change which error is raised.
	for level, k := range s.possibleSimpleKeys {
		if k.line != s.line || s.index-k.index > 1024 {
			if k.required {
				s.fail("while scanning a simple key", k.mark, "could not find expected ':'")
			}
			delete(s.possibleSimpleKeys, level)
		}
	}
}

func (s *scanner) savePossibleSimpleKey() {
	required := s.flowLevel == 0 && s.indent == s.column
	if s.allowSimpleKey {
		s.removePossibleSimpleKey()
		s.possibleSimpleKeys[s.flowLevel] = &simpleKey{
			tokenNumber: s.tokensTaken + len(s.tokens), required: required,
			index: s.index, line: s.line, column: s.column, mark: s.mark(),
		}
	}
}

func (s *scanner) removePossibleSimpleKey() {
	if k, ok := s.possibleSimpleKeys[s.flowLevel]; ok {
		if k.required {
			s.fail("while scanning a simple key", k.mark, "could not find expected ':'")
		}
		delete(s.possibleSimpleKeys, s.flowLevel)
	}
}

// Indentation.

func (s *scanner) unwindIndent(column int) {
	if s.flowLevel != 0 {
		return
	}
	for s.indent > column {
		m := s.mark()
		s.indent = s.indents[len(s.indents)-1]
		s.indents = s.indents[:len(s.indents)-1]
		s.add(&token{kind: tBlockEnd, start: m, end: m})
	}
}

func (s *scanner) addIndent(column int) bool {
	if s.indent < column {
		s.indents = append(s.indents, s.indent)
		s.indent = column
		return true
	}
	return false
}

func (s *scanner) add(t *token) { s.tokens = append(s.tokens, t) }

func (s *scanner) insert(at int, t *token) {
	s.tokens = append(s.tokens, nil)
	copy(s.tokens[at+1:], s.tokens[at:])
	s.tokens[at] = t
}

// Fetchers.

func (s *scanner) fetchStreamStart() {
	m := s.mark()
	s.add(&token{kind: tStreamStart, start: m, end: m})
}

func (s *scanner) fetchStreamEnd() {
	s.unwindIndent(-1)
	s.removePossibleSimpleKey()
	s.allowSimpleKey = false
	s.possibleSimpleKeys = map[int]*simpleKey{}
	m := s.mark()
	s.add(&token{kind: tStreamEnd, start: m, end: m})
	s.done = true
}

func (s *scanner) fetchDirective() {
	s.unwindIndent(-1)
	s.removePossibleSimpleKey()
	s.allowSimpleKey = false
	s.add(s.scanDirective())
}

func (s *scanner) fetchDocumentIndicator(kind tokenKind) {
	s.unwindIndent(-1)
	s.removePossibleSimpleKey()
	s.allowSimpleKey = false
	start := s.mark()
	s.forward(3)
	s.add(&token{kind: kind, start: start, end: s.mark()})
}

func (s *scanner) fetchFlowCollectionStart(kind tokenKind) {
	s.savePossibleSimpleKey()
	s.flowLevel++
	s.allowSimpleKey = true
	start := s.mark()
	s.forward(1)
	s.add(&token{kind: kind, start: start, end: s.mark()})
}

func (s *scanner) fetchFlowCollectionEnd(kind tokenKind) {
	s.removePossibleSimpleKey()
	s.flowLevel--
	s.allowSimpleKey = false
	start := s.mark()
	s.forward(1)
	s.add(&token{kind: kind, start: start, end: s.mark()})
}

func (s *scanner) fetchFlowEntry() {
	s.allowSimpleKey = true
	s.removePossibleSimpleKey()
	start := s.mark()
	s.forward(1)
	s.add(&token{kind: tFlowEntry, start: start, end: s.mark()})
}

func (s *scanner) fetchBlockEntry() {
	if s.flowLevel == 0 {
		if !s.allowSimpleKey {
			s.fail("", Mark{}, "sequence entries are not allowed here")
		}
		if s.addIndent(s.column) {
			m := s.mark()
			s.add(&token{kind: tBlockSequenceStart, start: m, end: m})
		}
	}
	s.allowSimpleKey = true
	s.removePossibleSimpleKey()
	start := s.mark()
	s.forward(1)
	s.add(&token{kind: tBlockEntry, start: start, end: s.mark()})
}

func (s *scanner) fetchKey() {
	if s.flowLevel == 0 {
		if !s.allowSimpleKey {
			s.fail("", Mark{}, "mapping keys are not allowed here")
		}
		if s.addIndent(s.column) {
			m := s.mark()
			s.add(&token{kind: tBlockMappingStart, start: m, end: m})
		}
	}
	s.allowSimpleKey = s.flowLevel == 0
	s.removePossibleSimpleKey()
	start := s.mark()
	s.forward(1)
	s.add(&token{kind: tKey, start: start, end: s.mark()})
}

func (s *scanner) fetchValue() {
	if k, ok := s.possibleSimpleKeys[s.flowLevel]; ok {
		delete(s.possibleSimpleKeys, s.flowLevel)
		s.insert(k.tokenNumber-s.tokensTaken, &token{kind: tKey, start: k.mark, end: k.mark})
		if s.flowLevel == 0 && s.addIndent(k.column) {
			s.insert(k.tokenNumber-s.tokensTaken, &token{kind: tBlockMappingStart, start: k.mark, end: k.mark})
		}
		s.allowSimpleKey = false
	} else {
		if s.flowLevel == 0 && !s.allowSimpleKey {
			s.fail("", Mark{}, "mapping values are not allowed here")
		}
		if s.flowLevel == 0 && s.addIndent(s.column) {
			m := s.mark()
			s.add(&token{kind: tBlockMappingStart, start: m, end: m})
		}
		s.allowSimpleKey = s.flowLevel == 0
		s.removePossibleSimpleKey()
	}
	start := s.mark()
	s.forward(1)
	s.add(&token{kind: tValue, start: start, end: s.mark()})
}

func (s *scanner) fetchAnchor(kind tokenKind) {
	s.savePossibleSimpleKey()
	s.allowSimpleKey = false
	s.add(s.scanAnchor(kind))
}

func (s *scanner) fetchTag() {
	s.savePossibleSimpleKey()
	s.allowSimpleKey = false
	s.add(s.scanTag())
}

func (s *scanner) fetchBlockScalar(style rune) {
	s.allowSimpleKey = true
	s.removePossibleSimpleKey()
	s.add(s.scanBlockScalar(style))
}

func (s *scanner) fetchFlowScalar(style rune) {
	s.savePossibleSimpleKey()
	s.allowSimpleKey = false
	s.add(s.scanFlowScalar(style))
}

func (s *scanner) fetchPlain() {
	s.savePossibleSimpleKey()
	s.allowSimpleKey = false
	s.add(s.scanPlain())
}

// Checkers.

func (s *scanner) checkDirective() bool { return s.column == 0 }

func (s *scanner) checkDocumentIndicator(ind string) bool {
	return s.column == 0 && s.prefix(3) == ind && in(s.peek(3), blankz)
}

func (s *scanner) checkBlockEntry() bool { return in(s.peek(1), blankz) }

func (s *scanner) checkKey() bool { return s.flowLevel != 0 || in(s.peek(1), blankz) }

func (s *scanner) checkValue() bool { return s.flowLevel != 0 || in(s.peek(1), blankz) }

func (s *scanner) checkPlain() bool {
	ch := s.peek(0)
	return !in(ch, blankz+"-?:,[]{}#&*!|>'\"%@`") ||
		(!in(s.peek(1), blankz) && (ch == '-' || (s.flowLevel == 0 && in(ch, "?:"))))
}

// Scanners.

func (s *scanner) scanToNextToken() {
	if s.index == 0 && s.peek(0) == 0xfeff {
		s.forward(1)
	}
	for {
		for s.peek(0) == ' ' {
			s.forward(1)
		}
		if s.peek(0) == '#' {
			for !in(s.peek(0), breakz) {
				s.forward(1)
			}
		}
		if s.scanLineBreak() != "" {
			if s.flowLevel == 0 {
				s.allowSimpleKey = true
			}
		} else {
			return
		}
	}
}

func (s *scanner) scanDirective() *token {
	start := s.mark()
	s.forward(1)
	name := s.scanDirectiveName(start)
	t := &token{kind: tDirective, value: name, start: start}
	switch name {
	case "YAML":
		t.major, t.minor = s.scanYAMLDirectiveValue(start)
		t.end = s.mark()
	case "TAG":
		t.tagHandle, t.tagPrefix = s.scanTagDirectiveValue(start)
		t.end = s.mark()
	default:
		t.end = s.mark()
		for !in(s.peek(0), breakz) {
			s.forward(1)
		}
	}
	s.scanDirectiveIgnoredLine(start)
	return t
}

func (s *scanner) scanDirectiveName(start Mark) string {
	n := 0
	for isAlnumDash(s.peek(n)) {
		n++
	}
	if n == 0 {
		s.fail("while scanning a directive", start, "expected alphabetic or numeric character, but found %s", pyRepr(string(s.peek(n))))
	}
	value := s.prefix(n)
	s.forward(n)
	if ch := s.peek(0); !in(ch, spaceBrkz) {
		s.fail("while scanning a directive", start, "expected alphabetic or numeric character, but found %s", pyRepr(string(ch)))
	}
	return value
}

func (s *scanner) scanYAMLDirectiveValue(start Mark) (int, int) {
	for s.peek(0) == ' ' {
		s.forward(1)
	}
	major := s.scanYAMLDirectiveNumber(start)
	if s.peek(0) != '.' {
		s.fail("while scanning a directive", start, "expected a digit or '.', but found %s", pyRepr(string(s.peek(0))))
	}
	s.forward(1)
	minor := s.scanYAMLDirectiveNumber(start)
	if !in(s.peek(0), spaceBrkz) {
		s.fail("while scanning a directive", start, "expected a digit or ' ', but found %s", pyRepr(string(s.peek(0))))
	}
	return major, minor
}

func (s *scanner) scanYAMLDirectiveNumber(start Mark) int {
	if ch := s.peek(0); !(ch >= '0' && ch <= '9') {
		s.fail("while scanning a directive", start, "expected a digit, but found %s", pyRepr(string(ch)))
	}
	n := 0
	for ch := s.peek(n); ch >= '0' && ch <= '9'; ch = s.peek(n) {
		n++
	}
	v, err := strconv.Atoi(s.prefix(n))
	if err != nil {
		// Python's int has no limit; a version that long is refused
		// further on anyway (major != 1) or is meaningless.
		panic(&LimitError{"config: YAML directive version number too long"})
	}
	s.forward(n)
	return v
}

func (s *scanner) scanTagDirectiveValue(start Mark) (string, string) {
	for s.peek(0) == ' ' {
		s.forward(1)
	}
	handle := s.scanTagHandle("directive", start)
	if ch := s.peek(0); ch != ' ' {
		s.fail("while scanning a directive", start, "expected ' ', but found %s", pyRepr(string(ch)))
	}
	for s.peek(0) == ' ' {
		s.forward(1)
	}
	prefix := s.scanTagURI("directive", start)
	if ch := s.peek(0); !in(ch, spaceBrkz) {
		s.fail("while scanning a directive", start, "expected ' ', but found %s", pyRepr(string(ch)))
	}
	return handle, prefix
}

func (s *scanner) scanDirectiveIgnoredLine(start Mark) {
	for s.peek(0) == ' ' {
		s.forward(1)
	}
	if s.peek(0) == '#' {
		for !in(s.peek(0), breakz) {
			s.forward(1)
		}
	}
	if ch := s.peek(0); !in(ch, breakz) {
		s.fail("while scanning a directive", start, "expected a comment or a line break, but found %s", pyRepr(string(ch)))
	}
	s.scanLineBreak()
}

func (s *scanner) scanAnchor(kind tokenKind) *token {
	start := s.mark()
	name := "anchor"
	if s.peek(0) == '*' {
		name = "alias"
	}
	s.forward(1)
	n := 0
	for isAlnumDash(s.peek(n)) {
		n++
	}
	if n == 0 {
		s.fail("while scanning an "+name, start, "expected alphabetic or numeric character, but found %s", pyRepr(string(s.peek(n))))
	}
	value := s.prefix(n)
	s.forward(n)
	if ch := s.peek(0); !in(ch, blankz+"?:,]}%@`") {
		s.fail("while scanning an "+name, start, "expected alphabetic or numeric character, but found %s", pyRepr(string(ch)))
	}
	return &token{kind: kind, value: value, start: start, end: s.mark()}
}

func (s *scanner) scanTag() *token {
	start := s.mark()
	t := &token{kind: tTag, start: start}
	ch := s.peek(1)
	switch {
	case ch == '<':
		s.forward(2)
		t.suffix = s.scanTagURI("tag", start)
		if s.peek(0) != '>' {
			s.fail("while parsing a tag", start, "expected '>', but found %s", pyRepr(string(s.peek(0))))
		}
		s.forward(1)
	case in(ch, blankz):
		t.suffix = "!"
		s.forward(1)
	default:
		n := 1
		useHandle := false
		for !in(ch, spaceBrkz) {
			if ch == '!' {
				useHandle = true
				break
			}
			n++
			ch = s.peek(n)
		}
		t.hasHandle = true
		if useHandle {
			t.handle = s.scanTagHandle("tag", start)
		} else {
			t.handle = "!"
			s.forward(1)
		}
		t.suffix = s.scanTagURI("tag", start)
	}
	if ch := s.peek(0); !in(ch, spaceBrkz) {
		s.fail("while scanning a tag", start, "expected ' ', but found %s", pyRepr(string(ch)))
	}
	t.end = s.mark()
	return t
}

func (s *scanner) scanBlockScalar(style rune) *token {
	folded := style == '>'
	var chunks []string
	start := s.mark()
	s.forward(1)
	chomping, increment := s.scanBlockScalarIndicators(start)
	s.scanBlockScalarIgnoredLine(start)

	minIndent := s.indent + 1
	if minIndent < 1 {
		minIndent = 1
	}
	var breaks []string
	var end Mark
	var indent int
	if increment == 0 {
		var maxIndent int
		breaks, maxIndent, end = s.scanBlockScalarIndentation()
		indent = max(minIndent, maxIndent)
	} else {
		indent = minIndent + increment - 1
		breaks, end = s.scanBlockScalarBreaks(indent)
	}
	lineBreak := ""

	for s.column == indent && s.peek(0) != 0 {
		chunks = append(chunks, breaks...)
		leadingNonSpace := !in(s.peek(0), " \t")
		n := 0
		for !in(s.peek(n), breakz) {
			n++
		}
		chunks = append(chunks, s.prefix(n))
		s.forward(n)
		lineBreak = s.scanLineBreak()
		breaks, end = s.scanBlockScalarBreaks(indent)
		if s.column == indent && s.peek(0) != 0 {
			if folded && lineBreak == "\n" && leadingNonSpace && !in(s.peek(0), " \t") {
				if len(breaks) == 0 {
					chunks = append(chunks, " ")
				}
			} else {
				chunks = append(chunks, lineBreak)
			}
		} else {
			break
		}
	}
	if chomping != chompStrip {
		chunks = append(chunks, lineBreak)
	}
	if chomping == chompKeep {
		chunks = append(chunks, breaks...)
	}
	return &token{kind: tScalar, value: strings.Join(chunks, ""), plain: false, start: start, end: end, style: style}
}

const (
	chompClip  = iota // None
	chompKeep         // True
	chompStrip        // False
)

func (s *scanner) scanBlockScalarIndicators(start Mark) (chomping int, increment int) {
	ch := s.peek(0)
	if in(ch, "+-") {
		chomping = chompStrip
		if ch == '+' {
			chomping = chompKeep
		}
		s.forward(1)
		ch = s.peek(0)
		if in(ch, "0123456789") {
			increment = int(ch - '0')
			if increment == 0 {
				s.fail("while scanning a block scalar", start, "expected indentation indicator in the range 1-9, but found 0")
			}
			s.forward(1)
		}
	} else if in(ch, "0123456789") {
		increment = int(ch - '0')
		if increment == 0 {
			s.fail("while scanning a block scalar", start, "expected indentation indicator in the range 1-9, but found 0")
		}
		s.forward(1)
		ch = s.peek(0)
		if in(ch, "+-") {
			chomping = chompStrip
			if ch == '+' {
				chomping = chompKeep
			}
			s.forward(1)
		}
	}
	if ch := s.peek(0); !in(ch, spaceBrkz) {
		s.fail("while scanning a block scalar", start, "expected chomping or indentation indicators, but found %s", pyRepr(string(ch)))
	}
	return chomping, increment
}

func (s *scanner) scanBlockScalarIgnoredLine(start Mark) {
	for s.peek(0) == ' ' {
		s.forward(1)
	}
	if s.peek(0) == '#' {
		for !in(s.peek(0), breakz) {
			s.forward(1)
		}
	}
	if ch := s.peek(0); !in(ch, breakz) {
		s.fail("while scanning a block scalar", start, "expected a comment or a line break, but found %s", pyRepr(string(ch)))
	}
	s.scanLineBreak()
}

func (s *scanner) scanBlockScalarIndentation() ([]string, int, Mark) {
	var chunks []string
	maxIndent := 0
	end := s.mark()
	for in(s.peek(0), " "+brk) {
		if s.peek(0) != ' ' {
			chunks = append(chunks, s.scanLineBreak())
			end = s.mark()
		} else {
			s.forward(1)
			if s.column > maxIndent {
				maxIndent = s.column
			}
		}
	}
	return chunks, maxIndent, end
}

func (s *scanner) scanBlockScalarBreaks(indent int) ([]string, Mark) {
	var chunks []string
	end := s.mark()
	for s.column < indent && s.peek(0) == ' ' {
		s.forward(1)
	}
	for in(s.peek(0), brk) {
		chunks = append(chunks, s.scanLineBreak())
		end = s.mark()
		for s.column < indent && s.peek(0) == ' ' {
			s.forward(1)
		}
	}
	return chunks, end
}

func (s *scanner) scanFlowScalar(style rune) *token {
	double := style == '"'
	var chunks []string
	start := s.mark()
	quote := s.peek(0)
	s.forward(1)
	chunks = append(chunks, s.scanFlowScalarNonSpaces(double, start)...)
	for s.peek(0) != quote {
		chunks = append(chunks, s.scanFlowScalarSpaces(double, start)...)
		chunks = append(chunks, s.scanFlowScalarNonSpaces(double, start)...)
	}
	s.forward(1)
	return &token{kind: tScalar, value: strings.Join(chunks, ""), plain: false, start: start, end: s.mark(), style: style}
}

var escapeReplacements = map[rune]string{
	'0': "\x00", 'a': "\x07", 'b': "\x08", 't': "\x09", '\t': "\x09", 'n': "\x0a",
	'v': "\x0b", 'f': "\x0c", 'r': "\x0d", 'e': "\x1b", ' ': "\x20", '"': "\"",
	'\\': "\\", '/': "/", 'N': "\u0085", '_': " ", 'L': " ", 'P': " ",
}

var escapeCodes = map[rune]int{'x': 2, 'u': 4, 'U': 8}

func (s *scanner) scanFlowScalarNonSpaces(double bool, start Mark) []string {
	var chunks []string
	for {
		n := 0
		for !in(s.peek(n), "'\"\\"+blankz) {
			n++
		}
		if n > 0 {
			chunks = append(chunks, s.prefix(n))
			s.forward(n)
		}
		ch := s.peek(0)
		switch {
		case !double && ch == '\'' && s.peek(1) == '\'':
			chunks = append(chunks, "'")
			s.forward(2)
		case (double && ch == '\'') || (!double && in(ch, "\"\\")):
			chunks = append(chunks, string(ch))
			s.forward(1)
		case double && ch == '\\':
			s.forward(1)
			ch = s.peek(0)
			if rep, ok := escapeReplacements[ch]; ok {
				chunks = append(chunks, rep)
				s.forward(1)
			} else if length, ok := escapeCodes[ch]; ok {
				s.forward(1)
				for k := 0; k < length; k++ {
					if !isHex(s.peek(k)) {
						s.fail("while scanning a double-quoted scalar", start,
							"expected escape sequence of %d hexadecimal numbers, but found %s", length, pyRepr(string(s.peek(k))))
					}
				}
				code, _ := strconv.ParseUint(s.prefix(length), 16, 32)
				if code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff) {
					// Python's chr() fails beyond U+10FFFF (1.x crashes),
					// and a lone surrogate can't be held in UTF-8.
					panic(&LimitError{fmt.Sprintf("config: \\%c escape %s is not a Unicode character", ch, s.prefix(length))})
				}
				chunks = append(chunks, string(rune(code)))
				s.forward(length)
			} else if in(ch, brk) {
				s.scanLineBreak()
				chunks = append(chunks, s.scanFlowScalarBreaks(double, start)...)
			} else {
				s.fail("while scanning a double-quoted scalar", start, "found unknown escape character %s", pyRepr(string(ch)))
			}
		default:
			return chunks
		}
	}
}

func (s *scanner) scanFlowScalarSpaces(double bool, start Mark) []string {
	var chunks []string
	n := 0
	for in(s.peek(n), " \t") {
		n++
	}
	whitespaces := s.prefix(n)
	s.forward(n)
	ch := s.peek(0)
	switch {
	case ch == 0:
		s.fail("while scanning a quoted scalar", start, "found unexpected end of stream")
	case in(ch, brk):
		lineBreak := s.scanLineBreak()
		breaks := s.scanFlowScalarBreaks(double, start)
		if lineBreak != "\n" {
			chunks = append(chunks, lineBreak)
		} else if len(breaks) == 0 {
			chunks = append(chunks, " ")
		}
		chunks = append(chunks, breaks...)
	default:
		chunks = append(chunks, whitespaces)
	}
	return chunks
}

func (s *scanner) scanFlowScalarBreaks(double bool, start Mark) []string {
	var chunks []string
	for {
		p := s.prefix(3)
		if (p == "---" || p == "...") && in(s.peek(3), blankz) {
			s.fail("while scanning a quoted scalar", start, "found unexpected document separator")
		}
		for in(s.peek(0), " \t") {
			s.forward(1)
		}
		if in(s.peek(0), brk) {
			chunks = append(chunks, s.scanLineBreak())
		} else {
			return chunks
		}
	}
}

func (s *scanner) scanPlain() *token {
	var chunks []string
	start := s.mark()
	end := start
	indent := s.indent + 1
	var spaces []string
	for {
		n := 0
		if s.peek(0) == '#' {
			break
		}
		for {
			ch := s.peek(n)
			follow := blankz
			if s.flowLevel != 0 {
				follow += ",[]{}"
			}
			if in(ch, blankz) || (ch == ':' && in(s.peek(n+1), follow)) || (s.flowLevel != 0 && in(ch, ",?[]{}")) {
				break
			}
			n++
		}
		if n == 0 {
			break
		}
		s.allowSimpleKey = false
		chunks = append(chunks, spaces...)
		chunks = append(chunks, s.prefix(n))
		s.forward(n)
		end = s.mark()
		var ok bool
		spaces, ok = s.scanPlainSpaces(indent, start)
		if !ok || len(spaces) == 0 || s.peek(0) == '#' || (s.flowLevel == 0 && s.column < indent) {
			break
		}
	}
	return &token{kind: tScalar, value: strings.Join(chunks, ""), plain: true, start: start, end: end}
}

// scanPlainSpaces returns ok false for Python's None (a document
// separator follows).
func (s *scanner) scanPlainSpaces(indent int, start Mark) ([]string, bool) {
	var chunks []string
	n := 0
	for s.peek(n) == ' ' {
		n++
	}
	whitespaces := s.prefix(n)
	s.forward(n)
	ch := s.peek(0)
	if in(ch, brk) {
		lineBreak := s.scanLineBreak()
		s.allowSimpleKey = true
		separator := func() bool {
			p := s.prefix(3)
			return (p == "---" || p == "...") && in(s.peek(3), blankz)
		}
		if separator() {
			return nil, false
		}
		var breaks []string
		for in(s.peek(0), " "+brk) {
			if s.peek(0) == ' ' {
				s.forward(1)
			} else {
				breaks = append(breaks, s.scanLineBreak())
				if separator() {
					return nil, false
				}
			}
		}
		if lineBreak != "\n" {
			chunks = append(chunks, lineBreak)
		} else if len(breaks) == 0 {
			chunks = append(chunks, " ")
		}
		chunks = append(chunks, breaks...)
	} else if whitespaces != "" {
		chunks = append(chunks, whitespaces)
	}
	return chunks, true
}

func (s *scanner) scanTagHandle(name string, start Mark) string {
	ch := s.peek(0)
	if ch != '!' {
		s.fail("while scanning a "+name, start, "expected '!', but found %s", pyRepr(string(ch)))
	}
	n := 1
	ch = s.peek(n)
	if ch != ' ' {
		for isAlnumDash(ch) {
			n++
			ch = s.peek(n)
		}
		if ch != '!' {
			s.forward(n)
			s.fail("while scanning a "+name, start, "expected '!', but found %s", pyRepr(string(ch)))
		}
		n++
	}
	value := s.prefix(n)
	s.forward(n)
	return value
}

func (s *scanner) scanTagURI(name string, start Mark) string {
	var chunks []string
	n := 0
	ch := s.peek(n)
	for isAlnumDash(ch) || in(ch, "-;/?:@&=+$,_.!~*'()[]%") {
		if ch == '%' {
			chunks = append(chunks, s.prefix(n))
			s.forward(n)
			n = 0
			chunks = append(chunks, s.scanURIEscapes(name, start))
		} else {
			n++
		}
		ch = s.peek(n)
	}
	if n > 0 {
		chunks = append(chunks, s.prefix(n))
		s.forward(n)
	}
	if len(chunks) == 0 {
		s.fail("while parsing a "+name, start, "expected URI, but found %s", pyRepr(string(ch)))
	}
	return strings.Join(chunks, "")
}

func (s *scanner) scanURIEscapes(name string, start Mark) string {
	var codes []byte
	m := s.mark()
	for s.peek(0) == '%' {
		s.forward(1)
		for k := 0; k < 2; k++ {
			if !isHex(s.peek(k)) {
				s.fail("while scanning a "+name, start,
					"expected URI escape sequence of 2 hexadecimal numbers, but found %s", pyRepr(string(s.peek(k))))
			}
		}
		c, _ := strconv.ParseUint(s.prefix(2), 16, 8)
		codes = append(codes, byte(c))
		s.forward(2)
	}
	if msg := utf8DecodeError(codes); msg != "" {
		panic(Errorf("while scanning a "+name, start, m, "%s", msg))
	}
	return string(codes)
}

// utf8DecodeError is str() of the UnicodeDecodeError Python's strict
// UTF-8 decoder raises for b, or "" when b decodes.
func utf8DecodeError(b []byte) string {
	for i := 0; i < len(b); {
		n, reason := utf8Seq(b[i:])
		if reason != "" {
			end := i + n
			if n <= 1 {
				return fmt.Sprintf("'utf-8' codec can't decode byte 0x%02x in position %d: %s", b[i], i, reason)
			}
			return fmt.Sprintf("'utf-8' codec can't decode bytes in position %d-%d: %s", i, end-1, reason)
		}
		i += n
	}
	return ""
}

// utf8Seq is the length of the sequence at the start of b, or the
// length of the bad part and CPython's reason.
func utf8Seq(b []byte) (int, string) {
	c := b[0]
	switch {
	case c < 0x80:
		return 1, ""
	case c < 0xc2 || c > 0xf4:
		return 1, "invalid start byte"
	}
	need := 1
	lo, hi := byte(0x80), byte(0xbf)
	switch {
	case c >= 0xf0:
		need = 3
		if c == 0xf0 {
			lo = 0x90
		} else if c == 0xf4 {
			hi = 0x8f
		}
	case c >= 0xe0:
		need = 2
		if c == 0xe0 {
			lo = 0xa0
		} else if c == 0xed {
			hi = 0x9f
		}
	}
	for k := 1; k <= need; k++ {
		if k >= len(b) {
			return k, "unexpected end of data"
		}
		if b[k] < lo || b[k] > hi {
			return k, "invalid continuation byte"
		}
		lo, hi = 0x80, 0xbf
	}
	return need + 1, ""
}

func (s *scanner) scanLineBreak() string {
	ch := s.peek(0)
	if in(ch, "\r\n\u0085") {
		if s.prefix(2) == "\r\n" {
			s.forward(2)
		} else {
			s.forward(1)
		}
		return "\n"
	}
	if ch == 0x2028 || ch == 0x2029 {
		s.forward(1)
		return string(ch)
	}
	return ""
}
