package pyyaml

import (
	"fmt"
	"strings"
)

// The serializer and emitter (yaml.serializer.Serializer and
// yaml.emitter.Emitter of PyYAML 6.0.1) with yaml.safe_dump's settings:
// block style, indent 2, width 80, allow_unicode off, no explicit
// document start or end, "\n" line breaks. 1.x writes config.yaml with
// safe_dump when the webUI address moves (ROADMAP SEC-27), so FR_OS 2
// writes the same text, byte for byte.
//
// Only what a representer of safe_load's values hands it is here: a
// scalar's Style is 0 (PyYAML's None: the emitter picks plain, single-
// or double-quoted), and no collection asks for flow style (only an
// empty one is written in flow style, as PyYAML does). The block scalar
// styles (| and >) are what safe_dump uses for bytes alone, which no
// config value is (decisions.md).

const (
	bestIndent = 2
	bestWidth  = 80
)

// Dump is the text the serializer and emitter write for the node graph
// at root. A node reached twice (the same *Node) is written once with an
// anchor and then as an alias, as PyYAML's serializer does for the same
// Python object.
func Dump(root *Node) (string, error) {
	s := &serializer{anchors: map[*Node]string{}, seen: map[*Node]bool{}}
	s.anchorNode(root)
	s.events = append(s.events, &event{kind: eStreamStart}, &event{kind: eDocumentStart})
	s.serializeNode(root)
	s.events = append(s.events, &event{kind: eDocumentEnd}, &event{kind: eStreamEnd})
	e := &emitter{indent: -1, whitespace: true, indention: true, style: styleNone}
	e.state = e.expectStreamStart
	for i, ev := range s.events {
		e.ev, e.next = ev, s.events[i+1:]
		if err := e.run(); err != nil {
			return "", err
		}
	}
	return e.out.String(), nil
}

// --- serializer ---------------------------------------------------------------

type serializer struct {
	anchors    map[*Node]string // "" until the node is met a second time
	seen       map[*Node]bool
	lastAnchor int
	events     []*event
}

func (s *serializer) anchorNode(n *Node) {
	if a, ok := s.anchors[n]; ok {
		if a == "" {
			s.lastAnchor++
			s.anchors[n] = fmt.Sprintf("id%03d", s.lastAnchor)
		}
		return
	}
	s.anchors[n] = ""
	switch n.Kind {
	case SequenceNode:
		for _, item := range n.Items {
			s.anchorNode(item)
		}
	case MappingNode:
		for _, p := range n.Pairs {
			s.anchorNode(p[0])
			s.anchorNode(p[1])
		}
	}
}

func (s *serializer) serializeNode(n *Node) {
	anchor := s.anchors[n]
	if s.seen[n] {
		s.events = append(s.events, &event{kind: eAlias, anchor: anchor, hasAnchor: true})
		return
	}
	s.seen[n] = true
	switch n.Kind {
	case ScalarNode:
		implicit := [2]bool{n.Tag == resolveScalar(n.Value, true), n.Tag == resolveScalar(n.Value, false)}
		s.events = append(s.events, &event{kind: eScalar, anchor: anchor, hasAnchor: anchor != "",
			tag: n.Tag, hasTag: true, implicit: implicit, value: n.Value, style: n.Style})
	case SequenceNode:
		s.events = append(s.events, &event{kind: eSequenceStart, anchor: anchor, hasAnchor: anchor != "",
			tag: n.Tag, hasTag: true, implicit: [2]bool{n.Tag == yamlSeq}})
		for _, item := range n.Items {
			s.serializeNode(item)
		}
		s.events = append(s.events, &event{kind: eSequenceEnd})
	case MappingNode:
		s.events = append(s.events, &event{kind: eMappingStart, anchor: anchor, hasAnchor: anchor != "",
			tag: n.Tag, hasTag: true, implicit: [2]bool{n.Tag == yamlMap}})
		for _, p := range n.Pairs {
			s.serializeNode(p[0])
			s.serializeNode(p[1])
		}
		s.events = append(s.events, &event{kind: eMappingEnd})
	}
}

const (
	yamlSeq = "tag:yaml.org,2002:seq"
	yamlMap = "tag:yaml.org,2002:map"
)

// --- emitter ------------------------------------------------------------------

// The scalar style the emitter chose: none yet, plain, or quoted.
const (
	styleNone  rune = -1
	stylePlain rune = 0
)

type analysis struct {
	scalar                          []rune
	empty, multiline                bool
	allowFlowPlain, allowBlockPlain bool
	allowSingleQuoted, allowBlock   bool
}

type emitter struct {
	out    strings.Builder
	ev     *event
	next   []*event // the events after ev, all already known
	state  func() error
	states []func() error

	indents []int
	indent  int // -1 is PyYAML's None

	flowLevel                                      int
	rootCtx, sequenceCtx, mappingCtx, simpleKeyCtx bool

	line, column          int
	whitespace, indention bool
	openEnded             bool

	preparedAnchor, preparedTag *string
	analysis                    *analysis
	style                       rune
}

type emitterError struct{ msg string }

func (e *emitterError) Error() string { return e.msg }

func (e *emitter) run() error { return e.state() }

func (e *emitter) pushState(f func() error) { e.states = append(e.states, f) }

func (e *emitter) popState() func() error {
	f := e.states[len(e.states)-1]
	e.states = e.states[:len(e.states)-1]
	return f
}

func (e *emitter) popIndent() {
	e.indent = e.indents[len(e.indents)-1]
	e.indents = e.indents[:len(e.indents)-1]
}

func (e *emitter) increaseIndent(flow, indentless bool) {
	e.indents = append(e.indents, e.indent)
	if e.indent < 0 {
		if flow {
			e.indent = bestIndent
		} else {
			e.indent = 0
		}
	} else if !indentless {
		e.indent += bestIndent
	}
}

func (e *emitter) nextKind() (eventKind, bool) {
	if len(e.next) == 0 {
		return 0, false
	}
	return e.next[0].kind, true
}

// Stream and document handlers.

func (e *emitter) expectStreamStart() error {
	if e.ev.kind != eStreamStart {
		return &emitterError{"expected StreamStartEvent"}
	}
	e.state = e.expectFirstDocumentStart
	return nil
}

func (e *emitter) expectNothing() error { return &emitterError{"expected nothing"} }

func (e *emitter) expectFirstDocumentStart() error { return e.expectDocumentStart(true) }

func (e *emitter) expectDocumentStart(first bool) error {
	switch e.ev.kind {
	case eDocumentStart:
		if !first || e.checkEmptyDocument() {
			e.writeIndent()
			e.writeIndicator("---", true, false, false)
		}
		e.state = e.expectDocumentRoot
	case eStreamEnd:
		if e.openEnded {
			e.writeIndicator("...", true, false, false)
			e.writeIndent()
		}
		e.state = e.expectNothing
	default:
		return &emitterError{"expected DocumentStartEvent"}
	}
	return nil
}

func (e *emitter) expectDocumentEnd() error {
	if e.ev.kind != eDocumentEnd {
		return &emitterError{"expected DocumentEndEvent"}
	}
	e.writeIndent()
	e.state = func() error { return e.expectDocumentStart(false) }
	return nil
}

func (e *emitter) expectDocumentRoot() error {
	e.pushState(e.expectDocumentEnd)
	return e.expectNode(true, false, false, false)
}

// Node handlers.

func (e *emitter) expectNode(root, sequence, mapping, simpleKey bool) error {
	e.rootCtx, e.sequenceCtx, e.mappingCtx, e.simpleKeyCtx = root, sequence, mapping, simpleKey
	switch e.ev.kind {
	case eAlias:
		return e.expectAlias()
	case eScalar, eSequenceStart, eMappingStart:
		if err := e.processAnchor("&"); err != nil {
			return err
		}
		if err := e.processTag(); err != nil {
			return err
		}
		switch e.ev.kind {
		case eScalar:
			e.expectScalar()
		case eSequenceStart:
			if e.flowLevel > 0 || e.checkEmptySequence() {
				e.expectFlowSequence()
			} else {
				e.expectBlockSequence()
			}
		case eMappingStart:
			if e.flowLevel > 0 || e.checkEmptyMapping() {
				e.expectFlowMapping()
			} else {
				e.expectBlockMapping()
			}
		}
		return nil
	}
	return &emitterError{"expected NodeEvent"}
}

func (e *emitter) expectAlias() error {
	if !e.ev.hasAnchor {
		return &emitterError{"anchor is not specified for alias"}
	}
	if err := e.processAnchor("*"); err != nil {
		return err
	}
	e.state = e.popState()
	return nil
}

func (e *emitter) expectScalar() {
	e.increaseIndent(true, false)
	e.processScalar()
	e.popIndent()
	e.state = e.popState()
}

// Flow sequence and mapping handlers: only an empty one gets here.

func (e *emitter) expectFlowSequence() {
	e.writeIndicator("[", true, true, false)
	e.flowLevel++
	e.increaseIndent(true, false)
	e.state = e.expectFirstFlowSequenceItem
}

func (e *emitter) expectFirstFlowSequenceItem() error {
	if e.ev.kind == eSequenceEnd {
		e.popIndent()
		e.flowLevel--
		e.writeIndicator("]", false, false, false)
		e.state = e.popState()
		return nil
	}
	if e.column > bestWidth {
		e.writeIndent()
	}
	e.pushState(e.expectFlowSequenceItem)
	return e.expectNode(false, true, false, false)
}

func (e *emitter) expectFlowSequenceItem() error {
	if e.ev.kind == eSequenceEnd {
		e.popIndent()
		e.flowLevel--
		e.writeIndicator("]", false, false, false)
		e.state = e.popState()
		return nil
	}
	e.writeIndicator(",", false, false, false)
	if e.column > bestWidth {
		e.writeIndent()
	}
	e.pushState(e.expectFlowSequenceItem)
	return e.expectNode(false, true, false, false)
}

func (e *emitter) expectFlowMapping() {
	e.writeIndicator("{", true, true, false)
	e.flowLevel++
	e.increaseIndent(true, false)
	e.state = func() error { return e.expectFlowMappingKey(true) }
}

func (e *emitter) expectFlowMappingKey(first bool) error {
	if e.ev.kind == eMappingEnd {
		e.popIndent()
		e.flowLevel--
		e.writeIndicator("}", false, false, false)
		e.state = e.popState()
		return nil
	}
	if !first {
		e.writeIndicator(",", false, false, false)
	}
	if e.column > bestWidth {
		e.writeIndent()
	}
	simple, err := e.checkSimpleKey()
	if err != nil {
		return err
	}
	if simple {
		e.pushState(e.expectFlowMappingSimpleValue)
		return e.expectNode(false, false, true, true)
	}
	e.writeIndicator("?", true, false, false)
	e.pushState(e.expectFlowMappingValue)
	return e.expectNode(false, false, true, false)
}

func (e *emitter) expectFlowMappingSimpleValue() error {
	e.writeIndicator(":", false, false, false)
	e.pushState(func() error { return e.expectFlowMappingKey(false) })
	return e.expectNode(false, false, true, false)
}

func (e *emitter) expectFlowMappingValue() error {
	if e.column > bestWidth {
		e.writeIndent()
	}
	e.writeIndicator(":", true, false, false)
	e.pushState(func() error { return e.expectFlowMappingKey(false) })
	return e.expectNode(false, false, true, false)
}

// Block sequence and mapping handlers.

func (e *emitter) expectBlockSequence() {
	indentless := e.mappingCtx && !e.indention
	e.increaseIndent(false, indentless)
	e.state = func() error { return e.expectBlockSequenceItem(true) }
}

func (e *emitter) expectBlockSequenceItem(first bool) error {
	if !first && e.ev.kind == eSequenceEnd {
		e.popIndent()
		e.state = e.popState()
		return nil
	}
	e.writeIndent()
	e.writeIndicator("-", true, false, true)
	e.pushState(func() error { return e.expectBlockSequenceItem(false) })
	return e.expectNode(false, true, false, false)
}

func (e *emitter) expectBlockMapping() {
	e.increaseIndent(false, false)
	e.state = func() error { return e.expectBlockMappingKey(true) }
}

func (e *emitter) expectBlockMappingKey(first bool) error {
	if !first && e.ev.kind == eMappingEnd {
		e.popIndent()
		e.state = e.popState()
		return nil
	}
	e.writeIndent()
	simple, err := e.checkSimpleKey()
	if err != nil {
		return err
	}
	if simple {
		e.pushState(e.expectBlockMappingSimpleValue)
		return e.expectNode(false, false, true, true)
	}
	e.writeIndicator("?", true, false, true)
	e.pushState(e.expectBlockMappingValue)
	return e.expectNode(false, false, true, false)
}

func (e *emitter) expectBlockMappingSimpleValue() error {
	e.writeIndicator(":", false, false, false)
	e.pushState(func() error { return e.expectBlockMappingKey(false) })
	return e.expectNode(false, false, true, false)
}

func (e *emitter) expectBlockMappingValue() error {
	e.writeIndent()
	e.writeIndicator(":", true, false, true)
	e.pushState(func() error { return e.expectBlockMappingKey(false) })
	return e.expectNode(false, false, true, false)
}

// Checkers.

func (e *emitter) checkEmptySequence() bool {
	k, ok := e.nextKind()
	return e.ev.kind == eSequenceStart && ok && k == eSequenceEnd
}

func (e *emitter) checkEmptyMapping() bool {
	k, ok := e.nextKind()
	return e.ev.kind == eMappingStart && ok && k == eMappingEnd
}

func (e *emitter) checkEmptyDocument() bool {
	if e.ev.kind != eDocumentStart || len(e.next) == 0 {
		return false
	}
	n := e.next[0]
	return n.kind == eScalar && !n.hasAnchor && !n.hasTag && n.value == ""
}

func (e *emitter) checkSimpleKey() (bool, error) {
	length := 0
	ev := e.ev
	if ev.kind == eAlias || ev.kind == eScalar || ev.kind == eSequenceStart || ev.kind == eMappingStart {
		if ev.hasAnchor {
			if e.preparedAnchor == nil {
				a, err := prepareAnchor(ev.anchor)
				if err != nil {
					return false, err
				}
				e.preparedAnchor = &a
			}
			length += len([]rune(*e.preparedAnchor))
		}
	}
	if (ev.kind == eScalar || ev.kind == eSequenceStart || ev.kind == eMappingStart) && ev.hasTag {
		if e.preparedTag == nil {
			t, err := prepareTag(ev.tag)
			if err != nil {
				return false, err
			}
			e.preparedTag = &t
		}
		length += len([]rune(*e.preparedTag))
	}
	if ev.kind == eScalar {
		if e.analysis == nil {
			e.analysis = analyzeScalar(ev.value)
		}
		length += len(e.analysis.scalar)
	}
	return length < 128 && (ev.kind == eAlias ||
		(ev.kind == eScalar && !e.analysis.empty && !e.analysis.multiline) ||
		e.checkEmptySequence() || e.checkEmptyMapping()), nil
}

// Anchor, tag and scalar processors.

func (e *emitter) processAnchor(indicator string) error {
	if !e.ev.hasAnchor {
		e.preparedAnchor = nil
		return nil
	}
	if e.preparedAnchor == nil {
		a, err := prepareAnchor(e.ev.anchor)
		if err != nil {
			return err
		}
		e.preparedAnchor = &a
	}
	if *e.preparedAnchor != "" {
		e.writeIndicator(indicator+*e.preparedAnchor, true, false, false)
	}
	e.preparedAnchor = nil
	return nil
}

func (e *emitter) processTag() error {
	tag, hasTag := e.ev.tag, e.ev.hasTag
	if e.ev.kind == eScalar {
		if e.style == styleNone {
			e.style = e.chooseScalarStyle()
		}
		if (e.style == stylePlain && e.ev.implicit[0]) || (e.style != stylePlain && e.ev.implicit[1]) {
			e.preparedTag = nil
			return nil
		}
		if e.ev.implicit[0] && !hasTag {
			tag, hasTag = "!", true
			e.preparedTag = nil
		}
	} else if e.ev.implicit[0] {
		e.preparedTag = nil
		return nil
	}
	if !hasTag {
		return &emitterError{"tag is not specified"}
	}
	if e.preparedTag == nil {
		t, err := prepareTag(tag)
		if err != nil {
			return err
		}
		e.preparedTag = &t
	}
	if *e.preparedTag != "" {
		e.writeIndicator(*e.preparedTag, true, false, false)
	}
	e.preparedTag = nil
	return nil
}

func (e *emitter) chooseScalarStyle() rune {
	if e.analysis == nil {
		e.analysis = analyzeScalar(e.ev.value)
	}
	a, style := e.analysis, e.ev.style
	if style == '"' {
		return '"'
	}
	if style == 0 && e.ev.implicit[0] {
		if !(e.simpleKeyCtx && (a.empty || a.multiline)) &&
			((e.flowLevel > 0 && a.allowFlowPlain) || (e.flowLevel == 0 && a.allowBlockPlain)) {
			return stylePlain
		}
	}
	if style == 0 || style == '\'' {
		if a.allowSingleQuoted && !(e.simpleKeyCtx && a.multiline) {
			return '\''
		}
	}
	return '"'
}

func (e *emitter) processScalar() {
	if e.analysis == nil {
		e.analysis = analyzeScalar(e.ev.value)
	}
	if e.style == styleNone {
		e.style = e.chooseScalarStyle()
	}
	split := !e.simpleKeyCtx
	switch e.style {
	case '"':
		e.writeDoubleQuoted(e.analysis.scalar, split)
	case '\'':
		e.writeSingleQuoted(e.analysis.scalar, split)
	default:
		e.writePlain(e.analysis.scalar, split)
	}
	e.analysis = nil
	e.style = styleNone
}

func alnum(r rune) bool { return '0' <= r && r <= '9' || 'A' <= r && r <= 'Z' || 'a' <= r && r <= 'z' }

func prepareAnchor(anchor string) (string, error) {
	if anchor == "" {
		return "", &emitterError{"anchor must not be empty"}
	}
	for _, r := range anchor {
		if !alnum(r) && r != '-' && r != '_' {
			return "", &emitterError{fmt.Sprintf("invalid character %s in the anchor: %s", pyRepr(string(r)), pyRepr(anchor))}
		}
	}
	return anchor, nil
}

// prepareTag writes a tag with the default handles: "!" and "!!" for
// tag:yaml.org,2002:, as safe_dump has no %TAG directives.
func prepareTag(tag string) (string, error) {
	if tag == "" {
		return "", &emitterError{"tag must not be empty"}
	}
	if tag == "!" {
		return tag, nil
	}
	handle, suffix := "", tag
	for _, p := range [...]struct{ prefix, handle string }{{"!", "!"}, {"tag:yaml.org,2002:", "!!"}} {
		if strings.HasPrefix(tag, p.prefix) && (p.prefix == "!" || len(p.prefix) < len(tag)) {
			handle, suffix = p.handle, tag[len(p.prefix):]
		}
	}
	var b strings.Builder
	for _, r := range suffix {
		if alnum(r) || strings.ContainsRune("-;/?:@&=+$,_.~*'()[]", r) || (r == '!' && handle != "!") {
			b.WriteRune(r)
		} else {
			for _, c := range []byte(string(r)) {
				fmt.Fprintf(&b, "%%%02X", c)
			}
		}
	}
	if handle != "" {
		return handle + b.String(), nil
	}
	return "!<" + b.String() + ">", nil
}

const lineBreaks = "\n\u0085\u2028\u2029"

func isBreak(r rune) bool { return strings.ContainsRune(lineBreaks, r) }

// whitespaceOrNul is '\0 \t\r\n\x85\u2028\u2029'.
func whitespaceOrNul(r rune) bool {
	return r == 0 || strings.ContainsRune(" \t\r\n\u0085\u2028\u2029", r)
}

func analyzeScalar(value string) *analysis {
	scalar := []rune(value)
	if len(scalar) == 0 {
		return &analysis{scalar: scalar, empty: true, allowBlockPlain: true, allowSingleQuoted: true}
	}
	var blockIndicators, flowIndicators, lineBreaksSeen, specialCharacters bool
	var leadingSpace, leadingBreak, trailingSpace, trailingBreak, breakSpace, spaceBreak bool
	if strings.HasPrefix(value, "---") || strings.HasPrefix(value, "...") {
		blockIndicators, flowIndicators = true, true
	}
	precededByWhitespace := true
	followedByWhitespace := len(scalar) == 1 || whitespaceOrNul(scalar[1])
	previousSpace, previousBreak := false, false
	for index := 0; index < len(scalar); {
		ch := scalar[index]
		if index == 0 {
			if strings.ContainsRune("#,[]{}&*!|>'\"%@`", ch) {
				flowIndicators, blockIndicators = true, true
			}
			if ch == '?' || ch == ':' {
				flowIndicators = true
				if followedByWhitespace {
					blockIndicators = true
				}
			}
			if ch == '-' && followedByWhitespace {
				flowIndicators, blockIndicators = true, true
			}
		} else {
			if strings.ContainsRune(",?[]{}", ch) {
				flowIndicators = true
			}
			if ch == ':' {
				flowIndicators = true
				if followedByWhitespace {
					blockIndicators = true
				}
			}
			if ch == '#' && precededByWhitespace {
				flowIndicators, blockIndicators = true, true
			}
		}
		if isBreak(ch) {
			lineBreaksSeen = true
		}
		if !(ch == '\n' || 0x20 <= ch && ch <= 0x7e) {
			// allow_unicode is off: every other character is special
			// (it is written escaped, double-quoted).
			specialCharacters = true
		}
		switch {
		case ch == ' ':
			if index == 0 {
				leadingSpace = true
			}
			if index == len(scalar)-1 {
				trailingSpace = true
			}
			if previousBreak {
				breakSpace = true
			}
			previousSpace, previousBreak = true, false
		case isBreak(ch):
			if index == 0 {
				leadingBreak = true
			}
			if index == len(scalar)-1 {
				trailingBreak = true
			}
			if previousSpace {
				spaceBreak = true
			}
			previousSpace, previousBreak = false, true
		default:
			previousSpace, previousBreak = false, false
		}
		index++
		precededByWhitespace = whitespaceOrNul(ch)
		followedByWhitespace = index+1 >= len(scalar) || whitespaceOrNul(scalar[index+1])
	}
	a := &analysis{scalar: scalar, multiline: lineBreaksSeen,
		allowFlowPlain: true, allowBlockPlain: true, allowSingleQuoted: true, allowBlock: true}
	if leadingSpace || leadingBreak || trailingSpace || trailingBreak {
		a.allowFlowPlain, a.allowBlockPlain = false, false
	}
	if trailingSpace {
		a.allowBlock = false
	}
	if breakSpace {
		a.allowFlowPlain, a.allowBlockPlain, a.allowSingleQuoted = false, false, false
	}
	if spaceBreak || specialCharacters {
		a.allowFlowPlain, a.allowBlockPlain, a.allowSingleQuoted, a.allowBlock = false, false, false, false
	}
	if lineBreaksSeen {
		a.allowFlowPlain, a.allowBlockPlain = false, false
	}
	if flowIndicators {
		a.allowFlowPlain = false
	}
	if blockIndicators {
		a.allowBlockPlain = false
	}
	return a
}

// Writers.

func (e *emitter) write(data string) {
	e.column += len([]rune(data))
	e.out.WriteString(data)
}

func (e *emitter) writeIndicator(indicator string, needWhitespace, whitespace, indention bool) {
	data := indicator
	if !e.whitespace && needWhitespace {
		data = " " + indicator
	}
	e.whitespace = whitespace
	e.indention = e.indention && indention
	e.openEnded = false
	e.write(data)
}

func (e *emitter) writeIndent() {
	indent := max(e.indent, 0)
	if !e.indention || e.column > indent || (e.column == indent && !e.whitespace) {
		e.writeLineBreak("\n")
	}
	if e.column < indent {
		e.whitespace = true
		e.out.WriteString(strings.Repeat(" ", indent-e.column))
		e.column = indent
	}
}

func (e *emitter) writeLineBreak(data string) {
	e.whitespace, e.indention = true, true
	e.line++
	e.column = 0
	e.out.WriteString(data)
}

// writeBreaks writes each line break in text as itself.
func (e *emitter) writeBreaks(text []rune) {
	for _, br := range text {
		e.writeLineBreak(string(br))
	}
}

func (e *emitter) writeSingleQuoted(text []rune, split bool) {
	e.writeIndicator("'", true, false, false)
	spaces, breaks := false, false
	start, end := 0, 0
	for end <= len(text) {
		var ch rune = -1
		if end < len(text) {
			ch = text[end]
		}
		switch {
		case spaces:
			if ch != ' ' {
				if start+1 == end && e.column > bestWidth && split && start != 0 && end != len(text) {
					e.writeIndent()
				} else {
					e.write(string(text[start:end]))
				}
				start = end
			}
		case breaks:
			if ch < 0 || !isBreak(ch) {
				if text[start] == '\n' {
					e.writeLineBreak("\n")
				}
				e.writeBreaks(text[start:end])
				e.writeIndent()
				start = end
			}
		default:
			if ch < 0 || ch == ' ' || isBreak(ch) || ch == '\'' {
				if start < end {
					e.write(string(text[start:end]))
					start = end
				}
			}
		}
		if ch == '\'' {
			e.write("''")
			start = end + 1
		}
		if ch >= 0 {
			spaces, breaks = ch == ' ', isBreak(ch)
		}
		end++
	}
	e.writeIndicator("'", false, false, false)
}

var emitEscapes = map[rune]string{
	0: "0", 0x07: "a", 0x08: "b", 0x09: "t", 0x0a: "n", 0x0b: "v", 0x0c: "f", 0x0d: "r", 0x1b: "e",
	'"': "\"", '\\': "\\", 0x85: "N", 0xa0: "_", 0x2028: "L", 0x2029: "P",
}

func (e *emitter) writeDoubleQuoted(text []rune, split bool) {
	e.writeIndicator("\"", true, false, false)
	start, end := 0, 0
	for end <= len(text) {
		var ch rune = -1
		if end < len(text) {
			ch = text[end]
		}
		// allow_unicode is off: only printable ASCII is written as it is.
		if ch < 0 || strings.ContainsRune("\"\\\u0085\u2028\u2029\ufeff", ch) || !(0x20 <= ch && ch <= 0x7e) {
			if start < end {
				e.write(string(text[start:end]))
				start = end
			}
			if ch >= 0 {
				var data string
				if r, ok := emitEscapes[ch]; ok {
					data = "\\" + r
				} else if ch <= 0xff {
					data = fmt.Sprintf("\\x%02X", ch)
				} else if ch <= 0xffff {
					data = fmt.Sprintf("\\u%04X", ch)
				} else {
					data = fmt.Sprintf("\\U%08X", ch)
				}
				e.write(data)
				start = end + 1
			}
		}
		if 0 < end && end < len(text)-1 && (ch == ' ' || start >= end) && e.column+(end-start) > bestWidth && split {
			data := "\\" // text[start:end] is empty in Python when start > end
			if start < end {
				data = string(text[start:end]) + data
				start = end
			}
			e.write(data)
			e.writeIndent()
			e.whitespace, e.indention = false, false
			if text[start] == ' ' {
				e.write("\\")
			}
		}
		end++
	}
	e.writeIndicator("\"", false, false, false)
}

func (e *emitter) writePlain(text []rune, split bool) {
	if e.rootCtx {
		e.openEnded = true
	}
	if len(text) == 0 {
		return
	}
	if !e.whitespace {
		e.write(" ")
	}
	e.whitespace, e.indention = false, false
	spaces, breaks := false, false
	start, end := 0, 0
	for end <= len(text) {
		var ch rune = -1
		if end < len(text) {
			ch = text[end]
		}
		switch {
		case spaces:
			if ch != ' ' {
				if start+1 == end && e.column > bestWidth && split {
					e.writeIndent()
					e.whitespace, e.indention = false, false
				} else {
					e.write(string(text[start:end]))
				}
				start = end
			}
		case breaks:
			// Never reached: a scalar with a line break is never plain.
			if ch < 0 || !isBreak(ch) {
				if text[start] == '\n' {
					e.writeLineBreak("\n")
				}
				e.writeBreaks(text[start:end])
				e.writeIndent()
				e.whitespace, e.indention = false, false
				start = end
			}
		default:
			if ch < 0 || ch == ' ' || isBreak(ch) {
				e.write(string(text[start:end]))
				start = end
			}
		}
		if ch >= 0 {
			spaces, breaks = ch == ' ', isBreak(ch)
		}
		end++
	}
}
