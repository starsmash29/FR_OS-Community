package pyyaml

// The parser (yaml.parser.Parser): tokens to events, state for state.

type eventKind int

const (
	eStreamStart eventKind = iota
	eStreamEnd
	eDocumentStart
	eDocumentEnd
	eAlias
	eScalar
	eSequenceStart
	eSequenceEnd
	eMappingStart
	eMappingEnd
)

type event struct {
	kind       eventKind
	start, end Mark
	anchor     string
	hasAnchor  bool
	tag        string
	hasTag     bool
	// implicit is (implicit[0], implicit[1]) for a scalar; implicit[0]
	// alone for a collection.
	implicit [2]bool
	value    string
	style    rune
}

var defaultTags = map[string]string{"!": "!", "!!": "tag:yaml.org,2002:"}

type parser struct {
	*scanner
	current     *event
	tagHandles  map[string]string
	states      []func() *event
	marks       []Mark
	state       func() *event
	yamlVersion bool
}

func newParser(s *scanner) *parser {
	p := &parser{scanner: s}
	p.state = p.parseStreamStart
	return p
}

func (p *parser) checkEvent(kinds ...eventKind) bool {
	if p.current == nil && p.state != nil {
		p.current = p.state()
	}
	if p.current != nil {
		if len(kinds) == 0 {
			return true
		}
		for _, k := range kinds {
			if p.current.kind == k {
				return true
			}
		}
	}
	return false
}

func (p *parser) peekEvent() *event {
	if p.current == nil && p.state != nil {
		p.current = p.state()
	}
	return p.current
}

func (p *parser) getEvent() *event {
	if p.current == nil && p.state != nil {
		p.current = p.state()
	}
	e := p.current
	p.current = nil
	return e
}

func (p *parser) push(f func() *event) { p.states = append(p.states, f) }

func (p *parser) pop() func() *event {
	f := p.states[len(p.states)-1]
	p.states = p.states[:len(p.states)-1]
	return f
}

func (p *parser) popMark() { p.marks = p.marks[:len(p.marks)-1] }

func (p *parser) parseStreamStart() *event {
	t := p.getToken()
	p.state = p.parseImplicitDocumentStart
	return &event{kind: eStreamStart, start: t.start, end: t.end}
}

func (p *parser) parseImplicitDocumentStart() *event {
	if !p.checkToken(tDirective, tDocumentStart, tStreamEnd) {
		p.tagHandles = defaultTags
		t := p.peekToken()
		p.push(p.parseDocumentEnd)
		p.state = p.parseBlockNode
		return &event{kind: eDocumentStart, start: t.start, end: t.start}
	}
	return p.parseDocumentStart()
}

func (p *parser) parseDocumentStart() *event {
	for p.checkToken(tDocumentEnd) {
		p.getToken()
	}
	if !p.checkToken(tStreamEnd) {
		start := p.peekToken().start
		p.processDirectives()
		if !p.checkToken(tDocumentStart) {
			t := p.peekToken()
			panic(Errorf("", Mark{}, t.start, "expected '<document start>', but found %s", pyRepr(t.id())))
		}
		t := p.getToken()
		p.push(p.parseDocumentEnd)
		p.state = p.parseDocumentContent
		return &event{kind: eDocumentStart, start: start, end: t.end}
	}
	t := p.getToken()
	p.state = nil
	return &event{kind: eStreamEnd, start: t.start, end: t.end}
}

func (p *parser) parseDocumentEnd() *event {
	t := p.peekToken()
	start, end := t.start, t.start
	if p.checkToken(tDocumentEnd) {
		end = p.getToken().end
	}
	p.state = p.parseDocumentStart
	return &event{kind: eDocumentEnd, start: start, end: end}
}

func (p *parser) parseDocumentContent() *event {
	if p.checkToken(tDirective, tDocumentStart, tDocumentEnd, tStreamEnd) {
		e := p.processEmptyScalar(p.peekToken().start)
		p.state = p.pop()
		return e
	}
	return p.parseBlockNode()
}

func (p *parser) processDirectives() {
	p.yamlVersion = false
	p.tagHandles = map[string]string{}
	for p.checkToken(tDirective) {
		t := p.getToken()
		switch t.value {
		case "YAML":
			if p.yamlVersion {
				panic(Errorf("", Mark{}, t.start, "found duplicate YAML directive"))
			}
			if t.major != 1 {
				panic(Errorf("", Mark{}, t.start, "found incompatible YAML document (version 1.* is required)"))
			}
			p.yamlVersion = true
		case "TAG":
			if _, ok := p.tagHandles[t.tagHandle]; ok {
				panic(Errorf("", Mark{}, t.start, "duplicate tag handle %s", pyRepr(t.tagHandle)))
			}
			p.tagHandles[t.tagHandle] = t.tagPrefix
		}
	}
	for k, v := range defaultTags {
		if _, ok := p.tagHandles[k]; !ok {
			p.tagHandles[k] = v
		}
	}
}

func (p *parser) parseBlockNode() *event { return p.parseNode(true, false) }

func (p *parser) parseFlowNode() *event { return p.parseNode(false, false) }

func (p *parser) parseBlockNodeOrIndentlessSequence() *event { return p.parseNode(true, true) }

func (p *parser) parseNode(block, indentlessSequence bool) *event {
	if p.checkToken(tAlias) {
		t := p.getToken()
		p.state = p.pop()
		return &event{kind: eAlias, anchor: t.value, hasAnchor: true, start: t.start, end: t.end}
	}
	var anchor, tag string
	var hasAnchor, hasTag, haveStart bool
	var start, end, tagMark Mark
	var tagTok *token
	if p.checkToken(tAnchor) {
		t := p.getToken()
		start, end, haveStart = t.start, t.end, true
		anchor, hasAnchor = t.value, true
		if p.checkToken(tTag) {
			t := p.getToken()
			tagMark, end = t.start, t.end
			tagTok = t
		}
	} else if p.checkToken(tTag) {
		t := p.getToken()
		start, end, haveStart = t.start, t.end, true
		tagMark = t.start
		tagTok = t
		if p.checkToken(tAnchor) {
			t := p.getToken()
			end = t.end
			anchor, hasAnchor = t.value, true
		}
	}
	if tagTok != nil {
		hasTag = true
		if tagTok.hasHandle {
			prefix, ok := p.tagHandles[tagTok.handle]
			if !ok {
				panic(Errorf("while parsing a node", start, tagMark, "found undefined tag handle %s", pyRepr(tagTok.handle)))
			}
			tag = prefix + tagTok.suffix
		} else {
			tag = tagTok.suffix
		}
	}
	if !haveStart {
		start = p.peekToken().start
		end = start
	}
	implicit := !hasTag || tag == "!"
	e := &event{anchor: anchor, hasAnchor: hasAnchor, tag: tag, hasTag: hasTag, start: start}
	if indentlessSequence && p.checkToken(tBlockEntry) {
		e.kind, e.end, e.implicit[0] = eSequenceStart, p.peekToken().end, implicit
		p.state = p.parseIndentlessSequenceEntry
		return e
	}
	switch {
	case p.checkToken(tScalar):
		t := p.getToken()
		e.kind, e.end, e.value, e.style = eScalar, t.end, t.value, t.style
		switch {
		case (t.plain && !hasTag) || tag == "!":
			e.implicit = [2]bool{true, false}
		case !hasTag:
			e.implicit = [2]bool{false, true}
		}
		p.state = p.pop()
	case p.checkToken(tFlowSequenceStart):
		e.kind, e.end, e.implicit[0] = eSequenceStart, p.peekToken().end, implicit
		p.state = p.parseFlowSequenceFirstEntry
	case p.checkToken(tFlowMappingStart):
		e.kind, e.end, e.implicit[0] = eMappingStart, p.peekToken().end, implicit
		p.state = p.parseFlowMappingFirstKey
	case block && p.checkToken(tBlockSequenceStart):
		e.kind, e.end, e.implicit[0] = eSequenceStart, p.peekToken().start, implicit
		p.state = p.parseBlockSequenceFirstEntry
	case block && p.checkToken(tBlockMappingStart):
		e.kind, e.end, e.implicit[0] = eMappingStart, p.peekToken().start, implicit
		p.state = p.parseBlockMappingFirstKey
	case hasAnchor || hasTag:
		e.kind, e.end, e.implicit = eScalar, end, [2]bool{implicit, false}
		p.state = p.pop()
	default:
		node := "flow"
		if block {
			node = "block"
		}
		t := p.peekToken()
		panic(Errorf("while parsing a "+node+" node", start, t.start, "expected the node content, but found %s", pyRepr(t.id())))
	}
	return e
}

func (p *parser) parseBlockSequenceFirstEntry() *event {
	t := p.getToken()
	p.marks = append(p.marks, t.start)
	return p.parseBlockSequenceEntry()
}

func (p *parser) parseBlockSequenceEntry() *event {
	if p.checkToken(tBlockEntry) {
		t := p.getToken()
		if !p.checkToken(tBlockEntry, tBlockEnd) {
			p.push(p.parseBlockSequenceEntry)
			return p.parseBlockNode()
		}
		p.state = p.parseBlockSequenceEntry
		return p.processEmptyScalar(t.end)
	}
	if !p.checkToken(tBlockEnd) {
		t := p.peekToken()
		panic(Errorf("while parsing a block collection", p.marks[len(p.marks)-1], t.start, "expected <block end>, but found %s", pyRepr(t.id())))
	}
	t := p.getToken()
	p.state = p.pop()
	p.popMark()
	return &event{kind: eSequenceEnd, start: t.start, end: t.end}
}

func (p *parser) parseIndentlessSequenceEntry() *event {
	if p.checkToken(tBlockEntry) {
		t := p.getToken()
		if !p.checkToken(tBlockEntry, tKey, tValue, tBlockEnd) {
			p.push(p.parseIndentlessSequenceEntry)
			return p.parseBlockNode()
		}
		p.state = p.parseIndentlessSequenceEntry
		return p.processEmptyScalar(t.end)
	}
	t := p.peekToken()
	p.state = p.pop()
	return &event{kind: eSequenceEnd, start: t.start, end: t.start}
}

func (p *parser) parseBlockMappingFirstKey() *event {
	t := p.getToken()
	p.marks = append(p.marks, t.start)
	return p.parseBlockMappingKey()
}

func (p *parser) parseBlockMappingKey() *event {
	if p.checkToken(tKey) {
		t := p.getToken()
		if !p.checkToken(tKey, tValue, tBlockEnd) {
			p.push(p.parseBlockMappingValue)
			return p.parseBlockNodeOrIndentlessSequence()
		}
		p.state = p.parseBlockMappingValue
		return p.processEmptyScalar(t.end)
	}
	if !p.checkToken(tBlockEnd) {
		t := p.peekToken()
		panic(Errorf("while parsing a block mapping", p.marks[len(p.marks)-1], t.start, "expected <block end>, but found %s", pyRepr(t.id())))
	}
	t := p.getToken()
	p.state = p.pop()
	p.popMark()
	return &event{kind: eMappingEnd, start: t.start, end: t.end}
}

func (p *parser) parseBlockMappingValue() *event {
	if p.checkToken(tValue) {
		t := p.getToken()
		if !p.checkToken(tKey, tValue, tBlockEnd) {
			p.push(p.parseBlockMappingKey)
			return p.parseBlockNodeOrIndentlessSequence()
		}
		p.state = p.parseBlockMappingKey
		return p.processEmptyScalar(t.end)
	}
	p.state = p.parseBlockMappingKey
	return p.processEmptyScalar(p.peekToken().start)
}

func (p *parser) parseFlowSequenceFirstEntry() *event {
	t := p.getToken()
	p.marks = append(p.marks, t.start)
	return p.flowSequenceEntry(true)
}

func (p *parser) parseFlowSequenceEntry() *event { return p.flowSequenceEntry(false) }

func (p *parser) flowSequenceEntry(first bool) *event {
	if !p.checkToken(tFlowSequenceEnd) {
		if !first {
			if p.checkToken(tFlowEntry) {
				p.getToken()
			} else {
				t := p.peekToken()
				panic(Errorf("while parsing a flow sequence", p.marks[len(p.marks)-1], t.start, "expected ',' or ']', but got %s", pyRepr(t.id())))
			}
		}
		if p.checkToken(tKey) {
			t := p.peekToken()
			p.state = p.parseFlowSequenceEntryMappingKey
			return &event{kind: eMappingStart, start: t.start, end: t.end, implicit: [2]bool{true, false}}
		} else if !p.checkToken(tFlowSequenceEnd) {
			p.push(p.parseFlowSequenceEntry)
			return p.parseFlowNode()
		}
	}
	t := p.getToken()
	p.state = p.pop()
	p.popMark()
	return &event{kind: eSequenceEnd, start: t.start, end: t.end}
}

func (p *parser) parseFlowSequenceEntryMappingKey() *event {
	t := p.getToken()
	if !p.checkToken(tValue, tFlowEntry, tFlowSequenceEnd) {
		p.push(p.parseFlowSequenceEntryMappingValue)
		return p.parseFlowNode()
	}
	p.state = p.parseFlowSequenceEntryMappingValue
	return p.processEmptyScalar(t.end)
}

func (p *parser) parseFlowSequenceEntryMappingValue() *event {
	if p.checkToken(tValue) {
		t := p.getToken()
		if !p.checkToken(tFlowEntry, tFlowSequenceEnd) {
			p.push(p.parseFlowSequenceEntryMappingEnd)
			return p.parseFlowNode()
		}
		p.state = p.parseFlowSequenceEntryMappingEnd
		return p.processEmptyScalar(t.end)
	}
	p.state = p.parseFlowSequenceEntryMappingEnd
	return p.processEmptyScalar(p.peekToken().start)
}

func (p *parser) parseFlowSequenceEntryMappingEnd() *event {
	p.state = p.parseFlowSequenceEntry
	t := p.peekToken()
	return &event{kind: eMappingEnd, start: t.start, end: t.start}
}

func (p *parser) parseFlowMappingFirstKey() *event {
	t := p.getToken()
	p.marks = append(p.marks, t.start)
	return p.flowMappingKey(true)
}

func (p *parser) parseFlowMappingKey() *event { return p.flowMappingKey(false) }

func (p *parser) flowMappingKey(first bool) *event {
	if !p.checkToken(tFlowMappingEnd) {
		if !first {
			if p.checkToken(tFlowEntry) {
				p.getToken()
			} else {
				t := p.peekToken()
				panic(Errorf("while parsing a flow mapping", p.marks[len(p.marks)-1], t.start, "expected ',' or '}', but got %s", pyRepr(t.id())))
			}
		}
		if p.checkToken(tKey) {
			t := p.getToken()
			if !p.checkToken(tValue, tFlowEntry, tFlowMappingEnd) {
				p.push(p.parseFlowMappingValue)
				return p.parseFlowNode()
			}
			p.state = p.parseFlowMappingValue
			return p.processEmptyScalar(t.end)
		} else if !p.checkToken(tFlowMappingEnd) {
			p.push(p.parseFlowMappingEmptyValue)
			return p.parseFlowNode()
		}
	}
	t := p.getToken()
	p.state = p.pop()
	p.popMark()
	return &event{kind: eMappingEnd, start: t.start, end: t.end}
}

func (p *parser) parseFlowMappingValue() *event {
	if p.checkToken(tValue) {
		t := p.getToken()
		if !p.checkToken(tFlowEntry, tFlowMappingEnd) {
			p.push(p.parseFlowMappingKey)
			return p.parseFlowNode()
		}
		p.state = p.parseFlowMappingKey
		return p.processEmptyScalar(t.end)
	}
	p.state = p.parseFlowMappingKey
	return p.processEmptyScalar(p.peekToken().start)
}

func (p *parser) parseFlowMappingEmptyValue() *event {
	p.state = p.parseFlowMappingKey
	return p.processEmptyScalar(p.peekToken().start)
}

func (p *parser) processEmptyScalar(m Mark) *event {
	return &event{kind: eScalar, implicit: [2]bool{true, false}, start: m, end: m}
}
