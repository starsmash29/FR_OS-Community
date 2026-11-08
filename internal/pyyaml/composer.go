package pyyaml

import (
	"fmt"
	"regexp"
)

// Kind is a node's kind (ScalarNode, SequenceNode, MappingNode).
type Kind int

const (
	ScalarNode Kind = iota
	SequenceNode
	MappingNode
)

// ID is the node's id in PyYAML's messages.
func (k Kind) ID() string { return [...]string{"scalar", "sequence", "mapping"}[k] }

// Node is a composed node (yaml.nodes). Aliases are the same *Node.
type Node struct {
	Kind       Kind
	Tag        string
	Value      string     // a scalar's text
	Items      []*Node    // a sequence's entries
	Pairs      [][2]*Node // a mapping's (key, value) pairs, in order
	Start, End Mark
	Style      rune
}

// Limits FR_OS 2 sets where PyYAML has none (decisions.md, 2026-11-08).
const (
	// MaxDepth: nesting deeper than this is refused. PyYAML's composer
	// recurses, so 1.x crashes with RecursionError a few hundred levels
	// down; no config needs more than a handful.
	MaxDepth = 64
	// MaxExpanded: a document whose aliases, followed, make more nodes
	// than this is refused (a "billion laughs" document is small, but
	// walking or printing it is not).
	MaxExpanded = 1_000_000
)

type composer struct {
	*parser
	anchors map[string]*Node
	open    map[*Node]bool
	depth   int
}

// Load composes the single document in text, as yaml.safe_load does
// before constructing it: nil (no error) for an empty stream. Errors
// are *MarkedError, *ReaderError or *LimitError.
func Load(text string) (root *Node, err error) {
	defer func() {
		if r := recover(); r != nil {
			switch e := r.(type) {
			case *MarkedError:
				err = e
			case *ReaderError:
				err = e
			case *LimitError:
				err = e
			default:
				panic(r)
			}
			root = nil
		}
	}()
	s, err := newScanner(text)
	if err != nil {
		return nil, err
	}
	c := &composer{parser: newParser(s), anchors: map[string]*Node{}, open: map[*Node]bool{}}
	root = c.getSingleNode()
	if root != nil {
		if n := expanded(root, map[*Node]int{}); n > MaxExpanded {
			return nil, &LimitError{fmt.Sprintf("config: the document's aliases expand to more than %d nodes", MaxExpanded)}
		}
	}
	return root, nil
}

func expanded(n *Node, memo map[*Node]int) int {
	if v, ok := memo[n]; ok {
		return v
	}
	total := 1
	for _, c := range n.Items {
		total += expanded(c, memo)
		if total > MaxExpanded {
			break
		}
	}
	for _, kv := range n.Pairs {
		total += expanded(kv[0], memo) + expanded(kv[1], memo)
		if total > MaxExpanded {
			break
		}
	}
	memo[n] = total
	return total
}

func (c *composer) getSingleNode() *Node {
	c.getEvent() // STREAM-START
	var doc *Node
	if !c.checkEvent(eStreamEnd) {
		doc = c.composeDocument()
	}
	if !c.checkEvent(eStreamEnd) {
		e := c.getEvent()
		panic(&MarkedError{
			Context: "expected a single document in the stream", HasContext: true, ContextMark: doc.Start,
			Problem: "but found another document", HasProblem: true, ProblemMark: e.start,
		})
	}
	c.getEvent() // STREAM-END
	return doc
}

func (c *composer) composeDocument() *Node {
	c.getEvent() // DOCUMENT-START
	n := c.composeNode()
	c.getEvent() // DOCUMENT-END
	c.anchors = map[string]*Node{}
	return n
}

func (c *composer) composeNode() *Node {
	if c.checkEvent(eAlias) {
		e := c.getEvent()
		n, ok := c.anchors[e.anchor]
		if !ok {
			panic(Errorf("", Mark{}, e.start, "found undefined alias %s", pyRepr(e.anchor)))
		}
		if c.open[n] {
			// PyYAML builds a list or mapping that contains itself.
			panic(&LimitError{fmt.Sprintf("config: alias %s refers to a node that contains it", pyRepr(e.anchor))})
		}
		return n
	}
	e := c.peekEvent()
	if e.hasAnchor {
		if first, ok := c.anchors[e.anchor]; ok {
			panic(&MarkedError{
				Context: fmt.Sprintf("found duplicate anchor %s; first occurrence", pyRepr(e.anchor)), HasContext: true,
				ContextMark: first.Start, Problem: "second occurrence", HasProblem: true, ProblemMark: e.start,
			})
		}
	}
	c.depth++
	if c.depth > MaxDepth {
		panic(&LimitError{fmt.Sprintf("config: nested more than %d levels deep", MaxDepth)})
	}
	defer func() { c.depth-- }()
	switch {
	case c.checkEvent(eScalar):
		return c.composeScalar()
	case c.checkEvent(eSequenceStart):
		return c.composeSequence()
	default:
		return c.composeMapping()
	}
}

func (c *composer) register(e *event, n *Node) {
	if e.hasAnchor {
		c.anchors[e.anchor] = n
	}
}

func (c *composer) composeScalar() *Node {
	e := c.getEvent()
	tag := e.tag
	if !e.hasTag || tag == "!" {
		tag = resolveScalar(e.value, e.implicit[0])
	}
	n := &Node{Kind: ScalarNode, Tag: tag, Value: e.value, Start: e.start, End: e.end, Style: e.style}
	c.register(e, n)
	return n
}

func (c *composer) composeSequence() *Node {
	e := c.getEvent()
	tag := e.tag
	if !e.hasTag || tag == "!" {
		tag = "tag:yaml.org,2002:seq"
	}
	n := &Node{Kind: SequenceNode, Tag: tag, Items: []*Node{}, Start: e.start}
	c.register(e, n)
	c.open[n] = true
	for !c.checkEvent(eSequenceEnd) {
		n.Items = append(n.Items, c.composeNode())
	}
	delete(c.open, n)
	n.End = c.getEvent().end
	return n
}

func (c *composer) composeMapping() *Node {
	e := c.getEvent()
	tag := e.tag
	if !e.hasTag || tag == "!" {
		tag = "tag:yaml.org,2002:map"
	}
	n := &Node{Kind: MappingNode, Tag: tag, Pairs: [][2]*Node{}, Start: e.start}
	c.register(e, n)
	c.open[n] = true
	for !c.checkEvent(eMappingEnd) {
		k := c.composeNode()
		v := c.composeNode()
		n.Pairs = append(n.Pairs, [2]*Node{k, v})
	}
	delete(c.open, n)
	n.End = c.getEvent().end
	return n
}

// The resolver (yaml.resolver.Resolver): the YAML 1.1 implicit types
// for a plain scalar, tried in PyYAML's order for the first character.
// Each pattern ends in Python's `$`, which also matches before a final
// "\n"; `\n?\z` says the same.

type implicitResolver struct {
	tag   string
	re    *regexp.Regexp
	first string // the characters a value may start with ("" matches the empty value)
}

var implicitResolvers = []implicitResolver{
	{"tag:yaml.org,2002:bool", regexp.MustCompile(`\A(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)\n?\z`), "yYnNtTfFoO"},
	{"tag:yaml.org,2002:float", regexp.MustCompile(`\A(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))\n?\z`), "-+0123456789."},
	{"tag:yaml.org,2002:int", regexp.MustCompile(`\A(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)\n?\z`), "-+0123456789"},
	{"tag:yaml.org,2002:merge", regexp.MustCompile(`\A(?:<<)\n?\z`), "<"},
	{"tag:yaml.org,2002:null", regexp.MustCompile(`\A(?:~|null|Null|NULL|)\n?\z`), "~nN\x00"},
	{"tag:yaml.org,2002:timestamp", regexp.MustCompile(`\A(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)\n?\z`), "0123456789"},
	{"tag:yaml.org,2002:value", regexp.MustCompile(`\A(?:=)\n?\z`), "="},
	// PyYAML's 'tag:yaml.org,2002:yaml' for "!", "&", "*" can't apply:
	// a plain scalar can't start with them.
}

func resolveScalar(value string, implicit bool) string {
	if implicit {
		var first rune // 0 stands for the empty value
		for _, r := range value {
			first = r
			break
		}
		for _, r := range implicitResolvers {
			if in(first, r.first) && (first != 0 || value == "") && r.re.MatchString(value) {
				return r.tag
			}
		}
	}
	return "tag:yaml.org,2002:str"
}
