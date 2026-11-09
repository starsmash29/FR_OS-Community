package config

import (
	"fmt"
	"math/big"

	"github.com/starsmash29/fr_os-community/internal/pyyaml"
)

// DumpYAML is yaml.safe_dump(v, sort_keys=False) of PyYAML 6.0.1 for a
// value LoadYAML built (or one made of the same types): 1.x writes
// config.yaml with it when the webUI address moves (ROADMAP SEC-27), and
// FR_OS 2 writes the same text.
//
// SafeRepresenter writes an object reached twice once, with an anchor,
// and then as an alias; it knows them by id(). A mapping is the same
// *Map and a list the same backing array, as LoadYAML builds them; None,
// bools, numbers and strings are never anchored, as in PyYAML. A date
// is a value here, not an object, so one a YAML alias reached twice is
// written twice (testdata/reference/decisions.md).
func DumpYAML(v Value) (string, error) {
	r := &representer{lists: map[listID]*pyyaml.Node{}, maps: map[*Map]*pyyaml.Node{}}
	root, err := r.represent(v)
	if err != nil {
		return "", err
	}
	return pyyaml.Dump(root)
}

type listID struct {
	first *Value
	n     int
}

type representer struct {
	lists map[listID]*pyyaml.Node
	maps  map[*Map]*pyyaml.Node
}

func scalarNode(tag, value string) *pyyaml.Node {
	return &pyyaml.Node{Kind: pyyaml.ScalarNode, Tag: yamlTag + tag, Value: value}
}

func (r *representer) represent(v Value) (*pyyaml.Node, error) {
	switch x := v.(type) {
	case nil:
		return scalarNode("null", "null"), nil
	case bool:
		if x {
			return scalarNode("bool", "true"), nil
		}
		return scalarNode("bool", "false"), nil
	case *big.Int:
		return scalarNode("int", x.String()), nil
	case float64:
		return scalarNode("float", yamlFloatText(x)), nil
	case string:
		return scalarNode("str", x), nil
	case Date:
		return scalarNode("timestamp", x.str()), nil
	case Datetime:
		return scalarNode("timestamp", x.str()), nil
	case []Value:
		var id listID
		if cap(x) > 0 {
			id = listID{&x[:cap(x)][0], len(x)}
			if n, ok := r.lists[id]; ok {
				return n, nil
			}
		}
		n := &pyyaml.Node{Kind: pyyaml.SequenceNode, Tag: yamlTag + "seq"}
		if id.first != nil {
			r.lists[id] = n // before the items: a list may hold itself
		}
		for _, item := range x {
			sub, err := r.represent(item)
			if err != nil {
				return nil, err
			}
			n.Items = append(n.Items, sub)
		}
		return n, nil
	case *Map:
		if n, ok := r.maps[x]; ok {
			return n, nil
		}
		n := &pyyaml.Node{Kind: pyyaml.MappingNode, Tag: yamlTag + "map"}
		r.maps[x] = n
		for i, k := range x.keys {
			key, err := r.represent(k)
			if err != nil {
				return nil, err
			}
			val, err := r.represent(x.vals[i])
			if err != nil {
				return nil, err
			}
			n.Pairs = append(n.Pairs, [2]*pyyaml.Node{key, val})
		}
		return n, nil
	}
	return nil, fmt.Errorf("config: cannot write a %T as YAML", v)
}
