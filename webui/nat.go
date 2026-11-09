package webui

import (
	"fmt"
	"math/big"
	"slices"

	"github.com/starsmash29/fr_os-community/config"
)

// The NAT screen (1.x's routes/nat.py): masquerade and port forwards.

type portForwardRow struct {
	Name, InZone, Proto, DstPort, ToAddress, ToPort string
}

type natData struct {
	Masquerade   []string // out_zone of each
	PortForwards []portForwardRow
	Zones        []string
}

func (s *Server) showNAT(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	nat, err := getMapOr(raw, "nat")
	if err != nil {
		return nil, err
	}
	d := &natData{}
	masquerade, err := pyIter(field(nat, "masquerade"))
	if err != nil {
		return nil, err
	}
	for _, m := range masquerade {
		d.Masquerade = append(d.Masquerade, jinjaText(m, "out_zone"))
	}
	forwards, err := pyIter(field(nat, "port_forwards"))
	if err != nil {
		return nil, err
	}
	for _, pf := range forwards {
		d.PortForwards = append(d.PortForwards, portForwardRow{jinjaText(pf, "name"), jinjaText(pf, "in_zone"),
			jinjaText(pf, "proto"), jinjaText(pf, "dst_port"), jinjaText(pf, "to_address"), jinjaText(pf, "to_port")})
	}
	if d.Zones, err = sortedZoneKeys(raw); err != nil {
		return nil, err
	}
	return s.render(q, "nat", flash(q, &page{Username: q.user.Username, Data: d}))
}

func (s *Server) addMasquerade(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var outZone string
	if err = q.fields(func(p *formParams) { outZone = p.str("out_zone") }); err != nil {
		return nil, err
	}
	nat, err := setdefaultMap(raw, "nat")
	if err != nil {
		return nil, err
	}
	masquerade, err := getList(nat, "masquerade", false)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(masquerade, func(m *config.Map) bool { return strEq(field(m, "out_zone"), outZone) }) {
		nat.Set("masquerade", values(append(masquerade, cmdMap("out_zone", outZone))))
	}
	return s.saved(raw, "/nat", fmt.Sprintf("Masquerade on %s added", config.Repr(outZone)))
}

func (s *Server) deleteMasquerade(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	outZone := q.params["out_zone"]
	nat, err := setdefaultMap(raw, "nat")
	if err != nil {
		return nil, err
	}
	masquerade, err := getList(nat, "masquerade", true)
	if err != nil {
		return nil, err
	}
	nat.Set("masquerade", values(slices.DeleteFunc(slices.Clone(masquerade), func(m *config.Map) bool {
		return strEq(field(m, "out_zone"), outZone)
	})))
	return s.saved(raw, "/nat", fmt.Sprintf("Masquerade on %s removed", config.Repr(outZone)))
}

func (s *Server) addPortForward(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var name, inZone, proto, toAddress string
	var dstPort, toPort *big.Int
	if err = q.fields(func(p *formParams) {
		name, inZone, proto = p.str("name"), p.str("in_zone"), p.str("proto")
		dstPort, toAddress, toPort = p.int("dst_port"), p.str("to_address"), p.intOr("to_port", nil)
	}); err != nil {
		return nil, err
	}
	target := dstPort
	if toPort != nil && toPort.Sign() != 0 { // `to_port if to_port else dst_port`
		target = toPort
	}
	entry := cmdMap("name", name, "in_zone", inZone, "proto", proto, "dst_port", dstPort, "to_address", toAddress,
		"to_port", target)
	nat, err := setdefaultMap(raw, "nat")
	if err != nil {
		return nil, err
	}
	forwards, err := getList(nat, "port_forwards", false)
	if err != nil {
		return nil, err
	}
	forwards = slices.DeleteFunc(slices.Clone(forwards), func(m *config.Map) bool { return strEq(field(m, "name"), name) })
	nat.Set("port_forwards", values(append(forwards, entry)))
	return s.saved(raw, "/nat", fmt.Sprintf("Port forward %s saved", config.Repr(name)))
}

func (s *Server) deletePortForward(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	name := q.params["name"]
	nat, err := setdefaultMap(raw, "nat")
	if err != nil {
		return nil, err
	}
	forwards, err := getList(nat, "port_forwards", true)
	if err != nil {
		return nil, err
	}
	nat.Set("port_forwards", values(slices.DeleteFunc(slices.Clone(forwards), func(m *config.Map) bool {
		return strEq(field(m, "name"), name)
	})))
	return s.saved(raw, "/nat", fmt.Sprintf("Port forward %s deleted", config.Repr(name)))
}
