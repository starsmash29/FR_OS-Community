package helper

import (
	"errors"
	"math"
	"math/big"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/nft"
)

// ReadRuntime reads the members an apply carries over the ruleset reload
// (frfw.provision._read_runtime_sets): the brute-force jail and the AI
// IDS quarantine always (turning a detector off must not amnesty the
// hosts it caught), ZTNA sessions and isolated IoT devices while their
// feature is on. They are written into the new ruleset itself, so the
// reload's `flush ruleset` never lets anyone out, not even for a moment
// (review FR-002). The same readers as the status commands; a read that
// fails stops the apply before anything is reloaded.
func (s *Server) ReadRuntime(c *config.Config) (*nft.RuntimeSets, error) {
	rs := &nft.RuntimeSets{}
	timed := func(what, set string, prefixes bool, into *[]nft.Timed) error {
		members, err := s.timedMembers(set, prefixes)
		if err != nil {
			return readFailed(what, err)
		}
		for _, m := range members {
			*into = append(*into, nft.Timed{Member: m.member, Left: clampInt64(m.left)})
		}
		return nil
	}
	if err := timed("the brute-force jail", nft.BruteforceJailSet, true, &rs.BruteforceJail); err != nil {
		return nil, err
	}
	if err := timed("the AI IDS quarantine", nft.IDSQuarantineSet, false, &rs.IDSQuarantine); err != nil {
		return nil, err
	}
	if c.Ztna.Enabled {
		ans, err := s.ztnaSessionsStatus()
		if err == nil {
			if r, ok := ans.(ztnaReply); ok {
				for _, z := range r.Sessions {
					rs.Ztna = append(rs.Ztna, nft.ZtnaSession{IP: z.IP, MAC: z.MAC, Left: clampInt64(z.ExpiresIn)})
				}
			} else {
				err = errors.New(ans.(reply).Message)
			}
		}
		if err != nil {
			return nil, readFailed("ZTNA sessions", err)
		}
	}
	if c.Iot.Enabled {
		ans, err := s.iotIsolationStatus()
		if err == nil {
			if r, ok := ans.(iotReply); ok {
				rs.IotIsolated = r.Isolated
			} else {
				err = errors.New(ans.(reply).Message)
			}
		}
		if err != nil {
			return nil, readFailed("isolated IoT devices", err)
		}
	}
	if err := timed("the AI IDS quarantine's MACs", nft.IDSQuarantineMacSet, false, &rs.IDSQuarantineMac); err != nil {
		return nil, err
	}
	if err := timed("the IPv6 brute-force jail", nft.BruteforceJail6Set, true, &rs.BruteforceJail6); err != nil {
		return nil, err
	}
	if err := timed("the brute-force jail's MACs", nft.BruteforceJailMacSet, true, &rs.BruteforceJailMac); err != nil {
		return nil, err
	}
	return rs, nil
}

func readFailed(what string, err error) error {
	return &apply.NftError{Msg: "could not read " + what + " before reloading the firewall, so nothing was " +
		"changed (the running ruleset keeps enforcing): " + err.Error()}
}

func clampInt64(n *big.Int) int64 {
	switch {
	case n.IsInt64():
		return n.Int64()
	case n.Sign() > 0:
		return math.MaxInt64
	}
	return math.MinInt64
}
