package apply

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
)

// LinkState is a network device as it was: whether it existed, was up,
// and its IPv4 addresses (frfw.transaction.LinkState), for the
// interface-address step's undo.
type LinkState struct {
	Device    string
	Exists    bool
	Up        bool
	Addresses []string // "a.b.c.d/len", sorted
}

type ipLink struct {
	Flags    []string `json:"flags"`
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		Prefixlen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

// CaptureLink reads device with `ip -j addr show`.
func CaptureLink(run Runner, device string) (LinkState, error) {
	d, err := Ifname(device)
	if err != nil {
		return LinkState{}, err
	}
	res, err := run(Cmd{Argv: []string{"ip", "-j", "addr", "show", "dev", d}})
	if err != nil {
		return LinkState{}, err
	}
	if res.Code != 0 {
		return LinkState{Device: d}, nil
	}
	var links []ipLink
	if err := json.Unmarshal([]byte(res.Stdout), &links); err != nil || len(links) != 1 {
		if err == nil { // Python's text for `(link,) = ...`
			err = errors.New("not enough values to unpack (expected 1, got 0)")
			if len(links) > 1 {
				err = fmt.Errorf("too many values to unpack (expected 1, got %d)", len(links))
			}
		}
		return LinkState{}, fmt.Errorf("could not read the state of %s: %v", d, err)
	}
	s := LinkState{Device: d, Exists: true, Up: slices.Contains(links[0].Flags, "UP")}
	for _, a := range links[0].AddrInfo {
		if a.Family != "inet" {
			continue
		}
		ip, err := netip.ParseAddr(a.Local)
		if err != nil || !ip.Is4() || a.Prefixlen < 0 || a.Prefixlen > 32 {
			return LinkState{}, fmt.Errorf("could not read the state of %s: address %q/%d", d, a.Local, a.Prefixlen)
		}
		text := fmt.Sprintf("%s/%d", ip, a.Prefixlen)
		if !slices.Contains(s.Addresses, text) {
			s.Addresses = append(s.Addresses, text)
		}
	}
	slices.Sort(s.Addresses)
	return s, nil
}

// Restore removes what an apply added and puts back what it removed
// (the address step removes the last applied config's stale addresses,
// review v0.2.1 FR-NEW-005); a device it created goes away.
func (s LinkState) Restore(run Runner) error {
	now, err := CaptureLink(run, s.Device)
	if err != nil {
		return err
	}
	if !now.Exists {
		return nil
	}
	if !s.Exists {
		return runIP(run, "link", "del", "dev", s.Device)
	}
	for _, a := range now.Addresses {
		if !slices.Contains(s.Addresses, a) {
			if err := runIP(run, "addr", "del", a, "dev", s.Device); err != nil {
				return err
			}
		}
	}
	for _, a := range s.Addresses {
		if !slices.Contains(now.Addresses, a) {
			v, err := IPv4Interface(a)
			if err != nil {
				return err
			}
			if err := runIP(run, "addr", "add", v, "dev", s.Device); err != nil {
				return err
			}
		}
	}
	if now.Up && !s.Up {
		return runIP(run, "link", "set", "dev", s.Device, "down")
	}
	return nil
}

func runIP(run Runner, args ...string) error {
	res, err := run(Cmd{Argv: append([]string{"ip"}, args...)})
	if err != nil {
		return err
	}
	if res.Code != 0 {
		if msg := config.PyStrip(res.Stderr); msg != "" {
			return errors.New(msg)
		}
		return errors.New("ip " + strings.Join(args, " ") + " failed")
	}
	return nil
}
