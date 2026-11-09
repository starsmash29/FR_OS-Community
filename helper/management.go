package helper

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
)

// --- set_management_addresses ---------------------------------------------------------

// cmdSetManagementAddresses (ROADMAP SEC-27) is the one way to move the
// webUI and SSH: the admin's own action. Only that changes, so
// config.yaml must hold nothing else that isn't applied yet. It is
// applied at once and held until it is confirmed from the new address
// (SEC-26); config.yaml is left as it was if the apply fails.
//
// The new config.yaml is 1.x's: yaml.safe_dump of the loaded config with
// management.addresses replaced (config.DumpYAML), so its comments go,
// as they do in 1.x.
func (s *Server) cmdSetManagementAddresses(request *config.Map) (any, error) {
	v, _ := request.Get("addresses")
	list, ok := v.([]config.Value)
	ok = ok && len(list) > 0
	addresses := make([]config.Value, 0, len(list))
	for _, a := range list {
		text, isStr := a.(string)
		if !isStr {
			ok = false
			break
		}
		addresses = append(addresses, text)
	}
	if !ok {
		return message(false, "'addresses' must be a non-empty list of IPv4 addresses"), nil
	}
	unlock, err := lockApply(s.lockPath())
	if err != nil {
		return commandError(err)
	}
	defer unlock()
	sys := s.sys()
	path := sys.Paths.Config
	text, err := readText(path)
	if err != nil {
		return commandError(err)
	}
	held, err := s.readHeld()
	if err != nil {
		return commandError(err)
	}
	if held != nil {
		return message(false, "The last apply is waiting for confirmation: confirm it or go back first"), nil
	}
	if recorded, ok := sys.AppliedConfigText(); ok && recorded != text {
		return message(false, "The config has changes that aren't applied yet: apply them (or undo them) first, so "+
			"that moving the webUI changes nothing else"), nil
	}
	raw, err := config.LoadYAML(text)
	if err != nil {
		return commandError(err)
	}
	if !config.Truthy(raw) {
		raw = config.NewMap()
	}
	top, ok := raw.(*config.Map)
	if !ok {
		return nil, errNoReply // 1.x: AttributeError, it has no .get
	}
	// {**(raw.get("management") or {}), "addresses": list(addresses)}: a
	// new mapping, so a management mapping a YAML alias also reaches
	// elsewhere stays as it was there.
	moved := config.NewMap()
	if old, _ := top.Get("management"); config.Truthy(old) {
		m, ok := old.(*config.Map)
		if !ok {
			return nil, errNoReply // 1.x: TypeError, it isn't a mapping
		}
		for i, k := range m.Keys() {
			moved.SetKey(k, m.Values()[i])
		}
	}
	moved.Set("addresses", addresses)
	top.Set("management", moved)
	newText, err := config.DumpYAML(top)
	if err != nil {
		return nil, errNoReply
	}
	again, err := config.LoadYAML(newText)
	if err != nil {
		return commandError(err)
	}
	c, err := config.Parse(again) // every address must be on the router
	if err != nil {
		return commandError(err)
	}
	if err := apply.WriteKeepingOwner(path, newText); err != nil {
		return commandError(err)
	}
	r, err := s.applyLocked(c, newText, true, userOf(request))
	if err != nil || !replyOK(r) {
		if werr := apply.WriteKeepingOwner(path, text); werr != nil {
			return nil, errNoReply
		}
	}
	return r, err
}

func replyOK(r any) bool {
	switch x := r.(type) {
	case reply:
		return x.OK
	case applyReply:
		return x.OK
	}
	return false
}

// readText is Path.read_text(): the text in universal-newline mode. A
// missing file is 1.x's FileNotFoundError, which it answers; any other
// failure (or text that isn't UTF-8) is an error 1.x lets through. At
// most config.MaxConfigBytes are read (AGENTS.md: every read has a size
// limit).
func readText(path string) (string, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", errors.New(apply.OSErrorText(err))
	}
	if err != nil {
		return "", errNoReply
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, config.MaxConfigBytes+1))
	if err != nil || !utf8.Valid(data) {
		return "", errNoReply
	}
	if len(data) > config.MaxConfigBytes {
		return "", fmt.Errorf("%s: larger than %d bytes", path, config.MaxConfigBytes)
	}
	return strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n"), nil
}

// --- refresh_adblock -------------------------------------------------------------------

// cmdRefreshAdblock downloads the ad-block lists the config names and
// writes them (apply.RefreshAdblock): the webUI's "Refresh now".
func (s *Server) cmdRefreshAdblock() (any, error) {
	sys := s.sys()
	c, _, err := apply.ReadConfig(sys.Paths.Config)
	if err != nil {
		return commandError(err)
	}
	r, err := sys.RefreshAdblock(c)
	if err != nil {
		return commandError(err)
	}
	failed := make([]config.Value, len(r.FailedURLs))
	for i, u := range r.FailedURLs {
		failed[i] = u
	}
	counts := config.NewMap()
	for _, n := range r.Counts {
		counts.Set(n.Name, big.NewInt(int64(n.Count)))
	}
	m := okMap()
	m.Set("message", r.Message)
	m.Set("domain_count", big.NewInt(int64(r.DomainCount)))
	m.Set("failed_urls", failed)
	m.Set("category_counts", counts)
	return pyReply(m)
}
