package webui

import (
	"errors"
	"math/big"
	"sort"

	"github.com/starsmash29/fr_os-community/config"
)

// The screens that change the config (phase 3b) edit it as 1.x does:
// the raw document, one section at a time, then validate the whole of
// it and save it through the apply-helper (frfw.webui.actions.try_save,
// config_store). The helpers below are the Python dict and list steps
// they take; where 1.x would raise (a section that isn't a mapping, a
// list item that isn't one) the page fails with a 500, as it does there.

// trySave is try_save: the config check first, for a fast and specific
// message, then save_config, which checks it again before writing. An
// apply-helper that can't be reached fails the request, as in 1.x
// (HelperError is not caught there).
func (s *Server) trySave(raw *config.Map) (bool, string, error) {
	if _, err := config.Parse(raw); err != nil {
		return false, err.Error(), nil
	}
	text, err := config.DumpYAML(raw)
	if err != nil {
		return false, "", err
	}
	reply, err := s.helper.SaveConfig(text)
	if err != nil {
		return false, "", err
	}
	ok, _ := reply.Get("ok")
	msg, _ := reply.Get("message")
	if msg == nil {
		msg = ""
	}
	return config.Truthy(ok), pyStr(msg), nil
}

// saved is the redirect after trySave: success or the error message.
func (s *Server) saved(raw *config.Map, path, success string) (*answer, error) {
	ok, message, err := s.trySave(raw)
	if err != nil {
		return nil, err
	}
	if ok {
		return redirect(redirectWith(path, "success", success)), nil
	}
	return redirect(redirectWith(path, "error", message)), nil
}

func errorRedirect(path, message string) *answer {
	return redirect(redirectWith(path, "error", message))
}

func successRedirect(path, message string) *answer {
	return redirect(redirectWith(path, "success", message))
}

// setdefaultMap is m.setdefault(key, {}) where the caller goes on to use
// the result as a dict.
func setdefaultMap(m *config.Map, key string) (*config.Map, error) {
	v, ok := m.Get(key)
	if !ok {
		out := config.NewMap()
		m.Set(key, out)
		return out, nil
	}
	if out, ok := v.(*config.Map); ok {
		return out, nil
	}
	return nil, errInternal
}

// getMapOr is `m.get(key) or {}` used as a dict; a falsy value is a new,
// unattached one.
func getMapOr(m *config.Map, key string) (*config.Map, error) {
	v, _ := m.Get(key)
	if !config.Truthy(v) {
		return config.NewMap(), nil
	}
	if out, ok := v.(*config.Map); ok {
		return out, nil
	}
	return nil, errInternal
}

// dictList is a list whose items 1.x calls .get on: every item must be
// a mapping. Absent (or, with orEmpty, falsy) is the empty list.
func dictList(v config.Value, present, orEmpty bool) ([]*config.Map, error) {
	if !present || (orEmpty && !config.Truthy(v)) {
		return nil, nil
	}
	list, ok := v.([]config.Value)
	if !ok {
		return nil, errInternal
	}
	out := make([]*config.Map, len(list))
	for i, item := range list {
		m, ok := item.(*config.Map)
		if !ok {
			return nil, errInternal
		}
		out[i] = m
	}
	return out, nil
}

// getList is `m.get(key) or []` (orEmpty) or m.setdefault(key, [])
// (!orEmpty, which stores the new list) for a list of mappings.
func getList(m *config.Map, key string, orEmpty bool) ([]*config.Map, error) {
	v, ok := m.Get(key)
	if !ok && !orEmpty {
		m.Set(key, []config.Value{})
	}
	return dictList(v, ok, orEmpty)
}

func values(items []*config.Map) []config.Value {
	out := make([]config.Value, len(items))
	for i, m := range items {
		out[i] = m
	}
	return out
}

// strEq is Python's `v == s` for a config value and a string.
func strEq(v config.Value, s string) bool { x, ok := v.(string); return ok && x == s }

func field(m *config.Map, key string) config.Value { v, _ := m.Get(key); return v }

// sortedZoneKeys is sorted((raw.get("zones") or {}).keys()).
func sortedZoneKeys(raw *config.Map) ([]string, error) {
	zones, err := getMapOr(raw, "zones")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, zones.Len())
	for _, k := range zones.Keys() {
		s, ok := k.(string)
		if !ok {
			return nil, errInternal // sorted() of mixed keys raises; a lone int key is left out of 3b-1
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

func pyInt(n int64) *big.Int { return big.NewInt(n) }

var errNoSuch = errors.New("no such entry")
