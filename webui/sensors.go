package webui

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
)

// What the filtering screens (phase 3b-2) read besides the config: the
// state files the unprivileged daemons write for them (1.x's
// paths.SENSOR_STATE_DIR), read as 1.x reads them, and the Jinja
// details their templates lean on.

// maxStateBytes bounds a state file read (every read has a size limit,
// AGENTS.md); the daemons keep theirs far smaller.
const maxStateBytes = 16 << 20

func (p Paths) sensorState(name string) string { return p.at("/etc/fr_os/sensors/" + name) }

// readJSONState is json.loads(path.read_text()): ok is false when the
// file is missing or isn't JSON (the callers' except clauses).
func readJSONState(path string) (config.Value, bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, nil // OSError: every caller but load_inventory catches it
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if err != nil || len(data) > maxStateBytes {
		return nil, false, nil
	}
	if !isUTF8(data) {
		return nil, false, errInternal // read_text() raises UnicodeDecodeError, which no caller catches
	}
	v, err := config.ParseJSONLastWins(data)
	if err != nil {
		return nil, false, nil
	}
	return v, true, nil
}

// readJSONMap is a state file that must be a JSON object, or nil.
func readJSONMap(path string) (*config.Map, error) {
	v, ok, err := readJSONState(path)
	if err != nil || !ok {
		return nil, err
	}
	m, _ := v.(*config.Map)
	return m, nil
}

// localStamp is time.strftime(layout, time.localtime(ts)) for a number
// (bool included, as isinstance(True, int)); ok is false for anything
// else.
func (s *Server) localStamp(v config.Value, layout string) (string, bool) {
	if _, isStr := v.(string); isStr {
		return "", false
	}
	f, ok := number(v)
	if !ok {
		return "", false
	}
	return unixTime(f).In(s.env.Local).Format(layout), true
}

// jinjaIter is `{% for x in v %}`: undefined is nothing, None or a
// number fails the page.
func jinjaIter(v config.Value, defined bool) ([]config.Value, error) {
	if !defined {
		return nil, nil
	}
	switch x := v.(type) {
	case []config.Value:
		return x, nil
	case *config.Map:
		return x.Keys(), nil
	case string:
		var out []config.Value
		for _, r := range x {
			out = append(out, string(r))
		}
		return out, nil
	}
	return nil, errInternal
}

// jinjaDefault is `{{ item.key|default(alt) }}`: alt only when undefined.
func jinjaDefault(item config.Value, key, alt string) string {
	if v, ok := jinjaGet(item, key); ok {
		return pyStr(v)
	}
	return alt
}

// pyStrList is `", ".join(v)` over a list (or `list(v)`) whose items
// must be strings; anything else raises.
func pyStrList(v config.Value) ([]string, error) {
	items, err := pyIter(v)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(items))
	for i, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, errInternal
		}
		out[i] = s
	}
	return out, nil
}

// configError is the message parse_config gives raw, or "" when it is
// valid: the "does not currently pass validation" banner.
func configError(raw *config.Map) string {
	if _, err := config.Parse(raw); err != nil {
		return err.Error()
	}
	return ""
}

// pyGet is d.get(key, def) on a raw section.
func pyGet(m *config.Map, key string, def config.Value) config.Value {
	if v, ok := m.Get(key); ok {
		return v
	}
	return def
}

// splitStripped is `[x.strip() for x in text.split(",") if x.strip()]`.
func splitStripped(text string) []config.Value {
	out := []config.Value{}
	for _, part := range strings.Split(text, ",") {
		if v := pyStripped(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}
