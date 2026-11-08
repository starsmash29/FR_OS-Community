// Package reference loads what FR_OS 1.x (Python) did, recorded by
// reference/generate.sh into testdata/reference/: the cases FR_OS 2 must
// reproduce (AGENTS.md, "Differential tests").
//
//   - config.jsonl: a raw config (as parsed from YAML) and whether
//     frfw.config.parse_config accepted it, with its message if not.
//   - ruleset.jsonl: an accepted config, the moment and schedule clock it
//     was rendered at, the runtime set members, and the nft script
//     frfw.nft.build_ruleset produced.
//
// The Go config and nft packages replay these in their tests.
package reference

import (
	"bufio"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// ConfigCase is one parse_config call.
type ConfigCase struct {
	ID    string         `json:"id"`
	Input jsontext.Value `json:"input"`
	OK    bool           `json:"ok"`
	Error string         `json:"error,omitempty"`
}

// Clock is frfw.nft.schedule.ScheduleClock.
type Clock struct {
	UTCOffsetMinutes  int `json:"utc_offset_minutes"`
	KernelMinutesWest int `json:"kernel_minuteswest"`
}

// RulesetCase is one build_ruleset call.
type RulesetCase struct {
	ID      string         `json:"id"`
	Input   jsontext.Value `json:"input"`
	Now     float64        `json:"now"`
	Clock   *Clock         `json:"clock"`
	Runtime jsontext.Value `json:"runtime"`
	Output  string         `json:"output"`
}

// Dir is testdata/reference in this repository.
func Dir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "reference")
}

func load[T any](name string) ([]T, error) {
	f, err := os.Open(filepath.Join(Dir(), name))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []T
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for n := 1; s.Scan(); n++ {
		var c T
		if err := json.Unmarshal(s.Bytes(), &c, json.RejectUnknownMembers(true)); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, n, err)
		}
		out = append(out, c)
	}
	return out, s.Err()
}

// ConfigCases is every recorded parse_config call.
func ConfigCases() ([]ConfigCase, error) { return load[ConfigCase]("config.jsonl") }

// RulesetCases is every recorded build_ruleset call.
func RulesetCases() ([]RulesetCase, error) { return load[RulesetCase]("ruleset.jsonl") }
