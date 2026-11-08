// Package reference loads what FR_OS 1.x (Python) did, recorded by
// reference/generate.sh into testdata/reference/: the cases FR_OS 2 must
// reproduce (AGENTS.md, "Differential tests").
//
//   - config.jsonl: a raw config (as parsed from YAML) and whether
//     frfw.config.parse_config accepted it, with its message if not.
//   - ruleset.jsonl: an accepted config, the moment and schedule clock it
//     was rendered at, the runtime set members, and the nft script
//     frfw.nft.build_ruleset produced.
//   - helper.jsonl: a request line to the apply-helper, the peer's role,
//     what nft answered and the files the command read, and the reply.
//
// The Go packages replay these in their tests.
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

// YAMLCase is one yaml.safe_load of a text: the value PyYAML built,
// tagged with its Python type ({"int": "5"}, {"map": [[k, v]...]},
// {"date": ...}; a bare JSON string, bool, null or array is itself), or
// the error. Crash names an exception that isn't a YAMLError (1.x
// crashes); Recursive is a value that contains itself.
type YAMLCase struct {
	ID        string         `json:"id"`
	Input     string         `json:"input"`
	OK        bool           `json:"ok"`
	Value     jsontext.Value `json:"value,omitempty"`
	Recursive bool           `json:"recursive,omitempty"`
	Error     string         `json:"error,omitempty"`
	Crash     string         `json:"crash,omitempty"`
}

// YAMLConfigCase is parse_config of what yaml.safe_load built from a
// text: accepted, refused with Error, or a Crash (not a ConfigError).
type YAMLConfigCase struct {
	ID    string `json:"id"`
	Input string `json:"input"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Crash string `json:"crash,omitempty"`
}

// YAMLCases is every recorded yaml.safe_load of a text.
func YAMLCases() ([]YAMLCase, error) { return load[YAMLCase]("yaml.jsonl") }

// YAMLConfigCases is every recorded parse_config of a loaded text.
func YAMLConfigCases() ([]YAMLConfigCase, error) { return load[YAMLConfigCase]("yaml_config.jsonl") }

// RulesetCases is every recorded build_ruleset call.
func RulesetCases() ([]RulesetCase, error) { return load[RulesetCase]("ruleset.jsonl") }

// NftAnswer is what the recording's nft gave for one set.
type NftAnswer struct {
	RC     int    `json:"rc"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

// HelperFiles are the files a helper case's command read, hex-encoded
// ("" or absent: no file).
type HelperFiles struct {
	ApplyPending *string `json:"apply_pending,omitempty"`
	Rejected     bool    `json:"rejected,omitempty"`
	KeaLeases    *string `json:"kea_leases,omitempty"`
}

// HelperCase is one request to 1.x's apply-helper
// (reference/test_fros_helper_cases.py). Line is the request (LineHex
// its bytes in hex when they aren't UTF-8); Role is "full", "sensor" or "none" for a peer with Uid; Nft maps a
// set's name to nft's answer (a set not named isn't loaded; nil: no nft
// at all); Reply is null when 1.x sent none. Decided names the
// decisions.md entry of a case 2.x answers differently on purpose.
type HelperCase struct {
	ID       string               `json:"id"`
	Line     *string              `json:"line,omitempty"`
	LineHex  string               `json:"line_hex,omitempty"`
	Role     string               `json:"role"`
	UID      int                  `json:"uid"`
	Nft      map[string]NftAnswer `json:"nft"`
	Files    HelperFiles          `json:"files"`
	Now      float64              `json:"now"`
	Reply    jsontext.Value       `json:"reply"`
	NftCalls [][]string           `json:"nft_calls"`
	Decided  string               `json:"decided,omitempty"`
}

// HelperCases is every recorded helper request.
func HelperCases() ([]HelperCase, error) { return load[HelperCase]("helper.jsonl") }
