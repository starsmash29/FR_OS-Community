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
//   - render.jsonl: the files an apply writes, rendered from a config.
//   - apply.jsonl: a session of applies, confirmations, reverts,
//     rollbacks and saves against a fake system: the programs run, the
//     replies, and the files before and after.
//   - qr.jsonl: a text and the QR code SVG segno draws for it with 1.x's
//     webUI settings (level M, the scale, its colours).
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
	// Dump is what yaml.safe_dump(value, sort_keys=False) wrote for the
	// value loaded; DumpCrash the exception it raised instead.
	Dump      *string `json:"dump,omitempty"`
	DumpCrash string  `json:"dump_crash,omitempty"`
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

// RenderCase is one config's rendered files (reference/
// test_fros_render_cases.py), or one PQC fragment.
type RenderCase struct {
	ID string `json:"id"`
	// Config is the id of the config's case in config.jsonl; "" for a
	// PQC fragment.
	Config string `json:"config"`
	// ULAState is the generated ULA prefix the router's state file held,
	// nil for none. With one, Output holds only what it changed.
	ULAState *string `json:"ula_state"`
	// Pqc ("tls" or "ssh") and Hybrid say which PQC fragment it is.
	Pqc    string `json:"pqc"`
	Hybrid bool   `json:"hybrid"`
	// Output is each renderer's text (sysctl: [key, value] pairs);
	// Error the type of what a renderer raised instead.
	Output map[string]jsontext.Value `json:"output"`
	Error  map[string]string         `json:"error"`
}

// RenderCases are render.jsonl's cases.
func RenderCases() ([]RenderCase, error) { return load[RenderCase]("render.jsonl") }

// ApplyFile is one file of an apply case's tree: its mode, and its text
// (Hex when it isn't UTF-8, SHA256 and Len when it is large). A nil
// entry under a name ending in "/" is an empty directory.
type ApplyFile struct {
	Mode   string  `json:"mode"`
	Text   *string `json:"text,omitempty"`
	Hex    string  `json:"hex,omitempty"`
	SHA256 string  `json:"sha256,omitempty"`
	Len    int     `json:"len,omitempty"`
}

// ApplyAnswer is what a program says: the first entry whose Argv is a
// prefix of the call's (After lets that many such calls through to the
// entries below). Error is "missing" (not installed) or "timeout".
type ApplyAnswer struct {
	Argv   []string `json:"argv"`
	After  int      `json:"after,omitempty"`
	RC     int      `json:"rc,omitempty"`
	Stdout string   `json:"stdout,omitempty"`
	Stderr string   `json:"stderr,omitempty"`
	Error  string   `json:"error,omitempty"`
}

// ApplyCall is one program 1.x ran: its argv, its input (a string, or
// {"sha256", "len"} when long, or null) and its timeout in seconds.
type ApplyCall struct {
	Argv    []string       `json:"argv"`
	Input   jsontext.Value `json:"input"`
	Timeout jsontext.Value `json:"timeout"`
}

// ApplyStep is one request of an apply session: 1.x's reply, or the
// type and text of the exception it let through (no reply), and the
// programs it ran.
type ApplyStep struct {
	Request jsontext.Value `json:"request"`
	Reply   jsontext.Value `json:"reply,omitempty"`
	Raised  string         `json:"raised,omitempty"`
	Error   string         `json:"error,omitempty"`
	Calls   []ApplyCall    `json:"calls"`
}

// ApplyCase is one session with 1.x's apply-helper against a fake system
// (reference/test_fros_apply_cases.py). Paths are under "@ROOT@", the
// temporary directory is "@TMP@" (a temporary file's name "@TMP@/tmp*").
// Table answers the programs, OpenSSL is the host's ([major, minor,
// patch, text], as Python's ssl module says), Random is the randomness it drew (hex),
// Setup and Files are the tree before and after; Leaks are paths 1.x
// touched outside the root.
type ApplyCase struct {
	ID      string                `json:"id"`
	Setup   map[string]*ApplyFile `json:"setup"`
	Table   []ApplyAnswer         `json:"table"`
	Random  string                `json:"random"`
	Now     float64               `json:"now"`
	OpenSSL jsontext.Value        `json:"openssl"`
	// LoginUsers are who can log in with SSH (frfw.management.ssh_login_users).
	LoginUsers []string              `json:"login_users"`
	Steps      []ApplyStep           `json:"steps"`
	Files      map[string]*ApplyFile `json:"files"`
	Leaks      []string              `json:"leaks"`
	Decided    string                `json:"decided,omitempty"`
	// Fetch answers the downloads (urllib.request.urlopen), by URL.
	Fetch []ApplyFetch `json:"fetch,omitempty"`
}

// ApplyFetch is what one URL answers: a Body (Hex when it isn't
// UTF-8), an HTTP Status with its Reason, or a URLError's Error.
type ApplyFetch struct {
	URL    string  `json:"url"`
	Body   *string `json:"body,omitempty"`
	Hex    string  `json:"hex,omitempty"`
	Status int     `json:"status,omitempty"`
	Reason string  `json:"reason,omitempty"`
	Error  string  `json:"error,omitempty"`
}

// ApplyCases is every recorded apply session.
func ApplyCases() ([]ApplyCase, error) { return load[ApplyCase]("apply.jsonl") }

// FormValue is a form field as the session sent it: one value, or a
// list of them (the same name repeated, as a ticked group of checkboxes).
type FormValue []string

// UnmarshalJSON reads a string or a list of strings.
func (f *FormValue) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*f = FormValue{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*f = many
	return nil
}

// WebUIStep is one request of a webUI session and 1.x's answer: the
// form or JSON body and the headers and cookies sent; the status, the
// headers (but date, server and content-length) and the body (Hex when
// it isn't UTF-8, SHA256 when it is large); the helper requests it made,
// with the replies, and the programs it ran. A step with only Advance
// moves the clock that many seconds.
type WebUIStep struct {
	Advance         *float64             `json:"advance,omitempty"`
	Method          string               `json:"method"`
	Path            string               `json:"path"`
	Form            map[string]FormValue `json:"form"`
	JSON            jsontext.Value       `json:"json"`
	Headers         map[string]string    `json:"headers"`
	Cookies         map[string]string    `json:"cookies"`
	Status          int                  `json:"status"`
	ResponseHeaders [][2]string          `json:"response_headers"`
	Helper          jsontext.Value       `json:"helper"`
	Programs        jsontext.Value       `json:"programs"`
	Body            *string              `json:"body,omitempty"`
	BodyHex         string               `json:"body_hex,omitempty"`
	BodySHA256      string               `json:"body_sha256,omitempty"`
}

// WebUICase is one session with 1.x's webUI through Starlette's
// TestClient, at https://router.lan (reference/test_fros_webui_cases.py).
// Random is the randomness it drew (hex): the setup's first, then the
// steps' from RandomStart on. Table answers the helpers before Base
// does (the first entry for the command and socket; Times limits how
// often, Error makes it unreachable); Programs and ProgramBase answer
// the programs. FilesBefore and FilesAfter are the tree, each file its
// text or {"hex"} or {"sha256", "size"}.
type WebUICase struct {
	ID          string                    `json:"id"`
	Session     string                    `json:"session"`
	Version     string                    `json:"version"`
	Codename    string                    `json:"codename"`
	Now         float64                   `json:"now"`
	Random      string                    `json:"random"`
	RandomStart int                       `json:"random_start"`
	CPUs        int                       `json:"cpus"`
	Disk        []int64                   `json:"disk"`
	Uname       []string                  `json:"uname"`
	Table       []WebUIAnswer             `json:"table"`
	Base        []WebUIAnswer             `json:"base"`
	Programs    []ApplyAnswer             `json:"programs"`
	ProgramBase []ApplyAnswer             `json:"program_base"`
	FilesBefore map[string]jsontext.Value `json:"files_before"`
	Steps       []WebUIStep               `json:"steps"`
	FilesAfter  map[string]jsontext.Value `json:"files_after"`
	Leaks       []string                  `json:"leaks"`
}

// WebUIAnswer is what a helper answers a command with.
type WebUIAnswer struct {
	Cmd    string         `json:"cmd"`
	Socket string         `json:"socket,omitempty"`
	Times  *int           `json:"times,omitempty"`
	Error  jsontext.Value `json:"error,omitempty"`
	Reply  jsontext.Value `json:"reply,omitempty"`
	// Save: the answer also writes the request's YAML to config.yaml, as
	// the real save_config does.
	Save bool `json:"save,omitempty"`
	// For the update check's GitHub requests (Socket "https", Cmd the
	// URL): Status is an HTTP error, Reason a connection that failed.
	Status int    `json:"status,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// WebUICases is every recorded webUI session.
func WebUICases() ([]WebUICase, error) { return load[WebUICase]("webui.jsonl") }

// QRCase is one QR code 1.x's webUI would draw: segno.make(Text,
// error="m") saved as SVG at Scale, dark #0C141F on #FFFFFF.
type QRCase struct {
	ID    string `json:"id"`
	Text  string `json:"text"`
	Scale int    `json:"scale"`
	SVG   string `json:"svg"`
}

// QRCases are qr.jsonl's cases.
func QRCases() ([]QRCase, error) { return load[QRCase]("qr.jsonl") }
