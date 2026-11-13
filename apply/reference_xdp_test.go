package apply_test

import (
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"slices"
	"strconv"
	"strings"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/internal/reference"
)

// 1.x keeps the XDP filter's pins with bpftool; FR_OS 2 with fr-xdp
// (decisions.md, "phase 4d-2"). The replay holds the Go apply to the
// recording through this one translation of the calls, and nothing
// else:
//
//   - `bpftool prog loadall OBJ P/prog type xdp pinmaps P/maps` is
//     `fr-xdp load -- OBJ P/prog P/maps`;
//   - `bpftool -j prog show pinned PROG` is `fr-xdp prog-id -- PROG`,
//     answered with the same JSON;
//   - the blocklist's `bpftool map dump`, then one `map delete` per key
//     no longer wanted and one `map update` per key missing, are one
//     `fr-xdp blocklist -- MAP` whose input is every key wanted (the
//     dumped ones not deleted, and the updated ones), one hex line each;
//     a failing call fails it with 1.x's message on stderr, which the
//     apply reports as it is;
//   - the settings' `bpftool map update` is `fr-xdp settings -- MAP N`;
//   - the stats' `bpftool map dump` is `fr-xdp stats -- MAP`, answered
//     with the same JSON;
//   - 1.x's message for a missing bpftool is FR_OS 2's for a missing
//     fr-xdp.
//
// The ioctl that reads and sets GRO is recorded as a call
// ["ioctl", "SIOCETHTOOL", device, command(, value)] (rc the errno), and
// the Go apply's GRO hooks make the same call to the fake.

const bpftoolMissing = "'bpftool' not found; install the linux-tools package matching this kernel"

var xdpToolMissing = "'" + apply.XdpTool + "' not found; this FR_OS installation is incomplete"

// xdpAnswer is what the fake answers one fr-xdp call with.
type xdpAnswer struct {
	argv []string
	res  apply.Result
	err  error
}

// anyInput marks a call whose input isn't known from the recording (a
// blocklist sync 1.x gave up on part-way).
var anyInput = []byte(`{"any": true}`)

// answerOf is the table's answer for argv, as the fake gives it.
func answerOf(table []reference.ApplyAnswer, passed map[int]int, argv []string) (apply.Result, error) {
	for i, a := range table {
		if len(a.Argv) <= len(argv) && slices.Equal(argv[:len(a.Argv)], a.Argv) {
			if passed[i] < a.After {
				passed[i]++
				continue
			}
			switch a.Error {
			case "missing":
				return apply.Result{}, apply.ErrNotFound
			case "timeout":
				return apply.Result{}, &apply.TimeoutError{Argv: argv}
			}
			return apply.Result{Stdout: a.Stdout, Stderr: a.Stderr, Code: a.RC}, nil
		}
	}
	return apply.Result{}, nil
}

// keyArg is the bytes of a `key 0x.. 0x..` argument list.
func keyArg(argv []string) []byte {
	i := slices.Index(argv, "key")
	var out []byte
	for _, a := range argv[i+1:] {
		if a == "value" {
			break
		}
		b, err := strconv.ParseUint(strings.TrimPrefix(a, "0x"), 16, 8)
		if err != nil {
			return nil
		}
		out = append(out, byte(b))
	}
	return out
}

// dumpedKeys are the keys of bpftool's BTF dump of the LPM trie
// ("reversed" is a list of numbers).
func dumpedKeys(stdout string) []string {
	var entries []struct {
		Key struct {
			Prefixlen uint32 `json:"prefixlen"`
			Reversed  []int  `json:"reversed"`
		} `json:"key"`
		Value jsontext.Value `json:"value"`
	}
	if json.Unmarshal([]byte(stdout), &entries, json.RejectUnknownMembers(false)) != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		key := make([]byte, apply.LPMKeySize)
		p := e.Key.Prefixlen
		key[0], key[1], key[2], key[3] = byte(p), byte(p>>8), byte(p>>16), byte(p>>24)
		for j, b := range e.Key.Reversed {
			key[4+j] = byte(b)
		}
		out = append(out, hex.EncodeToString(key))
	}
	return out
}

func failed(res apply.Result, err error) bool { return err != nil || res.Code != 0 }

// translateXDP is a step's recorded calls as FR_OS 2 makes them, and
// the answers to its fr-xdp calls, in order.
func translateXDP(table []reference.ApplyAnswer, passed map[int]int,
	calls []reference.ApplyCall) ([]reference.ApplyCall, []xdpAnswer) {
	var out []reference.ApplyCall
	var answers []xdpAnswer
	tool := func(c reference.ApplyCall, input []byte, res apply.Result, err error, args ...string) {
		argv := append([]string{apply.XdpTool}, args...)
		if input == nil {
			input = []byte("null")
		}
		out = append(out, reference.ApplyCall{Argv: argv, Input: input, Timeout: c.Timeout})
		answers = append(answers, xdpAnswer{argv, res, err})
	}
	for i := 0; i < len(calls); i++ {
		c := calls[i]
		a := c.Argv
		if len(a) == 0 || a[0] != "bpftool" {
			out = append(out, c)
			continue
		}
		res, err := answerOf(table, passed, a)
		switch {
		case len(a) == 9 && a[1] == "prog" && a[2] == "loadall":
			tool(c, nil, res, err, "load", "--", a[3], a[4], a[8])
		case len(a) == 6 && a[1] == "-j" && a[2] == "prog":
			tool(c, nil, res, err, "prog-id", "--", a[5])
		case len(a) == 5 && a[1] == "map" && a[2] == "dump" && strings.HasSuffix(a[4], "/maps/stats"):
			tool(c, nil, res, err, "stats", "--", a[4])
		case a[1] == "map" && a[2] == "update" && strings.HasSuffix(a[4], "/maps/settings"):
			v := keyArg(append([]string{"key"}, a[slices.Index(a, "value")+1:]...))
			flags := uint32(v[0]) | uint32(v[1])<<8 | uint32(v[2])<<16 | uint32(v[3])<<24
			if failed(res, err) && err == nil {
				// The apply adds 1.x's "Updating ... failed" itself.
				res = apply.Result{Code: res.Code, Stdout: res.Stdout, Stderr: res.Stderr}
			}
			tool(c, nil, res, err, "settings", "--", a[4], strconv.FormatUint(uint64(flags), 10))
		case len(a) == 5 && a[1] == "map" && a[2] == "dump":
			// The blocklist: the dump, then its deletes and updates.
			bl := a[4]
			wanted := map[string]bool{}
			var gres apply.Result
			gerr := err
			complete := true
			if failed(res, err) {
				complete = false
				if err == nil {
					gres = apply.Result{Code: 1, Stderr: "Dumping " + bl + " failed:\n" + res.Stderr}
				}
			} else {
				for _, k := range dumpedKeys(res.Stdout) {
					wanted[k] = true
				}
			}
			for complete && i+1 < len(calls) {
				n := calls[i+1].Argv
				if len(n) < 5 || n[0] != "bpftool" || n[1] != "map" || (n[2] != "delete" && n[2] != "update") ||
					n[4] != bl {
					break
				}
				i++
				r, e := answerOf(table, passed, n)
				key := hex.EncodeToString(keyArg(n))
				if failed(r, e) {
					complete, gerr = false, e
					if e == nil {
						verb := map[string]string{"delete": "Deleting from ", "update": "Updating "}[n[2]]
						gres = apply.Result{Code: 1, Stderr: verb + bl + " failed:\n" + r.Stderr}
					}
					break
				}
				if n[2] == "delete" {
					delete(wanted, key)
				} else {
					wanted[key] = true
				}
			}
			input := anyInput
			if complete {
				var b strings.Builder
				for _, k := range slices.Sorted(func(yield func(string) bool) {
					for k := range wanted {
						if !yield(k) {
							return
						}
					}
				}) {
					b.WriteString(k + "\n")
				}
				input, _ = json.Marshal(b.String())
				if b.Len() == 0 {
					input = nil
				}
			}
			tool(c, input, gres, gerr, "blocklist", "--", bl)
		default:
			out = append(out, c) // nothing FR_OS 2 makes: the replay fails on it
		}
	}
	return out, answers
}
