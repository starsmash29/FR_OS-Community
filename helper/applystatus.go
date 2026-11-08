package helper

import (
	"errors"
	"math"
	"math/big"
	"os"
	"unicode/utf8"

	"github.com/starsmash29/fr_os-community/config"
)

// pending is the apply waiting to be confirmed (ROADMAP SEC-26,
// frfw.apply_confirm.Pending), without the previous config's text, which
// stays root's.
type pending struct {
	ID        string   `json:"id"`
	Remaining *big.Int `json:"remaining"`
	Seconds   *big.Int `json:"seconds"`
	By        string   `json:"by"`
	Addresses []string `json:"addresses"`
}

type applyStatusReply struct {
	OK       bool     `json:"ok"`
	Pending  *pending `json:"pending"`
	Rejected bool     `json:"rejected"`
}

// applyStatus is what the webUI shows on every page while an apply
// waits.
func (s *Server) applyStatus() (any, error) {
	record, deadline, err := readPending(s.Env.ApplyPendingPath)
	if err != nil {
		return nil, err
	}
	r := applyStatusReply{OK: true, Rejected: isFile(s.Env.RejectedConfigPath)}
	if record != nil {
		// max(0, int(deadline - now + 0.999)): whole seconds, rounded up.
		left, err := truncFloat(deadline - s.Env.Now() + 0.999)
		if err != nil {
			return nil, err
		}
		if left.Sign() < 0 {
			left = big.NewInt(0)
		}
		record.Remaining = left
		r.Pending = record
	}
	return r, nil
}

func isFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// readPending is frfw.apply_confirm.read: the record, or nil when there is
// none or it can't be read (there is nothing it could be reverted to).
// The fields are read as 1.x's str(), float() and int() read them, in
// its order; the one exception 1.x doesn't catch (an infinite float
// where an int belongs) is no reply.
func readPending(path string) (*pending, float64, error) {
	p, deadline, _, err := readPendingFull(path)
	return p, deadline, err
}

// readPendingFull is readPending with the record's previous config text
// (str(data["previous"])), which a revert writes back.
func readPendingFull(path string) (*pending, float64, string, error) {
	text, err := os.ReadFile(path)
	if err != nil || !utf8.Valid(text) {
		return nil, 0, "", nil
	}
	v, err := config.ParseJSONLastWins(text)
	if err != nil {
		return nil, 0, "", nil
	}
	data, ok := v.(*config.Map)
	if !ok {
		return nil, 0, "", nil
	}
	id, ok := data.Get("id")
	if !ok {
		return nil, 0, "", nil
	}
	d, ok := data.Get("deadline")
	if !ok {
		return nil, 0, "", nil
	}
	deadline, err := pyFloatOf(d)
	if err != nil {
		return nil, 0, "", nilUnlessNoReply(err)
	}
	sec, ok := data.Get("seconds")
	if !ok {
		return nil, 0, "", nil
	}
	seconds, err := pyInt(sec)
	if err != nil {
		return nil, 0, "", nilUnlessNoReply(err)
	}
	by, _ := data.Get("by")
	p := &pending{ID: config.Str(id), Seconds: seconds, Addresses: []string{}}
	if config.Truthy(by) {
		p.By = config.Str(by)
	}
	if a, _ := data.Get("addresses"); config.Truthy(a) {
		items, err := pyIter(a)
		if err != nil {
			return nil, 0, "", nil
		}
		for _, item := range items {
			p.Addresses = append(p.Addresses, config.Str(item))
		}
	}
	previous, ok := data.Get("previous")
	if !ok {
		return nil, 0, "", nil
	}
	return p, deadline, config.Str(previous), nil
}

// nilUnlessNoReply: read() catches ValueError and TypeError (no record),
// not OverflowError.
func nilUnlessNoReply(err error) error {
	if errors.Is(err, errNoReply) {
		return err
	}
	return nil
}

// pyFloatOf is float(v). An int too large for a float is an
// OverflowError: no reply.
func pyFloatOf(v config.Value) (float64, error) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	case *big.Int:
		f, _ := new(big.Float).SetInt(x).Float64()
		if math.IsInf(f, 0) {
			return 0, errNoReply
		}
		return f, nil
	case float64:
		return x, nil
	case string:
		if f, ok := config.PyFloat(x); ok {
			return f, nil
		}
		return 0, invalidRequest("could not convert string to float: " + config.Repr(x))
	}
	return 0, invalidRequest("float() argument must be a string or a real number, not '" + pyTypeName(v) + "'")
}
