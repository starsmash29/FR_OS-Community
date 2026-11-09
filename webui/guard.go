package webui

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/starsmash29/fr_os-community/config"
)

// The failed-login counters (1.x's frfw.webui.auth_rate_limiter,
// security-lessons G6):
//
//   - per source: 5 failures within 5 minutes and the source is jailed
//     at the firewall for an hour, through the apply-helper. An IPv6
//     source counts as its host, by the MAC the helper's source_device
//     finds for it (ROADMAP FND-1d, H3);
//   - per account: 10 failures within 15 minutes, from any number of
//     sources, and the account's sign-in is refused for the rest of the
//     window, except from a source it signed in from in the last 90
//     days (a known source), so an attacker can't lock the owner out.
//
// Both, and the known sources, are kept in login_guard.json, so
// restarting the webUI doesn't reset them.

const (
	guardMaxAttempts        = 5
	guardWindow             = 5 * 60
	BanSeconds              = 60 * 60
	guardAccountMaxAttempts = 10
	guardAccountWindow      = 15 * 60
	knownSourceSeconds      = 90 * 24 * 3600
	guardSweepInterval      = 100
	guardMaxTracked         = 5000
	deviceCacheSeconds      = 60
	deviceCacheSize         = 1024
)

// ordered is a dict that keeps insertion order, as the Python one whose
// order the state file shows.
type ordered[V any] struct {
	keys []string
	vals map[string]V
}

func newOrdered[V any]() *ordered[V] { return &ordered[V]{vals: map[string]V{}} }

func (o *ordered[V]) get(k string) (V, bool) { v, ok := o.vals[k]; return v, ok }

func (o *ordered[V]) set(k string, v V) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *ordered[V]) del(k string) {
	if _, ok := o.vals[k]; !ok {
		return
	}
	delete(o.vals, k)
	for i, key := range o.keys {
		if key == k {
			o.keys = append(o.keys[:i:i], o.keys[i+1:]...)
			break
		}
	}
}

func (o *ordered[V]) len() int { return len(o.keys) }

// jailKey is frfw.bruteforce.jail_key: the address itself, an
// IPv4-mapped IPv6 one as its IPv4; an error for what isn't an address
// or has a scope.
func jailKey(ip string) (string, error) {
	a, err := config.ParsePyIP(ip)
	if err != nil {
		return "", err
	}
	if a.HasScope() {
		return "", errors.New("no scope (%) allowed")
	}
	if m, ok := a.IPv4Mapped(); ok {
		return m.String(), nil
	}
	return a.String(), nil
}

type device struct {
	mac  string
	when float64
}

type bruteforceGuard struct {
	env      Env
	path     string
	deviceOf func(string) string
	mu       sync.Mutex
	attempts *ordered[[]float64]
	accounts *ordered[[]float64]
	known    *ordered[*ordered[float64]]
	sweep    int
	devices  map[string]device
}

func newBruteforceGuard(env Env, path string, deviceOf func(string) string) *bruteforceGuard {
	g := &bruteforceGuard{env: env, path: path, deviceOf: deviceOf, attempts: newOrdered[[]float64](),
		accounts: newOrdered[[]float64](), known: newOrdered[*ordered[float64]](), devices: map[string]device{}}
	g.load()
	return g
}

func (g *bruteforceGuard) key(ip string) string {
	key, err := jailKey(ip)
	if err != nil {
		key = ip // a test client's name
	}
	if g.deviceOf == nil || !containsByte(key, ':') {
		return key
	}
	now := g.env.Now()
	g.mu.Lock()
	cached, ok := g.devices[key]
	g.mu.Unlock()
	mac := cached.mac
	if !ok || now-cached.when >= deviceCacheSeconds {
		mac = g.deviceOf(key)
		g.mu.Lock()
		if len(g.devices) >= deviceCacheSize {
			g.devices = map[string]device{}
		}
		g.devices[key] = device{mac, now}
		g.mu.Unlock()
	}
	if mac != "" {
		return "mac:" + mac
	}
	return key
}

func containsByte(s string, b byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return true
		}
	}
	return false
}

func prune(ts []float64, now, window float64) []float64 {
	cutoff := now - window
	for len(ts) > 0 && ts[0] < cutoff {
		ts = ts[1:]
	}
	return ts
}

// recordFailure counts a failed attempt from ip; true exactly once per
// ban, on the attempt that reaches the limit, after which the source's
// count starts again.
func (g *bruteforceGuard) recordFailure(ip string) bool {
	ip = g.key(ip)
	now := g.env.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweep++
	if g.sweep >= guardSweepInterval {
		g.sweep = 0
		g.sweepExpired(now)
	}
	ts, _ := g.attempts.get(ip)
	ts = prune(append(ts, now), now, guardWindow)
	g.attempts.set(ip, ts)
	banned := len(ts) >= guardMaxAttempts
	if banned {
		g.attempts.del(ip)
	}
	g.save()
	return banned
}

// recordSuccess resets ip's failures, and with an account its failures
// too, and makes ip a known source of it. True when the account has
// signed in before, but not from ip (or not for 90 days).
func (g *bruteforceGuard) recordSuccess(ip, account string) bool {
	ip = g.key(ip)
	now := g.env.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.attempts.del(ip)
	newSource := false
	if account != "" {
		g.accounts.del(account)
		known, ok := g.known.get(account)
		if !ok {
			known = newOrdered[float64]()
			g.known.set(account, known)
		}
		seen, had := known.get(ip)
		newSource = known.len() > 0 && (!had || now-seen > knownSourceSeconds)
		known.set(ip, now)
	}
	g.save()
	return newSource
}

func (g *bruteforceGuard) recordAccountFailure(account string) {
	now := g.env.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	ts, ok := g.accounts.get(account)
	if !ok && g.accounts.len() >= guardMaxTracked {
		return
	}
	g.accounts.set(account, prune(append(ts, now), now, guardAccountWindow))
	g.save()
}

// accountLocked is the seconds until account can be tried again from
// ip, 0 for now. A known source of the account is never locked out.
func (g *bruteforceGuard) accountLocked(account, ip string) int64 {
	ip = g.key(ip)
	now := g.env.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if known, ok := g.known.get(account); ok {
		if seen, ok := known.get(ip); ok && now-seen <= knownSourceSeconds {
			return 0
		}
	}
	ts, ok := g.accounts.get(account)
	if ok {
		// 1.x prunes the list in place, also when it only asks.
		ts = prune(ts, now, guardAccountWindow)
		g.accounts.set(account, ts)
	}
	if len(ts) < guardAccountMaxAttempts {
		return 0
	}
	left := int64(ts[0] + guardAccountWindow - now)
	if left < 1 {
		return 1
	}
	return left
}

func (g *bruteforceGuard) sweepExpired(now float64) {
	cutoff := now - guardWindow
	for _, ip := range append([]string(nil), g.attempts.keys...) {
		ts, _ := g.attempts.get(ip)
		if len(ts) == 0 || ts[len(ts)-1] < cutoff {
			g.attempts.del(ip)
		}
	}
	cutoff = now - guardAccountWindow
	for _, a := range append([]string(nil), g.accounts.keys...) {
		ts, _ := g.accounts.get(a)
		if len(ts) == 0 || ts[len(ts)-1] < cutoff {
			g.accounts.del(a)
		}
	}
	if g.attempts.len() > guardMaxTracked { // flooded with one-off sources
		ips := append([]string(nil), g.attempts.keys...)
		sort.SliceStable(ips, func(i, j int) bool {
			a, _ := g.attempts.get(ips[i])
			b, _ := g.attempts.get(ips[j])
			return a[len(a)-1] < b[len(b)-1]
		})
		for _, ip := range ips[:len(ips)-guardMaxTracked] {
			g.attempts.del(ip)
		}
	}
}

func (g *bruteforceGuard) load() {
	if g.path == "" {
		return
	}
	text, err := os.ReadFile(g.path)
	if err != nil {
		return
	}
	v, err := config.ParseJSONLastWins(text)
	if err != nil {
		return
	}
	data, ok := v.(*config.Map)
	if !ok {
		return
	}
	now := g.env.Now()
	lists := func(key string) *ordered[[]float64] {
		out := newOrdered[[]float64]()
		raw, _ := data.Get(key)
		m, ok := raw.(*config.Map)
		if !ok {
			return out
		}
		for i, k := range m.Keys() {
			list, ok := m.Values()[i].([]config.Value)
			if !ok {
				continue
			}
			var ts []float64
			for _, t := range list {
				if f, ok := number(t); ok {
					ts = append(ts, f)
				}
			}
			sort.Float64s(ts)
			out.set(pyStr(k), ts)
		}
		return out
	}
	g.attempts = lists("ips")
	g.accounts = lists("accounts")
	g.known = newOrdered[*ordered[float64]]()
	if raw, _ := data.Get("known"); raw != nil {
		if m, ok := raw.(*config.Map); ok {
			for i, k := range m.Keys() {
				inner, ok := m.Values()[i].(*config.Map)
				if !ok {
					continue
				}
				seen := newOrdered[float64]()
				for j, ip := range inner.Keys() {
					if f, ok := number(inner.Values()[j]); ok && now-f <= knownSourceSeconds {
						seen.set(pyStr(ip), f)
					}
				}
				g.known.set(pyStr(k), seen)
			}
		}
	}
	g.sweepExpired(now)
}

func (g *bruteforceGuard) save() {
	if g.path == "" {
		return
	}
	floats := func(ts []float64) []config.Value {
		out := make([]config.Value, len(ts))
		for i, t := range ts {
			out[i] = t
		}
		return out
	}
	toMap := func(o *ordered[[]float64]) *config.Map {
		m := config.NewMap()
		for _, k := range o.keys {
			v, _ := o.get(k)
			m.Set(k, floats(v))
		}
		return m
	}
	known := config.NewMap()
	for _, a := range g.known.keys {
		inner, _ := g.known.get(a)
		m := config.NewMap()
		for _, ip := range inner.keys {
			t, _ := inner.get(ip)
			m.Set(ip, t)
		}
		known.Set(a, m)
	}
	data := config.NewMap()
	data.Set("ips", toMap(g.attempts))
	data.Set("accounts", toMap(g.accounts))
	data.Set("known", known)
	text, err := config.PyJSON(data, -1, false)
	if err != nil {
		return
	}
	// Counting must never break the sign-in it guards; the in-memory
	// counters still apply.
	_ = writePrivate(g.path, []byte(text), false)
}

// deviceLookup is the guard's deviceOf, through the helper's read-only
// source_device; "" when the helper can't say.
func deviceLookup(h helper) func(string) string {
	return func(ip string) string {
		reply, err := h.SourceDevice(ip)
		if err != nil {
			return ""
		}
		if ok, _ := reply.Get("ok"); !config.Truthy(ok) {
			return ""
		}
		mac, _ := reply.Get("device")
		s, _ := mac.(string)
		return s
	}
}

func lockedMessage(seconds int64) string {
	minutes := (seconds + 59) / 60
	if minutes < 1 {
		minutes = 1
	}
	return fmt.Sprintf("Too many failed sign-ins for this account -- try again in %d minute(s), "+
		"or from a device that has signed in to it before", minutes)
}
