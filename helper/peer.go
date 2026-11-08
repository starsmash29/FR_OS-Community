package helper

import (
	"os"
	"os/user"
	"strconv"

	"github.com/starsmash29/fr_os-community/config"
)

// The accounts the two roles go by (frfw.paths).
const (
	WebUIUser  = "fr_os-webui"
	SensorUser = "fr_os-sensor"
)

// Role is what a peer may ask for.
type Role int

const (
	// NoRole may ask for nothing, not even ping.
	NoRole Role = iota
	// Full is root, the helper's own uid (a development run where client
	// and helper are one unprivileged user) and the webUI: everything.
	Full
	// Sensor is the parser daemons' account: only SensorCommands. They
	// parse what strangers send, so one bug in a parser must not be one
	// JSON line from root (save_config + apply).
	Sensor
)

// SensorCommands is what a parser daemon may send: exactly what 1.x's
// AI IDS, TLS fingerprinting and IoT scanner send.
var SensorCommands = map[string]bool{
	"ping":               true,
	"quarantine_ip":      true,
	"conntrack_sample":   true,
	"dhcp_leases":        true,
	"iot_sync_isolation": true,
}

// Policy maps peer uids to roles (frfw.helper.peer.PeerPolicy).
type Policy struct {
	FullUIDs, SensorUIDs map[int]bool
}

// SystemPolicy is the policy for this machine now: root, this process's
// effective uid and fr_os-webui are full, fr_os-sensor is sensor. If one
// uid is both, the narrower role wins.
func SystemPolicy() Policy {
	full := map[int]bool{0: true, os.Geteuid(): true}
	if uid, ok := uidOf(WebUIUser); ok {
		full[uid] = true
	}
	sensor := map[int]bool{}
	if uid, ok := uidOf(SensorUser); ok {
		sensor[uid] = true
		delete(full, uid)
	}
	return Policy{FullUIDs: full, SensorUIDs: sensor}
}

func uidOf(name string) (int, bool) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, false
	}
	uid, err := strconv.Atoi(u.Uid)
	return uid, err == nil
}

// Role is uid's role.
func (p Policy) Role(uid int) Role {
	switch {
	case p.FullUIDs[uid]:
		return Full
	case p.SensorUIDs[uid]:
		return Sensor
	}
	return NoRole
}

// Allows says whether uid may send cmd, the request's "cmd" (any JSON
// value, nil if it has none). For a sensor 1.x asks `cmd in
// SENSOR_COMMANDS`, which Python can't answer for a list or a mapping:
// that is an invalid request.
func (p Policy) Allows(uid int, cmd config.Value) (bool, error) {
	switch p.Role(uid) {
	case Full:
		return true, nil
	case Sensor:
		switch x := cmd.(type) {
		case string:
			return SensorCommands[x], nil
		case []config.Value:
			return false, invalidRequest("unhashable type: 'list'")
		case *config.Map:
			return false, invalidRequest("unhashable type: 'dict'")
		}
	}
	return false, nil
}
