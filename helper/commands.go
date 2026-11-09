package helper

import (
	"fmt"
	"math"
	"math/big"
	"slices"

	"github.com/starsmash29/fr_os-community/config"
)

// reply is {"ok": ..., "message": ...}, 1.x's answer for most commands
// and every refusal.
type reply struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func message(ok bool, text string) reply { return reply{OK: ok, Message: text} }

// dispatch runs one allowed command. A command 1.x knows that isn't
// ported yet says so rather than pretending to be unknown.
func (s *Server) dispatch(cmd config.Value, request *config.Map) (any, error) {
	name, _ := cmd.(string)
	switch name {
	case "ping":
		return message(true, "pong"), nil
	case "apply_status":
		return s.applyStatus()
	case "bruteforce_status":
		return s.bruteforceStatus()
	case "ztna_sessions_status":
		return s.ztnaSessionsStatus()
	case "ids_quarantine_status":
		return s.idsQuarantineStatus()
	case "iot_isolation_status":
		return s.iotIsolationStatus()
	case "dhcp_leases":
		return s.dhcpLeases()
	case "iot_scan":
		return s.cmdIotScan()
	case "wireguard_status":
		return s.cmdWireguardStatus()
	case "firewall_drops":
		return s.cmdFirewallDrops()
	case "xdp_stats":
		return s.cmdXdpStats()
	case "ipv6_status":
		return s.cmdIPv6Status()
	case "listening_sockets":
		return s.cmdListeningSockets()
	case "hw_ram_info":
		return s.cmdHwRAMInfo()
	case "apply":
		return s.cmdApply(request)
	case "apply_confirm":
		return s.cmdApplyConfirm(request)
	case "apply_revert":
		return s.cmdApplyRevert()
	case "restore_rejected":
		return s.cmdRestoreRejected()
	case "rollback":
		return s.cmdRollback()
	case "ban_ip":
		return s.cmdBanIP(request)
	case "source_device":
		return s.cmdSourceDevice(request)
	case "quarantine_ip":
		return s.cmdQuarantineIP(request)
	case "conntrack_sample":
		return s.cmdConntrackSample()
	case "authorize_ztna":
		return s.cmdAuthorizeZtna(request)
	case "ztna_status":
		return s.cmdZtnaStatus(request)
	case "iot_sync_isolation":
		return s.cmdIotSyncIsolation(request)
	case "audit_append":
		return s.cmdAuditAppend(request)
	case "save_config":
		return s.cmdSaveConfig(request)
	case "set_management_addresses":
		return s.cmdSetManagementAddresses(request)
	case "refresh_adblock":
		return s.cmdRefreshAdblock()
	}
	if slices.Contains(Commands, name) {
		return message(false, fmt.Sprintf("command %s is not in FR_OS 2 yet", config.Repr(cmd))), nil
	}
	return message(false, "unknown command "+config.Repr(cmd)), nil
}

// pyTypeName is type(v).__name__.
func pyTypeName(v config.Value) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case *big.Int:
		return "int"
	case float64:
		return "float"
	case string:
		return "str"
	case []config.Value:
		return "list"
	case *config.Map:
		return "dict"
	}
	return "object"
}

// pyIter is iter(v)'s items: a list's items, a dict's keys, a str's
// characters. Anything else is a TypeError, which reaches 1.x's request
// handler as an invalid request.
func pyIter(v config.Value) ([]config.Value, error) {
	switch x := v.(type) {
	case []config.Value:
		return x, nil
	case *config.Map:
		return x.Keys(), nil
	case string:
		out := []config.Value{}
		for _, r := range x {
			out = append(out, string(r))
		}
		return out, nil
	}
	return nil, invalidRequest(fmt.Sprintf("'%s' object is not iterable", pyTypeName(v)))
}

// pyGet is v.get(key) on what 1.x expects to be a dict; anything else is
// an AttributeError, which nothing in 1.x catches: no reply.
func pyGet(v config.Value, key string) (config.Value, error) {
	m, ok := v.(*config.Map)
	if !ok {
		return nil, errNoReply
	}
	x, _ := m.Get(key)
	return x, nil
}

// pyInt is int(v): an OverflowError (an infinite float) is no reply, a
// ValueError or TypeError an invalid request.
func pyInt(v config.Value) (*big.Int, error) {
	switch x := v.(type) {
	case bool:
		if x {
			return big.NewInt(1), nil
		}
		return big.NewInt(0), nil
	case *big.Int:
		return x, nil
	case float64:
		return truncFloat(x)
	case string:
		if n, ok := config.PyInt(x); ok {
			return n, nil
		}
		return nil, invalidRequest("invalid literal for int() with base 10: " + config.Repr(x))
	}
	return nil, invalidRequest(fmt.Sprintf("int() argument must be a string, a bytes-like object or a real number, not '%s'",
		pyTypeName(v)))
}

// truncFloat is int(f).
func truncFloat(f float64) (*big.Int, error) {
	switch {
	case math.IsNaN(f):
		return nil, invalidRequest("cannot convert float NaN to integer")
	case math.IsInf(f, 0):
		return nil, errNoReply
	}
	n, _ := new(big.Float).SetFloat64(math.Trunc(f)).Int(nil)
	return n, nil
}
