// Package helper is the apply-helper: the root process that does the
// privileged work the webUI and the parser daemons ask for, one JSON
// line per request on a Unix socket (frfw.helper in 1.x). It answers as
// 1.x does, so a 1.x webUI can talk to it and the other way round;
// reference/test_fros_helper_cases.py records 1.x's answers and the
// tests here replay them.
//
// Two layers decide who gets what: the socket file's mode (the systemd
// socket unit: 0660 root:fr_os-feeds, the one group the webUI and the
// sensors share) decides who can connect, and the peer uid the kernel
// reports (SO_PEERCRED, which the peer can't forge) decides which
// commands that connection may send (Policy).
package helper

// Commands is every command 1.x's apply-helper understands
// (frfw.helper.protocol.COMMANDS, whose comments say what each is for).
// None takes a caller-supplied file path: the helper only touches the
// paths it was started with.
var Commands = []string{
	"ping",
	"apply",
	"rollback",
	"save_config",
	"authorize_ztna",
	"ztna_status",
	"refresh_adblock",
	"ban_ip",
	"quarantine_ip",
	"ids_quarantine_status",
	"conntrack_sample",
	"bruteforce_status",
	"ztna_sessions_status",
	"hw_ram_info",
	"dhcp_leases",
	"iot_sync_isolation",
	"iot_isolation_status",
	"iot_scan",
	"listening_sockets",
	"audit_append",
	"wireguard_status",
	"firewall_drops",
	"xdp_stats",
	"apply_status",
	"apply_confirm",
	"apply_revert",
	"restore_rejected",
	"set_management_addresses",
	"ipv6_status",
	"source_device",
}

// MaxLineBytes bounds a request line, so a misbehaving or malicious
// local peer can't make the helper buffer more (frfw.helper.protocol).
const MaxLineBytes = 64 * 1024

// The one larger reply: the conntrack sample the AI IDS reads. A flow is
// about 100-150 bytes of JSON; the helper sends at most
// ConntrackSampleMaxFlows of them, which fit in ConntrackSampleMaxBytes
// (1.x found 64 KiB held only some 500 flows, ROADMAP FND-1d).
const (
	ConntrackSampleMaxFlows = 65536
	ConntrackSampleMaxBytes = 16 * 1024 * 1024
)
