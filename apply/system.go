package apply

import (
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	"github.com/starsmash29/fr_os-community/appid"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/nft"
	"github.com/starsmash29/fr_os-community/render"
)

// Paths are the files an apply reads and writes, and the kernel's and
// the system's own trees it looks in (frfw.paths and the modules' own
// constants). DefaultPaths are the router's; tests point every one of
// them into a directory of their own.
type Paths struct {
	Config, AppliedConfig, RejectedConfig, SensorConfig string
	// SensorView is the sensor daemons' JSON view of the config (SensorView).
	SensorView                                           string
	ApplyPending, ApplyLock                              string
	BackupDir, ScheduleState, WebUIListen, AuditLog      string
	KeaConfig, XdpState                                  string
	PqcOpenSSLConf, SSHKexDropin, SSHManagementDropin    string
	SSHDPrivsepDir                                       string
	AdblockHosts, AdblockDnsmasqConf, AdblockCategoryDir string
	DNSQueryLog                                          string
	IPv6DhcpcdConf, IPv6RAConf, IPv6ULAState             string
	WireguardKey                                         string
	// IPForward is the IPv4 switch, ProcNet /proc/sys/net (the IPv6
	// settings), NetClass /sys/class/net (which devices there are).
	IPForward, ProcNet, NetClass string
	// Conntrack is the kernel's connection-tracking table.
	Conntrack string
	// ZtnaState notes who signed in where (display only).
	ZtnaState string
	// XdpStats is the XDP SNI filter's pinned packet counters
	// (frfw.xdp.PIN_STATS_PATH).
	XdpStats string
	// XdpObject is the XDP program the image ships; XdpPins is where it
	// and its maps are pinned (prog/ and maps/), on bpffs.
	XdpObject, XdpPins string
	// The programs whose presence an apply checks by path.
	DhcpcdBinary, RADnsmasqBinary string
}

// DefaultPaths are the router's.
func DefaultPaths() Paths {
	return Paths{
		Config: "/etc/fr_os/config.yaml", AppliedConfig: "/etc/fr_os/applied-config.yaml",
		RejectedConfig: "/etc/fr_os/config.rejected.yaml", SensorConfig: "/etc/fr_os/sensor-config.yaml", SensorView: "/etc/fr_os/sensor-view.json",
		ApplyPending: "/etc/fr_os/apply-pending.json", ApplyLock: "/etc/fr_os/.apply.lock",
		BackupDir: BackupDir, ScheduleState: "/etc/fr_os/schedule_state.json",
		WebUIListen: "/etc/fr_os/webui-listen.json", AuditLog: "/var/log/fr_os/audit.log",
		KeaConfig: "/etc/kea/kea-dhcp4.conf", XdpState: "/etc/fr_os/xdp_state.json",
		PqcOpenSSLConf:      "/etc/fr_os/webui_pqc_openssl.cnf",
		SSHKexDropin:        "/etc/ssh/sshd_config.d/50-fr_os-pqc-kex.conf",
		SSHManagementDropin: "/etc/ssh/sshd_config.d/40-fr_os-management.conf",
		SSHDPrivsepDir:      "/run/sshd",
		AdblockHosts:        render.AdblockHostsPath, AdblockDnsmasqConf: "/etc/fr_os/dnsmasq_adblock.conf",
		AdblockCategoryDir: render.AdblockCategoryDir, DNSQueryLog: render.DNSQueryLogPath,
		IPv6DhcpcdConf: "/etc/fr_os/dhcpcd6.conf", IPv6RAConf: "/etc/fr_os/dnsmasq_ra.conf",
		IPv6ULAState: "/etc/fr_os/ipv6_ula.json", WireguardKey: "/etc/fr_os/wireguard/private.key",
		IPForward: "/proc/sys/net/ipv4/ip_forward", ProcNet: "/proc/sys/net", NetClass: "/sys/class/net",
		Conntrack: "/proc/net/nf_conntrack", ZtnaState: "/etc/fr_os/ztna_state.json",
		XdpStats:  "/sys/fs/bpf/fr_os_xdp/maps/stats",
		XdpObject: "/usr/local/share/fr_os/bpf/xdp_sni_filter.o", XdpPins: "/sys/fs/bpf/fr_os_xdp",
		DhcpcdBinary: "/usr/sbin/dhcpcd", RADnsmasqBinary: "/usr/sbin/dnsmasq",
	}
}

// Under is p with every path moved under root, for tests.
func (p Paths) Under(root string) Paths {
	v := reflect.ValueOf(&p).Elem()
	for i := range v.NumField() {
		f := v.Field(i)
		f.SetString(filepath.Join(root, f.String()))
	}
	return p
}

// The units an apply starts, stops and reloads.
const (
	KeaService         = "kea-dhcp4-server"
	AdblockDNSService  = "fr-adblock-dns"
	IPv6Service        = "fr-dhcp6"
	IPv6RAService      = "fr-ra"
	TLSFPService       = "fr-tls-fp.service"
	RevertUnit         = "fr-apply-revert.service"
	SSHGroup           = render.SSHGroup
	SensorUser         = "fr_os-sensor"
	WebUIUnit          = "fr-webui.service"
	webUIRebindUnit    = "fr-webui-rebind"
	sshdBinary         = "sshd"
	defaultConfirmWait = time.Second
)

// sshUnits are Debian's OpenSSH units (the socket one exists but is off
// by default).
var sshUnits = []string{"ssh.service", "ssh.socket"}

// System is everything an apply acts on and asks: the programs it runs,
// the files, who it runs as, the clock and the randomness, and the few
// questions about the machine 1.x answers from Python itself. Tests
// replace any of it; DefaultSystem is the router's.
type System struct {
	Run   Runner
	Paths Paths
	// Euid is os.geteuid().
	Euid func() int
	// Now is the time an apply records (backups, the pending deadline).
	Now func() time.Time
	// Which is shutil.which: whether name is a program on PATH.
	Which func(name string) string
	// LoginUsers are the members of the SSH group with an
	// authorized_keys file (frfw.management.ssh_login_users).
	LoginUsers func() []string
	// Random fills b from the OS's CSPRNG.
	Random func(b []byte) error
	// OpenSSLVersion is the host OpenSSL's version, as (major, minor,
	// patch) and its text (frfw.pqc reads Python's ssl module, which is
	// the host's libssl).
	OpenSSLVersion func() ([3]int, string)
	// ReadRuntime reads the members a ruleset reload carries over (the
	// apply-helper's set readers): see readRuntimeSets.
	ReadRuntime func(c *config.Config) (*nft.RuntimeSets, error)
	// Catalog is the application catalog app control blocks from.
	Catalog *appid.Catalog
	// ConfirmPoll is how often the revert wait looks at the record.
	ConfirmPoll time.Duration
	// Sleep waits (the revert wait).
	Sleep func(time.Duration)
	// Chown is os.Chown, for the files a root apply hands to an account
	// (the sensors' copy, the audit log).
	Chown func(path string, uid, gid int) error
	// Fetch downloads one ad-block list (HTTPFetch): the only thing
	// fetched from the internet, and only for a refresh.
	Fetch func(url string) ([]byte, error)
	// GRO reads whether generic receive offload is on for a device, and
	// SetGRO turns it on or off (the SIOCETHTOOL ioctl, as 1.x: the
	// router has no ethtool). An error is the ioctl's errno.
	GRO    func(device string) (bool, error)
	SetGRO func(device string, on bool) error
}

// DefaultSystem is the router's, with the bundled application catalog;
// ReadRuntime is the caller's to give.
func DefaultSystem() *System {
	catalog, _ := appid.Load() // bundled and checked by its tests
	return &System{
		Catalog: catalog,
		Run:     Run, Paths: DefaultPaths(), Euid: os.Geteuid, Now: time.Now,
		Which:          func(name string) string { p, _ := exec.LookPath(name); return p },
		LoginUsers:     sshLoginUsers,
		Random:         func(b []byte) error { _, err := rand.Read(b); return err },
		OpenSSLVersion: hostOpenSSL,
		ConfirmPoll:    defaultConfirmWait,
		Sleep:          time.Sleep,
		Chown:          os.Chown,
		Fetch:          HTTPFetch,
		GRO:            ethtoolGRO,
		SetGRO:         ethtoolSetGRO,
	}
}

func (s *System) root() bool { return s.Euid() == 0 }

// sshLoginUsers: members of the SSH group whose home has
// ~/.ssh/authorized_keys, sorted.
func sshLoginUsers() []string {
	members, err := groupMembers(SSHGroup)
	if err != nil {
		return nil
	}
	var users []string
	for _, name := range members {
		u, err := user.Lookup(name)
		if err != nil {
			continue
		}
		if st, err := os.Stat(filepath.Join(u.HomeDir, ".ssh", "authorized_keys")); err == nil && st.Mode().IsRegular() {
			users = append(users, name)
		}
	}
	slices.Sort(users)
	return users
}

// groupMembers is grp.getgrnam(name).gr_mem, read from /etc/group (the
// router's accounts are local; os/user has no member list).
func groupMembers(name string) ([]string, error) {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return nil, err
	}
	return parseGroupMembers(string(data), name)
}

var errNoGroup = errors.New("apply: no such group")
