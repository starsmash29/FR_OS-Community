package config

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"strconv"
)

// The checked config: frfw.config.schema in 1.x, field for field. Values
// are normalized the way 1.x stores them (addresses in their canonical
// form, MACs in lower case), because the ruleset builder prints them as
// they are.

// SelfZone is the reserved zone name meaning the router itself.
const SelfZone = "self"

// Action is a rule's verdict.
type Action string

const (
	Accept Action = "accept"
	Drop   Action = "drop"
	Reject Action = "reject"
)

var actions = []string{"accept", "drop", "reject"}

// Protocol is a rule's protocol.
type Protocol string

const (
	ProtoAny  Protocol = "any"
	ProtoTCP  Protocol = "tcp"
	ProtoUDP  Protocol = "udp"
	ProtoICMP Protocol = "icmp"
)

var protocols = []string{"any", "tcp", "udp", "icmp"}

// IotIsolationMode is what an isolated IoT device may still reach.
type IotIsolationMode string

const (
	// IotInternetOnly: the internet (every nat.masquerade zone), DHCP
	// and DNS, nothing else.
	IotInternetOnly IotIsolationMode = "internet_only"
	// IotBlock: DHCP and DNS from the router, nothing routed.
	IotBlock IotIsolationMode = "block"
)

var iotModes = []string{"internet_only", "block"}

// Ordered is a mapping in the order the config wrote it.
type Ordered[T any] struct {
	Keys  []string
	byKey map[string]T
}

func (o *Ordered[T]) set(key string, v T) {
	if o.byKey == nil {
		o.byKey = map[string]T{}
	}
	if _, ok := o.byKey[key]; !ok {
		o.Keys = append(o.Keys, key)
	}
	o.byKey[key] = v
}

// MarshalJSONTo writes the keys and the values in order: the config's
// fingerprint (apply.ConfigFingerprint) is this JSON, and a value left
// out would make two different configs one.
func (o Ordered[T]) MarshalJSONTo(enc *jsontext.Encoder) error {
	return json.MarshalEncode(enc, struct {
		Keys   []string
		Values []T
	}{o.Keys, o.Values()})
}

// Get is the value at key.
func (o *Ordered[T]) Get(key string) (T, bool) {
	v, ok := o.byKey[key]
	return v, ok
}

// Has reports whether key is there.
func (o *Ordered[T]) Has(key string) bool { _, ok := o.byKey[key]; return ok }

// Len is the number of keys.
func (o *Ordered[T]) Len() int { return len(o.Keys) }

// Values are the values in order.
func (o *Ordered[T]) Values() []T {
	out := make([]T, len(o.Keys))
	for i, k := range o.Keys {
		out[i] = o.byKey[k]
	}
	return out
}

type Zone struct {
	Name string
	// Description is whatever the config had there: 1.x doesn't check it.
	Description Value
}

type Interface struct {
	Name, Device, Zone string
	Address            string // "10.0.0.1/24", or "" for none
	Description        Value
	VlanParent         string // "" without a VLAN
	VlanID             int
}

type RuleSchedule struct {
	Days           []int // 0 is Monday
	Start, End     int   // minutes after midnight; End may be 1440
	CutEstablished bool
}

type Rule struct {
	Name     string
	Action   Action
	FromZone string // "" for any
	ToZone   string // "" for any, SelfZone for the router
	Proto    Protocol
	DstPort  string // "443" or "1000-2000", "" for any
	// Normalized networks of either family; nil when the key is absent.
	SrcAddress, DstAddress []string
	Log, RequireZtna       bool
	SrcMac                 string
	Schedule               *RuleSchedule
	Expires                *int64 // Unix time
	srcNets, dstNets       []ipNet
}

// Families are the address families the rule can match: both without
// addresses; with them, those every address field names.
func (r *Rule) Families() map[int]bool {
	out := map[int]bool{4: true, 6: true}
	for _, nets := range [][]ipNet{r.srcNets, r.dstNets} {
		if len(nets) == 0 {
			continue
		}
		has := map[int]bool{}
		for _, n := range nets {
			has[n.version] = true
		}
		for v := range out {
			if !has[v] {
				delete(out, v)
			}
		}
	}
	return out
}

// IPv4AddressesOnly: it names addresses, and no IPv6 ones, so over IPv6
// the hosts it names get around it (ROADMAP FND-1b, FND-1d).
func (r *Rule) IPv4AddressesOnly() bool {
	return (len(r.SrcAddress) > 0 || len(r.DstAddress) > 0) && !r.Families()[6]
}

type Masquerade struct{ OutZone string }

type PortForward struct {
	Name, InZone    string
	Proto           Protocol
	DstPort, ToPort int
	ToAddress       string
}

type NatConfig struct {
	Masquerade   []Masquerade
	PortForwards []PortForward
}

type DhcpReservation struct{ MacAddress, Address, Hostname string }

type DhcpPool struct {
	Zone                 string
	RangeStart, RangeEnd string
	DNSServers           []string
	LeaseTime            int64
	// LeaseTimeTrue: the config wrote lease_time: true, which 1.x takes
	// as an integer (1) and keeps as the bool, so Kea's config says true.
	LeaseTimeTrue bool
	Reservations  []DhcpReservation
}

type DhcpConfig struct{ Zones Ordered[DhcpPool] }

type AiIdsConfig struct {
	Enabled                   bool
	ExcludedMacs              []string
	QuarantineDurationSeconds int64
}

type UpdateConfig struct {
	Repo                string
	AutoInstallSecurity bool
	KernelUpdates       bool
}

type XdpSniFilterConfig struct {
	Enabled    bool
	Interfaces []string
	Blocklist  []string
}

type ZtnaUser struct{ Username, PasswordHash string }

type ZtnaConfig struct {
	Enabled           bool
	SessionTTLSeconds int64
	Users             []ZtnaUser
}

type PqcConfig struct{ Enabled bool }

type AdblockerConfig struct {
	Enabled          bool
	SourceURLs       []string
	XdpCriticalLimit int64
	Categories       Ordered[[]string]
	Allowlist        []string
	ServeLan         bool
	ForceDNS         bool
	QueryLogging     bool
}

type LocalDnsConfig struct {
	Domain           string
	Hosts, Overrides Ordered[string]
}

type IotConfig struct {
	Enabled                   bool
	Zones                     []string
	AutoIsolate               bool
	IsolationMode             IotIsolationMode
	TrustedMacs, IsolatedMacs []string
}

type AppControlConfig struct {
	Enabled                 bool
	BlockedApps             []string
	BlockViaXdp, ObserveSni bool
}

type TlsFingerprintEntry struct{ Fingerprint, Label string }

type TlsFingerprintConfig struct {
	Enabled           bool
	Blocklist         []TlsFingerprintEntry
	QuarantineOnMatch bool
}

type MetricsConfig struct {
	Site        *string
	TokenSHA256 *string
}

type ManagementConfig struct {
	Zones               []string
	AllowWan            bool
	ConfirmApplySeconds int64
	Addresses           []string
	IPv6                bool
}

type WireguardPeer struct {
	Name, PublicKey, Address string // Address is "a.b.c.d/32"
	DualStack                bool
}

type WireguardConfig struct {
	Enabled    bool
	ListenPort int
	Address    string
	Zone       string
	Endpoint   string
	Peers      []WireguardPeer
}

type LoggingConfig struct {
	Drops          bool
	DropsPerMinute int
}

type Ipv6Pinhole struct {
	Name, Zone, Host string
	Proto            Protocol
	PortFrom, PortTo int
	Source           string // an IPv6 network, "" for anywhere
}

type Ipv6Config struct {
	Enabled bool
	// LanZones is nil when the config leaves the choice to the router.
	LanZones  []string
	UlaPrefix string
	Pinholes  []Ipv6Pinhole
}

// Config is a checked config.yaml.
type Config struct {
	// Version is 1, as the config wrote it (1.x accepts 1.0 and true).
	Version        Value
	Hostname       string
	Interfaces     Ordered[Interface]
	Zones          Ordered[Zone]
	Rules          []Rule
	Nat            NatConfig
	Dhcp           DhcpConfig
	AiIds          AiIdsConfig
	Update         UpdateConfig
	XdpSniFilter   XdpSniFilterConfig
	Ztna           ZtnaConfig
	Pqc            PqcConfig
	Adblocker      AdblockerConfig
	LocalDNS       LocalDnsConfig
	IPv6           Ipv6Config
	Iot            IotConfig
	AppControl     AppControlConfig
	TlsFingerprint TlsFingerprintConfig
	Metrics        MetricsConfig
	Management     ManagementConfig
	Wireguard      WireguardConfig
	Logging        LoggingConfig
	Timezone       string // "" for the router's own
}

// SrcNetworks are the networks of family version (4 or 6) in
// SrcAddress, in its order: Rule.networks("src_address", version).
func (r *Rule) SrcNetworks(version int) []string { return networksOf(r.SrcAddress, r.srcNets, version) }

// DstNetworks are DstAddress's, as SrcNetworks.
func (r *Rule) DstNetworks(version int) []string { return networksOf(r.DstAddress, r.dstNets, version) }

func networksOf(texts []string, nets []ipNet, version int) []string {
	var out []string
	for i, n := range nets {
		if n.version == version {
			out = append(out, texts[i])
		}
	}
	return out
}

// IsSuffix: Host is an interface identifier (the upper 64 bits zero),
// matched in whatever prefix the zone has now.
func (p *Ipv6Pinhole) IsSuffix() bool {
	a, err := parseIPv6Address(p.Host)
	return err == nil && a.ip.hi == 0
}

// Port is "443", or "1000-1010" for a range.
func (p *Ipv6Pinhole) Port() string {
	if p.PortFrom == p.PortTo {
		return strconv.Itoa(p.PortFrom)
	}
	return fmt.Sprintf("%d-%d", p.PortFrom, p.PortTo)
}

// ManagementZones are the zones the webUI and SSH are reachable from
// (frfw.management.management_zones).
func (c *Config) ManagementZones() map[string]bool { return managedZones(c) }

// IPv6LanExclusions: zone -> why it can't have IPv6 (ROADMAP FND-1b,
// frfw.config.loader.ipv6_lan_exclusions).
func (c *Config) IPv6LanExclusions() map[string]string {
	return ipv6LanExclusions(&c.Zones, &c.Nat, c.Rules)
}

// IPv6ExcludedZones are (zone, why) for each zone with an interface
// left out of the default ipv6.lan_zones (frfw.ipv6.excluded_zones):
// none while IPv6 is off or the list is explicit, which the loader
// refuses such a zone in.
func (c *Config) IPv6ExcludedZones() []ZoneReason {
	if !c.IPv6.Enabled || c.IPv6.LanZones != nil {
		return nil
	}
	withInterface := map[string]bool{}
	for _, i := range c.Interfaces.Values() {
		withInterface[i.Zone] = true
	}
	var out []ZoneReason
	for _, e := range ipv6LanExclusionList(&c.Zones, &c.Nat, c.Rules) {
		if withInterface[e.Zone] {
			out = append(out, e)
		}
	}
	return out
}
