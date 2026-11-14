// Command fr-webui serves FR_OS's webUI (package webui) over HTTPS, as
// 1.x's frfw.webui.server does: a self-signed certificate on the first
// run so HTTPS works out of the box, TLS 1.2 at least (1.3 only with
// PQC on, security-lessons H2), and only the management addresses the
// last apply recorded (F2, G4, ROADMAP SEC-5). Binding :443 without
// root is systemd's (AmbientCapabilities=CAP_NET_BIND_SERVICE in
// systemd/fr-webui.service), not this program's.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/webui"
)

// version is the installed release, set at build time
// (-ldflags "-X main.version=...").
var version = "0.0.0-dev"

// shutdownGrace is how long a stopping webUI waits for open requests
// before closing them: a live-log tab is a request that never ends, and
// without a limit every restart (an apply moving the webUI to a new
// address, an update) hung until systemd's stop timeout. The browser's
// EventSource reconnects by itself.
const shutdownGrace = 3 * time.Second

const (
	loopback   = "127.0.0.1"
	anyAddress = "0.0.0.0"
	wanWarning = "management.allow_wan is on: the webUI and SSH are reachable from the internet. " +
		"Use the WireGuard VPN (VPN screen) for remote management instead and turn this off."
)

// stringList is a repeatable flag.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	flags := flag.NewFlagSet("fr-webui", flag.ContinueOnError)
	var hosts stringList
	flags.Var(&hosts, "host", "listen on this address (repeatable); default: the management addresses from the config")
	port := flags.Int("port", 443, "the TCP port")
	certPath := flags.String("cert", "/etc/fr_os/webui/cert.pem", "the TLS certificate")
	keyPath := flags.String("key", "/etc/fr_os/webui/key.pem", "the TLS key")
	configPath := flags.String("config", "/etc/fr_os/config.yaml", "config.yaml")
	listenRecord := flags.String("listen-record", "/etc/fr_os/webui-listen.json",
		"where the last apply recorded the addresses to listen on (ROADMAP SEC-5)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "fr-webui: unexpected argument %q\n", flags.Arg(0))
		return 2
	}

	cfg, _, cfgErr := config.ReadFile(*configPath)
	if cfgErr != nil {
		cfg = nil // the webUI must start anyway: it is how an admin fixes a bad config
	}
	dnsNames, ips := certificateNames(cfg)
	if _, err := ensureSelfSignedCert(*certPath, *keyPath, dnsNames, ips); err != nil {
		fmt.Fprintf(os.Stderr, "fr-webui: %v\n", err)
		return 1
	}
	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fr-webui: %v\n", err)
		return 1
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if cfg != nil && cfg.Pqc.Enabled {
		// Go's default key exchange already prefers X25519MLKEM768; with
		// PQC on, the listener is TLS 1.3-only as in 1.x (frfw.pqc).
		tlsConfig.MinVersion = tls.VersionTLS13
	}

	env := webui.DefaultEnv()
	env.Paths.ConfigFile = *configPath
	handler, err := webui.New(env, version, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "fr-webui: %v\n", err)
		return 1
	}

	addresses := []string(hosts)
	if len(addresses) == 0 {
		addresses = listenAddresses(cfg, *listenRecord)
	}
	fmt.Fprintf(os.Stderr, "fr-webui: listening on %s port %d\n", strings.Join(addresses, ", "), *port)
	listeners, err := bind(addresses, *port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fr-webui: %v\n", err)
		return 1
	}
	server := &http.Server{
		Handler:   handler,
		TLSConfig: tlsConfig,
		// Slow clients don't hold a connection for ever (the 1.x
		// server's keep-alive timeout was 5 s).
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       5 * time.Second,
	}
	errs := make(chan error, len(listeners))
	var wg sync.WaitGroup
	for _, l := range listeners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := server.ServeTLS(l, "", ""); !errors.Is(err, http.ErrServerClosed) {
				errs <- err
			}
		}()
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	status := 0
	select {
	case <-stop:
	case err := <-errs:
		fmt.Fprintf(os.Stderr, "fr-webui: %v\n", err)
		status = 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		server.Close()
	}
	wg.Wait()
	return status
}

// certificateNames are the router's host name and its interfaces'
// static IPv4 addresses, for the self-signed certificate's
// subjectAltName (none without a readable config).
func certificateNames(cfg *config.Config) ([]string, []string) {
	if cfg == nil {
		return nil, nil
	}
	var ips []string
	for _, i := range cfg.Interfaces.Values() {
		if i.Address != "" {
			ip, _, _ := strings.Cut(i.Address, "/")
			ips = append(ips, ip)
		}
	}
	return []string{cfg.Hostname}, ips
}

// listenAddresses is where to listen: the addresses the last apply
// recorded for the config it applied in full (after a rolled-back
// apply config.yaml names addresses the router doesn't have); before
// any apply recorded them, config.yaml's; without a readable config,
// loopback only -- the console is the way in then, not the network.
func listenAddresses(cfg *config.Config, record string) []string {
	if recorded := apply.RecordedWebUIListen(record); recorded != nil {
		for _, a := range recorded {
			if a == anyAddress {
				fmt.Fprintf(os.Stderr, "fr-webui: WARNING: %s\n", wanWarning)
			}
		}
		return recorded
	}
	if cfg == nil {
		return []string{loopback}
	}
	if cfg.Management.AllowWan {
		fmt.Fprintf(os.Stderr, "fr-webui: WARNING: %s\n", wanWarning)
	}
	system := &apply.System{Paths: apply.DefaultPaths()}
	return system.ListenAddresses(cfg)
}

// bind is one listening socket per address. IP_FREEBIND lets it bind an
// address that isn't on an interface yet (a LAN port still coming up,
// the ULA address the boot's apply puts on, ROADMAP FND-1c) instead of
// failing. An IPv6 socket takes IPv6 only: its address is one ULA
// address, never a way in for IPv4.
func bind(addresses []string, port int) ([]net.Listener, error) {
	var out []net.Listener
	for _, address := range addresses {
		ip := net.ParseIP(strings.SplitN(address, "%", 2)[0])
		network := "tcp4"
		if ip == nil || ip.To4() == nil {
			network = "tcp6"
		}
		lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			err := c.Control(func(fd uintptr) {
				if network == "tcp6" {
					if serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1); serr != nil {
						return
					}
					serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6Freebind, 1)
					return
				}
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_FREEBIND, 1)
			})
			return errors.Join(err, serr)
		}}
		l, err := lc.Listen(context.Background(), network, net.JoinHostPort(address, strconv.Itoa(port)))
		if err != nil {
			for _, o := range out {
				o.Close()
			}
			return nil, err
		}
		out = append(out, l)
	}
	return out, nil
}

// ipv6Freebind is linux/in6.h's IPV6_FREEBIND, which package syscall
// doesn't name.
const ipv6Freebind = 78
