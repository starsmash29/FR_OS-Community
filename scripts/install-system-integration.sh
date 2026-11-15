#!/usr/bin/env bash
# System integration installer for FR_OS, as 1.x's
# scripts/install-system-integration.sh.
#
# Sets up /etc/fr_os, a default config (if none exists yet), the
# unprivileged accounts (firewall-cli ensure-accounts) and, from a
# checkout, the systemd units. Run as root on a Debian box that already
# has FR_OS's binaries in /usr/libexec/fr_os and the nftables and
# kea-dhcp4-server packages; on the image, fr-first-boot.sh runs it.
#
# A plain shell script: it runs once per machine and every step is a
# standard sysadmin primitive (install(1), systemctl(1)).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR=/etc/fr_os
CONFIG_PATH="$CONFIG_DIR/config.yaml"
WEBUI_STATE_DIR="$CONFIG_DIR/webui"
SYSTEMD_DIR=/etc/systemd/system
WEBUI_USER=fr_os-webui
FIREWALL_CLI=${FIREWALL_CLI:-/usr/libexec/fr_os/firewall-cli}

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root" >&2
    exit 1
fi

echo "==> Creating $CONFIG_DIR"
install -d -m 0755 -o root -g root "$CONFIG_DIR"
install -d -m 0750 -o root -g root "$CONFIG_DIR/backups"

echo "==> Ensuring the unprivileged accounts and their state directories exist"
# fr_os-webui (the webUI; $WEBUI_STATE_DIR, 0700), fr_os-sensor (the
# network-parsing daemons) and fr_os-feeds.
"$FIREWALL_CLI" ensure-accounts

# Unlike 1.x, no initial OpenSSL PQC fragment: fr-webui.service sets no
# OPENSSL_CONF (Go's TLS doesn't read it), and the apply writes the
# fragment the System screen reads.

if [[ ! -f "$CONFIG_PATH" && ! -f "$REPO_ROOT/examples/config.yaml" ]]; then
    # The image: no checkout around this script. fr-first-boot writes
    # the config right after (firewall-cli assign-interfaces).
    echo "==> No config at $CONFIG_PATH and no example to copy; fr-first-boot / 'firewall-cli assign-interfaces' writes it"
elif [[ ! -f "$CONFIG_PATH" ]]; then
    echo "==> No config found at $CONFIG_PATH, installing the example config as a starting point"
    install -m 0640 -o root -g "$WEBUI_USER" "$REPO_ROOT/examples/config.yaml" "$CONFIG_PATH"
    echo "    Review/edit it (or re-run 'firewall-cli assign-interfaces') before relying on it."
else
    echo "==> $CONFIG_PATH already exists; ensuring it is readable by '$WEBUI_USER'"
    chgrp "$WEBUI_USER" "$CONFIG_PATH"
    chmod 0640 "$CONFIG_PATH"
fi

echo "==> Loading the WireGuard module at boot (VPN, security-lessons G8)"
echo wireguard > /etc/modules-load.d/fr_os-wireguard.conf

if [[ -f "$REPO_ROOT/go.mod" && -f "$REPO_ROOT/systemd/journald-fr_os.conf" ]]; then
    echo "==> Journal size and age limit, drop-log backend (security-lessons K6)"
    echo nf_log_syslog > /etc/modules-load.d/fr_os-logging.conf
    install -D -m 0644 "$REPO_ROOT/systemd/journald-fr_os.conf" /etc/systemd/journald.conf.d/fr_os.conf
fi

if [[ -f "$REPO_ROOT/go.mod" && -f "$REPO_ROOT/systemd/watchdog-fr_os.conf" ]]; then
    echo "==> Hardware watchdog, when the machine has one (ROADMAP SEC-14)"
    install -D -m 0644 "$REPO_ROOT/systemd/watchdog-fr_os.conf" /etc/systemd/system.conf.d/fr_os-watchdog.conf
fi

echo "==> Installing systemd units"
# A checkout has go.mod next to systemd/ (the image installs this script
# under /usr/libexec/fr_os, beside the system's own /usr/libexec/systemd).
if [[ -f "$REPO_ROOT/go.mod" && -d "$REPO_ROOT/systemd" ]]; then
    # Every unit of the checkout (1.x listed them one by one).
    for unit in "$REPO_ROOT"/systemd/*.service "$REPO_ROOT"/systemd/*.socket \
        "$REPO_ROOT"/systemd/*.timer "$REPO_ROOT"/systemd/*.path; do
        if [[ -f "$unit" ]]; then
            install -m 0644 "$unit" "$SYSTEMD_DIR/"
        fi
    done
else
    echo "==> No systemd/ directory next to this script (the image): the units were installed when the image was built"
fi

echo "==> The console's drop-in directory (port summary, first-boot password)"
install -d -m 0755 /etc/issue.d

echo "==> Reloading systemd"
systemctl daemon-reload

# ROADMAP SEC-18: Debian's nftables.service would load /etc/nftables.conf
# (`flush ruleset`) over the FR_OS ruleset, and flush it when stopped.
# fr-firewall loads the ruleset; the nftables package stays for `nft`.
echo "==> Masking Debian's nftables.service (fr-firewall owns the ruleset)"
systemctl mask nftables.service

cat <<DONE

Done. Next steps:
  firewall-cli set-admin-password        # set the webUI's admin password
  systemctl enable --now fr-firewall     # fails closed: without a working config only
                                        # loopback and established connections get in
  systemctl enable --now fr-apply-helper.socket
  systemctl enable --now fr-webui        # https://<router-ip>/
  systemctl enable --now fr-ai-ids                 # AI IDS anomaly detection (idles until ai_ids.enabled)
  systemctl enable --now fr-iot-scan.timer         # IoT device discovery/isolation (needs iot.enabled)
  systemctl enable --now fr-xdp-sni-logger        # XDP SNI filter event log (needs xdp_sni_filter.enabled)
  systemctl enable --now fr-appid                  # app identification (idles until app_control.enabled)
  systemctl enable --now fr-schedule-check.timer  # keeps time-based rules right across DST changes
  systemctl enable --now fr-tls-fp                # TLS fingerprinting (idles until tls_fingerprint.enabled)
  systemctl enable --now fr-adblock-refresh.timer  # daily ad-block list refresh (needs 'dnsmasq' installed)
  systemctl enable --now fr-update-helper.socket   # the webUI's Update screen (kernel trials)
  systemctl enable --now fr-kernel-prepare.timer   # Debian's newer kernel, ready to try (live router with persistence)
  systemctl enable --now fr-dns-log-trim.timer     # hourly size cap for the resolver's query log
  systemctl enable --now fr-console-ports         # ports, links and the webUI's address on the console

The webUI's self-signed TLS cert is generated on its first start
(stored under $WEBUI_STATE_DIR); your browser will warn about it until
you replace it with a real certificate.

Note: the ad-block screen needs the 'dnsmasq' package installed (FR_OS
runs its own dedicated instance, fr-adblock-dns.service -- it never
touches the system's default dnsmasq.service/dnsmasq.conf). Nothing is
fetched until 'firewall-cli adblock-refresh' is run once (or the
webUI's "Refresh now" button is clicked) -- the daily timer above only
keeps an already-populated list current.
DONE
