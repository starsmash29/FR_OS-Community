package render

import "strings"

// The webUI's TLS groups (frfw.pqc): the ML-KEM hybrid first where the
// host's OpenSSL knows it (3.5 and later), the classical ones otherwise.
const (
	HybridTLSGroups    = "X25519MLKEM768:X25519:P-256"
	ClassicalTLSGroups = "X25519:P-256"
	// MLKEMKex is OpenSSH's hybrid key exchange (OpenSSH 9.9).
	MLKEMKex = "mlkem768x25519-sha256"
)

var classicalKex = []string{"curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521"}

const opensslHead = `# Managed by FR_OS (frfw.pqc) -- regenerated on every ` + "`apply`" + `, do not
# edit by hand. Referenced only via fr-webui.service's OPENSSL_CONF=
# environment variable (see systemd/fr-webui.service): this affects the
# webUI's own TLS listener alone, never the system-wide
# /etc/ssl/openssl.cnf or any other process on the host.
openssl_conf = fr_os_conf

[fr_os_conf]
ssl_conf = fr_os_ssl_conf

[fr_os_ssl_conf]
system_default = fr_os_ssl_defaults

[fr_os_ssl_defaults]
Groups = `

// OpenSSLConf is the fragment fr-webui's OPENSSL_CONF names
// (frfw.pqc.write_openssl_pqc_conf): TLS 1.3 only, with the hybrid group
// first when hybrid. It is always written, PQC on or off: the unit
// always names it.
func OpenSSLConf(hybrid bool) string {
	groups := ClassicalTLSGroups
	if hybrid {
		groups = HybridTLSGroups
	}
	return opensslHead + groups + "\nMinProtocol = TLSv1.3\nMaxProtocol = TLSv1.3\n"
}

const sshKexHead = `# Managed by FR_OS (frfw.pqc) -- regenerated on every ` + "`apply`" + `, do not
# edit by hand. Requires sshd_config's default
# ` + "`Include /etc/ssh/sshd_config.d/*.conf`" + ` (Debian's own default since
# the openssh 8.4p1 packaging); never touches /etc/ssh/sshd_config
# itself.
KexAlgorithms `

// SSHKexDropin is the PQC KexAlgorithms drop-in (frfw.pqc.sync_ssh_kex):
// the ML-KEM hybrid first when the installed sshd knows it, then the
// classical methods. Never hybrid unless `ssh -Q kex` named it.
func SSHKexDropin(hybrid bool) string {
	methods := classicalKex
	if hybrid {
		methods = append([]string{MLKEMKex}, classicalKex...)
	}
	return sshKexHead + strings.Join(methods, ",") + "\n"
}
