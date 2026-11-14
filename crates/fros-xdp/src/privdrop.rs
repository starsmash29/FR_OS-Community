//! Leaving root for good once the one privileged step is done (1.x's
//! `frfw.privdrop`). The daemons that read packet data out of the XDP
//! program's ring buffers start as root with nothing but CAP_BPF and
//! what switching user takes, open the pinned map, and become the
//! sensor account before reading a byte of it: the parsing of
//! untrusted input never runs with privileges (security-lessons I1).
//! An open ring buffer keeps working after the drop.

use nix::unistd::{Gid, Group, User, geteuid, getuid, setgid, setgroups, setuid};

/// The account the sensor daemons run as.
pub const SENSOR_USER: &str = "fr_os-sensor";

/// The group of the event feeds and of the apply-helper's sensor
/// commands (and not the webUI's, which reads config.yaml's secrets).
pub const FEEDS_GROUP: &str = "fr_os-feeds";

pub fn is_root() -> bool {
    geteuid().is_root()
}

/// Becomes `user` for good (nobody when it doesn't exist: a dev box),
/// with its own group and only FEEDS_GROUP besides. An error if root
/// could not be left; the caller must then stop.
pub fn drop_privileges(user: &str) -> Result<String, String> {
    let account = match User::from_name(user) {
        Ok(Some(a)) => a,
        Ok(None) => User::from_name("nobody")
            .map_err(|e| format!("looking up nobody: {e}"))?
            .ok_or("no account nobody to drop to")?,
        Err(e) => return Err(format!("looking up {user}: {e}")),
    };
    let extra: Vec<Gid> = match Group::from_name(FEEDS_GROUP) {
        Ok(Some(g)) => vec![g.gid],
        _ => Vec::new(),
    };
    setgroups(&extra).map_err(|e| format!("setgroups: {e}"))?;
    setgid(account.gid).map_err(|e| format!("setgid: {e}"))?;
    setuid(account.uid).map_err(|e| format!("setuid: {e}"))?;
    if getuid().is_root() || geteuid().is_root() {
        return Err(format!(
            "failed to drop root privileges to {:?}",
            account.name
        ));
    }
    Ok(account.name)
}
