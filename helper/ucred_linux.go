package helper

import (
	"net"
	"syscall"
)

// PeerCredentials is the pid, uid and gid of the process at the other end
// of c, as the kernel recorded them when it connected (SO_PEERCRED).
func PeerCredentials(c *net.UnixConn) (pid, uid, gid int, err error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0, 0, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, 0, 0, err
	}
	if credErr != nil {
		return 0, 0, 0, credErr
	}
	return int(cred.Pid), int(cred.Uid), int(cred.Gid), nil
}
