//go:build !linux

package helper

import (
	"errors"
	"net"
)

// PeerCredentials needs Linux's SO_PEERCRED: elsewhere every peer is
// refused.
func PeerCredentials(c *net.UnixConn) (pid, uid, gid int, err error) {
	return 0, 0, 0, errors.New("helper: peer credentials need Linux")
}
