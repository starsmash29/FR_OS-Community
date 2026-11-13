//go:build !linux

package apply

import "syscall"

// GRO is a Linux device setting; elsewhere there is none to read.
func ethtoolGRO(string) (bool, error) { return false, syscall.ENOTSUP }

func ethtoolSetGRO(string, bool) error { return syscall.ENOTSUP }
