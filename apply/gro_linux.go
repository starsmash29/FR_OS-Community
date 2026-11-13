package apply

import (
	"runtime"
	"syscall"
	"unsafe"
)

// The ethtool ioctl that reads and sets GRO, as 1.x's frfw.xdp makes it
// (the router has no ethtool program): SIOCETHTOOL with an ifreq whose
// data points at a struct ethtool_value {cmd, data}.
const (
	siocEthtool = 0x8946
	ethtoolGGRO = 0x2B
	ethtoolSGRO = 0x2C
)

// ifreqData is struct ifreq with its union as the pointer ethtool takes;
// the pad makes it the kernel's 40 bytes.
type ifreqData struct {
	name [16]byte
	data unsafe.Pointer
	_    [16]byte
}

type ethtoolValue struct{ cmd, data uint32 }

func ethtool(device string, cmd, data uint32) (uint32, error) {
	if len(device) >= 16 {
		return 0, syscall.EINVAL
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)
	value := &ethtoolValue{cmd: cmd, data: data}
	var ifr ifreqData
	copy(ifr.name[:], device)
	// A Go pointer the kernel writes through: it is an unsafe.Pointer
	// field, so the collector keeps value where it is until the call
	// returns.
	ifr.data = unsafe.Pointer(value)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), siocEthtool, uintptr(unsafe.Pointer(&ifr)))
	runtime.KeepAlive(value)
	if errno != 0 {
		return 0, errno
	}
	return value.data, nil
}

func ethtoolGRO(device string) (bool, error) {
	v, err := ethtool(device, ethtoolGGRO, 0)
	return v != 0, err
}

func ethtoolSetGRO(device string, on bool) error {
	var v uint32
	if on {
		v = 1
	}
	_, err := ethtool(device, ethtoolSGRO, v)
	return err
}
