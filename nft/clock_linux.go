package nft

import (
	"syscall"
	"unsafe"
)

// kernelMinutesWest is the kernel's sys_tz.tz_minuteswest, from
// gettimeofday(2): the value nft_meta_weekday subtracts. 0 if it can't be
// read, as in 1.x.
func kernelMinutesWest() int {
	var tv syscall.Timeval
	var tz struct{ minutesWest, dstTime int32 }
	// unsafe: gettimeofday takes the two structs by pointer; syscall has
	// no wrapper that returns the time zone.
	_, _, errno := syscall.RawSyscall(syscall.SYS_GETTIMEOFDAY,
		uintptr(unsafe.Pointer(&tv)), uintptr(unsafe.Pointer(&tz)), 0)
	if errno != 0 {
		return 0
	}
	return int(tz.minutesWest)
}
