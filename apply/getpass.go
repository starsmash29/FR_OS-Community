package apply

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// ErrNoInput is the end of input at a password prompt (Python's
// EOFError).
var ErrNoInput = errors.New("EOFError")

// getpass is getpass.getpass: the prompt and the answer on the
// controlling terminal, with echo off; with no terminal, the answer from
// standard input after a warning, as Python does.
func getpass(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		os.Stderr.WriteString("Warning: Password input may be echoed.\n" + prompt)
		return readAnswer(os.Stdin)
	}
	defer tty.Close()
	fd := tty.Fd()
	// TCGETS/TCSETS take a pointer to the termios struct: the standard
	// library has no wrapper, so the ioctl is made directly (as GRO's).
	var old syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&old))); e != 0 {
		os.Stderr.WriteString("Warning: Password input may be echoed.\n" + prompt)
		return readAnswer(os.Stdin)
	}
	quiet := old
	quiet.Lflag &^= syscall.ECHO
	quiet.Lflag |= syscall.ICANON
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&quiet))); e != 0 {
		return "", e
	}
	defer func() {
		syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&old)))
		tty.WriteString("\n")
	}()
	tty.WriteString(prompt)
	return readAnswer(tty)
}

// readAnswer is one line, without its newline; none at all is the end
// of input.
func readAnswer(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && line == "" {
		return "", ErrNoInput
	}
	return strings.TrimSuffix(line, "\n"), nil
}
