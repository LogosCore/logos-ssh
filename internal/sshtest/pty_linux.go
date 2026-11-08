//go:build linux

package sshtest

import (
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

// A terminal for a session's pty-req: a PTY from /dev/ptmx (syscall
// alone), as sshd makes one.

func ioctl(f *os.File, req uintptr, arg unsafe.Pointer) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var errno syscall.Errno
	if err := rc.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg))
	}); err != nil {
		return err
	}
	if errno != 0 {
		return errno
	}
	return nil
}

type winsize struct{ rows, cols, x, y uint16 }

func setSize(f *os.File, rows, cols int) error {
	ws := winsize{rows: uint16(rows), cols: uint16(cols)} //nolint:gosec // a terminal's size
	return ioctl(f, syscall.TIOCSWINSZ, unsafe.Pointer(&ws))
}

// openPTY is a PTY's two ends.
func openPTY() (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	var unlock int32
	if err := ioctl(m, syscall.TIOCSPTLCK, unsafe.Pointer(&unlock)); err != nil {
		_ = m.Close()
		return nil, nil, err
	}
	var n uint32
	if err := ioctl(m, syscall.TIOCGPTN, unsafe.Pointer(&n)); err != nil {
		_ = m.Close()
		return nil, nil, err
	}
	s, err := os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(n), 10), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		_ = m.Close()
		return nil, nil, err
	}
	return m, s, nil
}

// ptsName is the path of the terminal's other end.
func ptsName(m *os.File) string {
	var n uint32
	if ioctl(m, syscall.TIOCGPTN, unsafe.Pointer(&n)) != nil {
		return ""
	}
	return "/dev/pts/" + strconv.FormatUint(uint64(n), 10)
}
