//go:build unix && !linux

package sshtest

import (
	"errors"
	"os"
)

// No PTYs for the test server here: a pty-req is refused, and the
// session runs on pipes.

func openPTY() (master, slave *os.File, err error) { return nil, nil, errors.New("no PTY here") }

func setSize(*os.File, int, int) error { return errors.New("no PTY here") }

func ptsName(*os.File) string { return "" }
