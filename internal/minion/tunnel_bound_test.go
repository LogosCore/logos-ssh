package minion

import (
	"net"
	"testing"
)

// A forward over SSH does not know where the server connected from: its
// reply says no bound address, rather than 0.0.0.0:0.
func TestBoundOf(t *testing.T) {
	for a, want := range map[net.Addr]string{
		&net.TCPAddr{IP: net.IPv4zero}:                       "",
		&net.TCPAddr{}:                                       "",
		&net.UnixAddr{Name: "@", Net: "unix"}:                "",
		&net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 41234}: "10.0.0.5:41234",
		&net.TCPAddr{IP: net.IPv4zero, Port: 43575}:          "0.0.0.0:43575",
	} {
		if got := boundOf(a); got != want {
			t.Errorf("%v: %q, want %q", a, got, want)
		}
	}
	if boundOf(nil) != "" {
		t.Error("nil")
	}
}
