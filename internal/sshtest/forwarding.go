//go:build unix

package sshtest

import (
	"io"
	"net"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
)

// The test server's forwards, as sshd's: a direct-tcpip channel connects
// to its host and port, a direct-streamlocal@openssh.com one to its unix
// socket (refused with NoUnix, as a server without streamlocal does: an
// unknown channel type), each from
// the test's machine; a tcpip-forward listens where it asks (GatewayPorts
// yes) and opens a forwarded-tcpip channel for each connection. NoForward
// refuses them all, as AllowTcpForwarding no does.

// direct serves a channel to a destination: refused as sshd refuses one
// (administratively prohibited; connect failed, with the error's words),
// else the destination's bytes and the channel's, both ways.
func (s *Server) direct(nch ssh.NewChannel) {
	if s.NoForward.Load() {
		_ = nch.Reject(ssh.Prohibited, "open failed")
		return
	}
	var network, address string
	switch nch.ChannelType() {
	case "direct-tcpip":
		var p struct {
			Host  string
			Port  uint32
			OHost string
			OPort uint32
		}
		if ssh.Unmarshal(nch.ExtraData(), &p) != nil {
			_ = nch.Reject(ssh.ConnectionFailed, "bad request")
			return
		}
		network, address = "tcp", net.JoinHostPort(p.Host, strconv.FormatUint(uint64(p.Port), 10))
	default:
		if s.NoUnix.Load() {
			_ = nch.Reject(ssh.UnknownChannelType, "unknown channel type")
			return
		}
		var p struct {
			Path      string
			Reserved0 string
			Reserved1 uint32
		}
		if ssh.Unmarshal(nch.ExtraData(), &p) != nil {
			_ = nch.Reject(ssh.ConnectionFailed, "bad request")
			return
		}
		network, address = "unix", p.Path
	}
	c, err := net.Dial(network, address)
	if err != nil {
		_ = nch.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := nch.Accept()
	if err != nil {
		_ = c.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	pipe(ch, c)
}

// pipe carries bytes both ways until both are done: each side's end, the
// other's write side closed.
func pipe(ch ssh.Channel, c net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(ch, c)
		_ = ch.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(c, ch)
		if cw, ok := c.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
	_ = ch.Close()
	_ = c.Close()
}

// forwards are a connection's remote forwards, by the address asked.
type forwards struct {
	s    *Server
	conn *ssh.ServerConn
	mu   sync.Mutex
	lns  map[string]net.Listener
}

type forwardReq struct {
	Addr string
	Port uint32
}

// request serves a tcpip-forward (listen, saying the port when it asked
// for any) or a cancel-tcpip-forward (stop).
func (f *forwards) request(r *ssh.Request) {
	var p forwardReq
	if ssh.Unmarshal(r.Payload, &p) != nil || f.s.NoForward.Load() {
		_ = r.Reply(false, nil)
		return
	}
	key := net.JoinHostPort(p.Addr, strconv.FormatUint(uint64(p.Port), 10))
	if r.Type == "cancel-tcpip-forward" {
		f.mu.Lock()
		ln := f.lns[key]
		delete(f.lns, key)
		f.mu.Unlock()
		if ln != nil {
			_ = ln.Close()
		}
		_ = r.Reply(ln != nil, nil)
		return
	}
	ln, err := net.Listen("tcp", key)
	if err != nil {
		_ = r.Reply(false, nil)
		return
	}
	port := uint32(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // a port
	f.mu.Lock()
	// x/crypto's client cancels by the port the server gave.
	f.lns[net.JoinHostPort(p.Addr, strconv.FormatUint(uint64(port), 10))] = ln
	f.mu.Unlock()
	var reply []byte
	if p.Port == 0 {
		reply = ssh.Marshal(struct{ Port uint32 }{port})
	}
	_ = r.Reply(true, reply)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.forwarded(p.Addr, port, c)
		}
	}()
}

// forwarded opens a forwarded-tcpip channel for a connection to a
// listener, and carries its bytes.
func (f *forwards) forwarded(addr string, port uint32, c net.Conn) {
	from := c.RemoteAddr().(*net.TCPAddr)
	ch, reqs, err := f.conn.OpenChannel("forwarded-tcpip", ssh.Marshal(struct {
		Addr  string
		Port  uint32
		OAddr string
		OPort uint32
	}{addr, port, from.IP.String(), uint32(from.Port)})) //nolint:gosec // a port
	if err != nil {
		_ = c.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	pipe(ch, c)
}

// closeAll stops the connection's listeners: it went.
func (f *forwards) closeAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, ln := range f.lns {
		_ = ln.Close()
		delete(f.lns, k)
	}
}
