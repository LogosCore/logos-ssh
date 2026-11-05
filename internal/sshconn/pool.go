package sshconn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-ssh/internal/connection"
)

// Pool keeps calls' SSH connections for the next call to the same server,
// each for its target's Reuse: a file goes a chunk a call, and a login for
// each would cost a handshake and a line in the server's log every time.
type Pool struct {
	mu   sync.Mutex
	idle map[string]idleConn
	stop chan struct{}
	once sync.Once
}

type idleConn struct {
	c     *Conn
	until time.Time
}

// NewPool is an empty pool, closing what it keeps once its time is up.
func NewPool() *Pool {
	p := &Pool{idle: map[string]idleConn{}, stop: make(chan struct{})}
	go p.reap()
	return p
}

// Get is a connection to t's server, logged in: the one a call before kept,
// while it still answers, or a new one, with how its logins fared (none for
// one kept: nothing was tried).
func (p *Pool) Get(ctx context.Context, t connection.Target) (*Conn, []protocol.LinkLogin, error) {
	key := keyOf(t)
	p.mu.Lock()
	ic, ok := p.idle[key]
	delete(p.idle, key)
	p.mu.Unlock()
	if ok {
		if time.Now().Before(ic.until) && ic.c.Alive(2*time.Second) {
			return ic.c, nil, nil
		}
		_ = ic.c.Close() // gone quiet: a new one instead
	}
	return Dial(ctx, t)
}

// Put gives a call's connection back: kept for the target's Reuse, or
// closed when it has none, or when the call left it broken (ok false).
func (p *Pool) Put(t connection.Target, c *Conn, ok bool) {
	if !ok || t.Reuse <= 0 {
		_ = c.Close()
		return
	}
	key := keyOf(t)
	p.mu.Lock()
	old, had := p.idle[key]
	p.idle[key] = idleConn{c: c, until: time.Now().Add(t.Reuse)}
	p.mu.Unlock()
	if had && old.c != c {
		_ = old.c.Close()
	}
}

// Idle is how many connections the pool keeps now.
func (p *Pool) Idle() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.idle)
}

// CloseIdle closes every connection the pool keeps now.
func (p *Pool) CloseIdle() int {
	p.mu.Lock()
	all := p.idle
	p.idle = map[string]idleConn{}
	p.mu.Unlock()
	for _, ic := range all {
		_ = ic.c.Close()
	}
	return len(all)
}

// Close closes every connection the pool keeps, and stops it.
func (p *Pool) Close() {
	p.once.Do(func() { close(p.stop) })
	p.CloseIdle()
}

func (p *Pool) reap() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-p.stop:
			return
		case now := <-tick.C:
			p.mu.Lock()
			var expired []*Conn
			for k, ic := range p.idle {
				if !now.Before(ic.until) {
					expired = append(expired, ic.c)
					delete(p.idle, k)
				}
			}
			p.mu.Unlock()
			for _, c := range expired {
				_ = c.Close()
			}
		}
	}
}

// keyOf tells servers and logins apart: a connection serves the next call
// only to the same server, as the same user, with the same credentials.
func keyOf(t connection.Target) string {
	h := sha256.New()
	parts := []string{t.Addr, t.User, t.HostKey, proxyOf(t)}
	for _, l := range t.Logins {
		parts = append(parts, l.Credential, l.User, l.Password, l.PrivateKey, l.Passphrase)
	}
	for _, s := range parts {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func proxyOf(t connection.Target) string {
	if t.Proxy == nil {
		return ""
	}
	return t.Proxy.String()
}
