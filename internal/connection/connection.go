// Package connection declares the SSH channel's connection schema (docs:
// contracts/agentless-channels/): two kinds, bind-call and bind-persistent,
// both agentless (the channel acts as the minion; nothing runs on the
// server), with the same target fields, and reads a call's or an open's
// values.
package connection

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// Version is the built-in fields' version. Target fields change without
// it: nothing is built from them.
const Version = 1

// HostKeyPattern is a host key's SHA-256 fingerprint, as ssh-keygen -l
// prints it.
var HostKeyPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}=?$`)

// CredentialsField is the target's credentials: keys and passwords from the
// operation's, tried in order until one logs in.
var CredentialsField = protocol.FieldSpec{Key: "credentials", Type: protocol.FieldCredentialList, Label: "Credentials",
	Required: true, MaxItems: MaxLogins, Accept: []string{protocol.CredentialTypeKey, protocol.CredentialTypePlaintext},
	Group: "Login", Order: 5,
	Description: "Keys and passwords to log in with, tried in order until one is taken: each as its username " +
		"(a password's with a realm as username@realm), or as the target's user when it has none."}

// MaxLogins bounds a target's credentials: each is a connection to the
// server, and its log line.
const MaxLogins = 8

// target is every kind's target fields: where the server is and how to log
// in.
func target() []protocol.FieldSpec {
	return []protocol.FieldSpec{
		{Key: "host", Type: protocol.FieldString, Label: "Host", Required: true, MaxLength: 255, Group: "Server", Order: 1,
			Description: "The server's address or name.", Placeholder: "10.0.12.7"},
		{Key: "port", Type: protocol.FieldInt, Label: "Port", Default: 22, Min: 1, Max: 65535, Group: "Server", Order: 2},
		{Key: "host_key", Type: protocol.FieldString, Label: "Host key", MaxLength: 60, Group: "Server", Order: 3,
			Pattern:     HostKeyPattern.String(),
			Description: "The server's host key's SHA-256 fingerprint (SHA256:…, as ssh-keygen -l prints it): the server must present it. Empty: the first key it presents is taken, and its session shows it to pin here."},
		{Key: "user", Type: protocol.FieldString, Label: "User", MaxLength: 255, Group: "Login", Order: 4,
			Description: "Who a credential without a username logs in as."},
		CredentialsField,
		{Key: "proxy", Type: protocol.FieldURL, Label: "Proxy", MaxLength: 2048, Group: "Network", Order: 8,
			Pattern:     `^(socks5|socks5h|http)://[^\s]+$`,
			Description: "Reach the server through a proxy: socks5://host:port (a pivot, an SSH dynamic forward) or http://host:port (CONNECT)."},
		{Key: "connect_timeout", Type: protocol.FieldDuration, Label: "Connect timeout", Default: "10s", Min: "1s", Max: "2m", Group: "Network", Order: 9,
			Description: "How long reaching the server and logging in may take."},
	}
}

// Schema is the connection schema declared at registration.
func Schema() protocol.ConnectionSchema {
	return protocol.ConnectionSchema{
		SchemaVersion: protocol.ConnectionSchemaV2,
		Version:       Version,
		Kinds: map[string]protocol.ConnectionKind{
			protocol.KindBindCall: {
				Agentless: true,
				Fields: []protocol.FieldSpec{{
					Key: "call_reuse", Type: protocol.FieldDuration, Label: "Keep the login", Default: "30s", Min: "0s", Max: "10m",
					Group: "Calls", Order: 1,
					Description: "How long the channel keeps a server's SSH connection after a call, for the next one (a file goes a chunk a call). 0s logs in for every call.",
				}},
				Target: target(),
			},
			protocol.KindBindPersistent: {
				Agentless: true,
				Fields: []protocol.FieldSpec{{
					Key: "keepalive", Type: protocol.FieldDuration, Label: "Keepalive", Default: "30s", Min: "5s", Max: "1h",
					Group: "Connection", Order: 1,
					Description: "How often the channel checks the server is still there: a connection gone without a word is found.",
				}},
				Target: target(),
			},
		},
	}
}

// Target is what a call or an open says of a server.
type Target struct {
	// Addr is the server's host:port; Host its host alone.
	Addr, Host string
	// User is the target's own: who a credential without a username logs
	// in as.
	User string
	// Logins are the target's credentials, in its order: each tried in
	// turn until one logs in.
	Logins []Login
	// HostKey is the fingerprint the server must present; empty: any.
	HostKey string
	Proxy   *url.URL
	// ConnectTimeout bounds reaching the server and logging in.
	ConnectTimeout time.Duration
	// Reuse is how long a call's SSH connection stays for the next call;
	// Keepalive how often a persistent one is checked.
	Reuse, Keepalive time.Duration
}

// Login is one way to log in to a target's server: one of its credentials,
// as SSH takes it.
type Login struct {
	// Credential is its id, which the answer's logins name; Name is how
	// people call it.
	Credential, Name string
	// User is who it logs in as.
	User string
	// Password is a PLAINTEXT's; PrivateKey and Passphrase a KEY's.
	Password, PrivateKey, Passphrase string
}

// Label is how a message names the login: `root (key "prod root")`.
func (l Login) Label() string {
	how := "password"
	if l.PrivateKey != "" {
		how = "key"
	}
	if l.Name == "" {
		return fmt.Sprintf("%s (%s %s)", l.User, how, l.Credential)
	}
	return fmt.Sprintf("%s (%s %q)", l.User, how, l.Name)
}

// ReadTarget reads a call's or an open's values, and the credentials core
// gave beside them: core checked them against the schema, but they come
// over the wire all the same.
func ReadTarget(v map[string]any, given map[string]protocol.Credential) (Target, error) {
	str := func(k string) string { s, _ := v[k].(string); return s }
	dur := func(k string, def time.Duration) time.Duration {
		if _, ok := v[k]; !ok {
			return def
		}
		if d, err := protocol.ParseDuration(v[k]); err == nil && d >= 0 {
			return d
		}
		return def
	}
	host := str("host")
	if host == "" {
		return Target{}, errors.New("no host")
	}
	port := int64(22)
	if p, ok := intOf(v["port"]); ok && p != 0 {
		port = p
	}
	if port < 1 || port > 65535 {
		return Target{}, fmt.Errorf("port %d", port)
	}
	t := Target{Addr: net.JoinHostPort(host, strconv.FormatInt(port, 10)), Host: host, User: str("user"), HostKey: str("host_key"),
		ConnectTimeout: dur("connect_timeout", 10*time.Second), Reuse: dur("call_reuse", 30*time.Second), Keepalive: dur("keepalive", 30*time.Second)}
	creds, err := protocol.FieldCredentials(CredentialsField, v[CredentialsField.Key], given)
	if err != nil {
		return Target{}, err
	}
	if len(creds) == 0 {
		return Target{}, errors.New("no credentials to log in with")
	}
	if len(creds) > MaxLogins {
		return Target{}, fmt.Errorf("%d credentials, %d at most", len(creds), MaxLogins)
	}
	for _, c := range creds {
		l := Login{Credential: c.ID, Name: c.Name, User: c.Username}
		if l.User == "" {
			l.User = t.User
		}
		switch c.Type {
		case protocol.CredentialTypeKey:
			l.PrivateKey, l.Passphrase = c.Key, c.Passphrase
		case protocol.CredentialTypePlaintext:
			l.Password = c.Password
			if c.Realm != "" && l.User != "" {
				l.User += "@" + c.Realm
			}
		}
		if l.User == "" {
			return Target{}, fmt.Errorf("credential %s has no username, and the target gives no user", l.Label())
		}
		t.Logins = append(t.Logins, l)
	}
	if t.HostKey != "" && !HostKeyPattern.MatchString(t.HostKey) {
		return Target{}, fmt.Errorf("host key %q is not a SHA256 fingerprint", t.HostKey)
	}
	if t.ConnectTimeout <= 0 {
		t.ConnectTimeout = 10 * time.Second
	}
	if t.Keepalive < 5*time.Second {
		t.Keepalive = 30 * time.Second
	}
	if p := str("proxy"); p != "" {
		u, err := url.Parse(p)
		if err != nil || u.Host == "" {
			return Target{}, fmt.Errorf("proxy %q", p)
		}
		t.Proxy = u
	}
	return t, nil
}

// intOf reads an integer as the control link's CBOR decodes it (uint64 for
// a positive one), or as JSON would.
func intOf(v any) (int64, bool) {
	switch n := v.(type) {
	case uint64:
		if n <= 1<<62 {
			return int64(n), true
		}
		return 0, false
	case uint32:
		return int64(n), true
	case uint:
		return int64(n), true //nolint:gosec // a port
	}
	return protocol.AsInt64(v)
}
