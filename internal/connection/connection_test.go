package connection

import (
	"strings"
	"testing"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// Both kinds are agentless, with the same target fields; the schema is
// valid as core checks it.
func TestSchema(t *testing.T) {
	s := Schema()
	if err := protocol.ValidateConnectionSchema(s); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{protocol.KindBindCall, protocol.KindBindPersistent} {
		if !s.IsAgentless(kind) || len(s.TargetFields(kind)) != len(target()) {
			t.Errorf("%s: agentless %v, %d target fields", kind, s.IsAgentless(kind), len(s.TargetFields(kind)))
		}
	}
	// Logins are the operation's credentials: keys and passwords.
	var creds *protocol.FieldSpec
	for _, f := range target() {
		if f.Type == protocol.FieldSecret {
			t.Errorf("%s: a secret of the target's own, not a credential", f.Key)
		}
		if f.Key == CredentialsField.Key {
			creds = &f
		}
	}
	if creds == nil || creds.Type != protocol.FieldCredentialList || strings.Join(creds.Accept, ",") != "KEY,PLAINTEXT" || !creds.Required {
		t.Errorf("credentials: %+v", creds)
	}
}

var given = map[string]protocol.Credential{
	"k1": {ID: "k1", Name: "root key", Type: protocol.CredentialTypeKey, Username: "root", Key: "KEY", Passphrase: "pp"},
	"k2": {ID: "k2", Type: protocol.CredentialTypeKey, Key: "KEY2"},
	"p1": {ID: "p1", Name: "admin", Type: protocol.CredentialTypePlaintext, Username: "admin", Realm: "corp.local", Password: "pw"},
	"p2": {ID: "p2", Type: protocol.CredentialTypePlaintext, Password: "pw2"},
	"h1": {ID: "h1", Type: protocol.CredentialTypeHash, Hash: "31d6"},
}

// A call's or an open's values, as the control link brings them, and the
// credentials beside them.
func TestReadTarget(t *testing.T) {
	tg, err := ReadTarget(map[string]any{"host": "10.0.0.5", "credentials": []any{"k1"}, "call_reuse": "0s", "proxy": "socks5://127.0.0.1:1080"}, given)
	if err != nil || tg.Addr != "10.0.0.5:22" || tg.Reuse != 0 || tg.ConnectTimeout != 10*time.Second || tg.Keepalive != 30*time.Second ||
		tg.Proxy == nil || tg.Proxy.Host != "127.0.0.1:1080" {
		t.Fatalf("%+v %v", tg, err)
	}
	if tg, _ := ReadTarget(map[string]any{"host": "h", "credentials": []any{"k1"}, "port": uint64(2222)}, given); tg.Addr != "h:2222" || tg.Reuse != 30*time.Second {
		t.Fatalf("%+v", tg)
	}

	// The logins, in the target's order: each as its username, a password
	// with a realm as username@realm, one without a username as the
	// target's user.
	tg, err = ReadTarget(map[string]any{"host": "h", "user": "svc", "credentials": []any{"p1", "k1", "k2", "p2"}}, given)
	if err != nil {
		t.Fatal(err)
	}
	want := []Login{
		{Credential: "p1", Name: "admin", User: "admin@corp.local", Password: "pw"},
		{Credential: "k1", Name: "root key", User: "root", PrivateKey: "KEY", Passphrase: "pp"},
		{Credential: "k2", User: "svc", PrivateKey: "KEY2"},
		{Credential: "p2", User: "svc", Password: "pw2"},
	}
	if len(tg.Logins) != len(want) {
		t.Fatalf("logins %+v", tg.Logins)
	}
	for i := range want {
		if tg.Logins[i] != want[i] {
			t.Errorf("login %d: %+v, want %+v", i, tg.Logins[i], want[i])
		}
	}
	if l := tg.Logins[1].Label(); l != `root (key "root key")` {
		t.Errorf("label %q", l)
	}

	for name, v := range map[string]map[string]any{
		"no host":                {"credentials": []any{"k1"}},
		"no credentials":         {"host": "h"},
		"no user to log in as":   {"host": "h", "credentials": []any{"k2"}},
		"a credential not given": {"host": "h", "credentials": []any{"x9"}},
		"a hash":                 {"host": "h", "credentials": []any{"h1"}},
		"bad port":               {"host": "h", "credentials": []any{"k1"}, "port": uint64(70000)},
		"host key":               {"host": "h", "credentials": []any{"k1"}, "host_key": "MD5:aa"},
		"proxy":                  {"host": "h", "credentials": []any{"k1"}, "proxy": "::"},
	} {
		if _, err := ReadTarget(v, given); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}
