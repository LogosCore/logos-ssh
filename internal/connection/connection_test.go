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
	for _, f := range target() {
		if strings.Contains("password private_key passphrase", f.Key) && f.Type != protocol.FieldSecret {
			t.Errorf("%s is not a secret", f.Key)
		}
	}
}

// A call's or an open's values, as the control link brings them.
func TestReadTarget(t *testing.T) {
	tg, err := ReadTarget(map[string]any{"host": "10.0.0.5", "user": "root", "password": "pw", "call_reuse": "0s", "proxy": "socks5://127.0.0.1:1080"})
	if err != nil || tg.Addr != "10.0.0.5:22" || tg.Reuse != 0 || tg.ConnectTimeout != 10*time.Second || tg.Keepalive != 30*time.Second ||
		tg.Proxy == nil || tg.Proxy.Host != "127.0.0.1:1080" {
		t.Fatalf("%+v %v", tg, err)
	}
	if tg, _ := ReadTarget(map[string]any{"host": "h", "user": "u", "port": uint64(2222)}); tg.Addr != "h:2222" || tg.Reuse != 30*time.Second {
		t.Fatalf("%+v", tg)
	}
	for name, v := range map[string]map[string]any{
		"no host":  {"user": "u"},
		"no user":  {"host": "h"},
		"bad port": {"host": "h", "user": "u", "port": uint64(70000)},
		"host key": {"host": "h", "user": "u", "host_key": "MD5:aa"},
		"proxy":    {"host": "h", "user": "u", "proxy": "::"},
	} {
		if _, err := ReadTarget(v); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}
