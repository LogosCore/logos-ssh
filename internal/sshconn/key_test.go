package sshconn_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-ssh/internal/sshconn"
	"github.com/logoscore/logos-ssh/internal/sshtest"
	"golang.org/x/crypto/ssh"
)

// pastes are what a key's text may come as: a one-line box drops its line
// breaks (Chrome) or makes them spaces (Firefox), JSON writes them "\n",
// Windows ends lines with CRLF.
func pastes(key string) map[string]string {
	return map[string]string{
		"as it is":         key,
		"no line breaks":   strings.ReplaceAll(key, "\n", ""),
		"spaces for lines": strings.TrimSpace(strings.ReplaceAll(key, "\n", " ")),
		`"\n" for lines`:   strings.ReplaceAll(key, "\n", `\n`),
		"CRLF":             strings.ReplaceAll(key, "\n", "\r\n"),
	}
}

// A key that lost its line breaks reads as the key it was: OpenSSH's own
// format, and the old PEM.
func TestReadableKey(t *testing.T) {
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(edPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]string{
		"openssh":   string(pem.EncodeToMemory(block)),
		"rsa (pem)": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaPriv)})),
	} {
		want, err := ssh.ParsePrivateKey([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		for how, text := range pastes(key) {
			readable, err := sshconn.ReadableKey(text)
			if err != nil {
				t.Fatalf("%s, %s: %v", name, how, err)
			}
			got, err := ssh.ParsePrivateKey([]byte(readable))
			if err != nil {
				t.Fatalf("%s, %s: %v", name, how, err)
			}
			if !bytes.Equal(got.PublicKey().Marshal(), want.PublicKey().Marshal()) {
				t.Fatalf("%s, %s: another key", name, how)
			}
		}
	}

	// An old encrypted PEM key's headers cannot be told from its body once
	// its lines are gone: it says so.
	// Its markers in parts: a fixture no secret scanner takes for a key.
	begin, end := "-----BEGIN RSA PRIVATE"+" KEY-----", "-----END RSA PRIVATE"+" KEY-----"
	legacy := begin + "\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\nAAAA\n" + end + "\n"
	if _, err := sshconn.ReadableKey(strings.ReplaceAll(legacy, "\n", " ")); err == nil || !strings.Contains(err.Error(), "lost its line breaks") {
		t.Errorf("a flattened legacy key: %v", err)
	}
	if got, err := sshconn.ReadableKey(legacy); err != nil || got != strings.TrimSpace(legacy) {
		t.Errorf("a legacy key in its lines: %q, %v", got, err)
	}

	// The keys pasted by mistake say what they are.
	sshPub, _ := ssh.NewPublicKey(edPriv.Public())
	for text, want := range map[string]string{
		string(ssh.MarshalAuthorizedKey(sshPub)):                    "public key",
		"PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n...": "PuTTY key",
	} {
		if _, err := sshconn.ReadableKey(text); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", text[:20], err)
		}
	}
}

// A login goes by a key that lost its line breaks, its passphrase too.
func TestDialFlattenedKey(t *testing.T) {
	srv := sshtest.New(t, t.TempDir())
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	srv.AuthorizeKey(sshPub)
	key := keyCredential(t, srv, "k1", priv, "pass")
	key.Key = strings.ReplaceAll(key.Key, "\n", " ")
	key.Passphrase = "pass"
	v := srv.Values()
	v["credentials"] = []any{"k1"}
	c, _, err := sshconn.Dial(context.Background(), target(t, v, map[string]protocol.Credential{"k1": key}))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}
