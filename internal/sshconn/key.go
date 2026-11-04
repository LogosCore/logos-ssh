package sshconn

import (
	"errors"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// pemBlock is a PEM block's markers and what is between them, line breaks
// or not.
var pemBlock = regexp.MustCompile(`(?s)-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END ([A-Z0-9 ]+)-----`)

// ReadableKey is a private key as the key parser reads it, from what a
// paste may have left of it: a one-line box drops a key's line breaks
// (Chrome) or makes them spaces (Firefox), JSON writes them "\n". The body
// is base64, which ignores where its lines break, so the block is made
// again: its markers on lines of their own, the body in lines of 70. A key
// with headers (the old encrypted PEM: Proc-Type, DEK-Info) is left as it
// is, as headers that lost their lines cannot be told from the body. The
// keys people paste by mistake are told apart: a public key, a PuTTY key.
func ReadableKey(text string) (string, error) {
	s := strings.TrimSpace(text)
	if !strings.Contains(s, "\n") && strings.Contains(s, `\n`) {
		s = strings.ReplaceAll(s, `\n`, "\n")
	}
	switch {
	case strings.HasPrefix(s, "PuTTY-User-Key-File-"):
		return "", errors.New("it is a PuTTY key (.ppk): convert it with puttygen key.ppk -O private-openssh -o key")
	case isPublicKey(s):
		return "", errors.New("it is a public key: give the private one (the key file without .pub)")
	}
	m := pemBlock.FindStringSubmatch(s)
	switch {
	case m == nil || m[1] != m[3]:
		return s, nil // not a block: the parser says what it is
	case strings.Contains(m[2], ":") && !strings.Contains(strings.TrimSpace(m[2]), "\n"):
		return "", errors.New("an old encrypted PEM key that lost its line breaks: paste it again as the file has it, " +
			"or convert it to OpenSSH's format with ssh-keygen -p -f key")
	case strings.Contains(m[2], ":"):
		return s, nil // headers, in their lines: as it is
	}
	body := strings.Join(strings.Fields(m[2]), "")
	var b strings.Builder
	b.WriteString("-----BEGIN " + m[1] + "-----\n")
	for len(body) > 70 {
		b.WriteString(body[:70] + "\n")
		body = body[70:]
	}
	if body != "" {
		b.WriteString(body + "\n")
	}
	b.WriteString("-----END " + m[1] + "-----\n")
	return b.String(), nil
}

// isPublicKey reports whether s is a public key's line, as authorized_keys
// and a .pub file hold one.
func isPublicKey(s string) bool {
	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
	return err == nil
}
