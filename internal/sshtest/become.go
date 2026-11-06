package sshtest

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeSudo is sudo as a become test needs it: -S, -p (with %p), -u, --; it asks
// for FAKE_SUDO_PASSWORD (three tries, "Sorry, try again." between) unless
// FAKE_NOPASSWD, then runs the command as the test's user, FAKE_USER the
// user it became in name.
const fakeSudo = `#!/bin/sh
prompt=""
while [ $# -gt 0 ]; do
  case "$1" in
    -S) shift;;
    -p) prompt=$2; shift 2;;
    -u) user=$2; shift 2;;
    --) shift; break;;
    -*) shift;;
    *) break;;
  esac
done
prompt=$(printf '%s' "$prompt" | sed "s/%p/$(id -un)/")
if [ -z "$FAKE_NOPASSWD" ]; then
  tries=0
  while :; do
    printf '%s' "$prompt" >&2
    IFS= read -r pw || { echo "sudo: no password was provided" >&2; exit 1; }
    [ "$pw" = "$FAKE_SUDO_PASSWORD" ] && break
    echo "Sorry, try again." >&2
    tries=$((tries+1)); [ $tries -ge 3 ] && exit 1
  done
fi
FAKE_AS_ROOT=1 FAKE_USER=${user:-root} exec "$@"
`

// fakeSu asks for FAKE_SU_PASSWORD on stdout, as on a terminal, unless sudo
// ran it; FAKE_USER is the user it became in name.
const fakeSu = `#!/bin/sh
while [ $# -gt 0 ]; do case "$1" in -s) shift 2;; -c) cmd=$2; shift 2;; -*) shift;; *) user=$1; shift;; esac; done
if [ -z "$FAKE_AS_ROOT" ]; then
  printf 'Password: '
  IFS= read -r pw || exit 1
  [ "$pw" = "$FAKE_SU_PASSWORD" ] || { echo "su: Authentication failure"; exit 1; }
  echo
fi
FAKE_USER=$user exec /bin/sh -c "$cmd"
`

// fakeScript runs script -qc CMD /dev/null's command (no terminal: the
// test's su asks on stdout all the same).
const fakeScript = `#!/bin/sh
exec /bin/sh -c "$2"
`

// FakeBecome puts fake sudo, su and script first on the test's PATH, which
// the server's commands run with: sudo asks for sudoPassword (none with
// FAKE_NOPASSWD set), su for suPassword, both then running the command as
// the test's user.
func FakeBecome(t testing.TB, sudoPassword, suPassword string) {
	t.Helper()
	bin := t.TempDir()
	for name, body := range map[string]string{"sudo": fakeSudo, "su": fakeSu, "script": fakeScript} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil { //nolint:gosec // a test's script
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("FAKE_SUDO_PASSWORD", sudoPassword)
	t.Setenv("FAKE_SU_PASSWORD", suPassword)
	t.Setenv("FAKE_NOPASSWD", "")
}
