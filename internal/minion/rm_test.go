//go:build unix

package minion

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

func runRm(t *testing.T, args protocol.Args) *Task {
	t.Helper()
	r := newTestRunner(CmdRm)
	r.start(protocol.TaskItem{T: protocol.ItemTask, Task: bytes.Repeat([]byte{8}, 16), Cmd: uint64(CmdRm), Args: args})
	return waitEnd(t, r, 2*time.Second)
}

// A file goes; a folder with something in it only with recursive; a link
// goes, not what it points to; a root never.
func TestRm(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.txt")
	_ = os.WriteFile(file, []byte("x"), 0o600)
	if task := runRm(t, protocol.Args{ArgRmPath: file}); !task.ok || !strings.Contains(string(task.out), "(file)") {
		t.Fatalf("file: %+v", task)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("the file is still there")
	}

	full := filepath.Join(dir, "full")
	_ = os.MkdirAll(filepath.Join(full, "sub"), 0o700)
	if task := runRm(t, protocol.Args{ArgRmPath: full, ArgRmRecursive: false}); task.ok || !strings.Contains(task.err, "not empty") {
		t.Fatalf("a full folder without recursive: %+v", task)
	}
	if task := runRm(t, protocol.Args{ArgRmPath: full, ArgRmRecursive: true}); !task.ok {
		t.Fatalf("with recursive: %+v", task)
	}

	target := filepath.Join(dir, "target.txt")
	_ = os.WriteFile(target, []byte("y"), 0o600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("no symlinks here")
	}
	if task := runRm(t, protocol.Args{ArgRmPath: link}); !task.ok || !strings.Contains(string(task.out), "(link)") {
		t.Fatalf("link: %+v", task)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("removing a link removed its target")
	}
}

// A root is never removed: checked without removing one.
func TestRmNeverARoot(t *testing.T) {
	if _, errText := removePath(osHost{}, protocol.Args{ArgRmPath: "/", ArgRmRecursive: true}); !strings.Contains(errText, "root: not removed") {
		t.Fatalf("the root: %q", errText)
	}
}
