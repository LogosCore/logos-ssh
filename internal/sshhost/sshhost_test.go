//go:build unix

package sshhost

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-ssh/internal/connection"
	"github.com/logoscore/logos-ssh/internal/sshconn"
	"github.com/logoscore/logos-ssh/internal/sshtest"
)

// hostIn is a Host over the test server, its SFTP and commands in dir.
func hostIn(t *testing.T, dir string) *Host {
	t.Helper()
	srv := sshtest.New(t, dir)
	tg, err := connection.ReadTarget(srv.Values(), srv.Credentials())
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := sshconn.Dial(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return New(c)
}

// Paths are the login's folder's; a folder lists in name order, a link as
// the link with its target, owners by name; files read, write, move and
// go as SFTP has them.
func TestFiles(t *testing.T) {
	dir := t.TempDir()
	h := hostIn(t, dir)
	if err := os.MkdirAll(filepath.Join(dir, "sub", "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("hello"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b.txt", filepath.Join(dir, "a-link")); err != nil {
		t.Fatal(err)
	}
	if abs, err := h.Abs("sub"); err != nil || abs != filepath.Join(dir, "sub") {
		t.Fatalf("abs %q %v", abs, err)
	}
	if abs, _ := h.Abs("~/sub/../b.txt"); abs != filepath.Join(dir, "b.txt") {
		t.Fatalf("abs ~ %q", abs)
	}
	entries, err := h.ReadDir(dir)
	if err != nil || len(entries) != 3 {
		t.Fatalf("entries %+v %v", entries, err)
	}
	me, _ := user.Current()
	link, file, sub := entries[0], entries[1], entries[2]
	if link.Name != "a-link" || link.Type != protocol.EntryLink || link.Target != "b.txt" {
		t.Errorf("link %+v", link)
	}
	if file.Type != protocol.EntryFile || *file.Size != 5 || file.OwnerName != me.Username || protocol.RenderMode("linux", file.Mode) != "-rw-r-----" {
		t.Errorf("file %+v (%s)", file, protocol.RenderMode("linux", file.Mode))
	}
	if sub.Type != protocol.EntryDir || sub.Size != nil || !sub.HasDev {
		t.Errorf("sub %+v", sub)
	}
	if _, err := h.ReadDir(filepath.Join(dir, "none")); !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "none") {
		t.Errorf("a folder not there: %v", err)
	}
	if i, err := h.Lstat(filepath.Join(dir, "a-link")); err != nil || i.Mode&fs.ModeSymlink == 0 {
		t.Errorf("lstat %+v %v", i, err)
	}
	if i, err := h.Stat(filepath.Join(dir, "a-link")); err != nil || !i.Mode.IsRegular() || i.Size != 5 {
		t.Errorf("stat %+v %v", i, err)
	}

	f, err := h.Open(filepath.Join(dir, "b.txt"))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 3)
	if _, err := f.ReadAt(buf, 1); err != nil || string(buf) != "ell" {
		t.Errorf("read %q %v", buf, err)
	}
	_ = f.Close()

	// A temporary file takes a file's place, replacing it.
	tmp, err := h.CreateTemp(dir, ".b.txt.*.part")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = tmp.Write([]byte("bye"))
	if err := tmp.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	_ = tmp.Close()
	if err := h.Rename(tmp.Name(), filepath.Join(dir, "b.txt")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "b.txt")); string(got) != "bye" {
		t.Errorf("renamed over: %q", got)
	}
	// A chunk at a time, from an offset.
	part := filepath.Join(dir, "c.part")
	if err := h.WriteAt(part, 0, nil, true); err != nil {
		t.Fatal(err)
	}
	_ = h.WriteAt(part, 0, []byte("abc"), false)
	_ = h.WriteAt(part, 3, []byte("def"), false)
	if got, _ := os.ReadFile(part); string(got) != "abcdef" {
		t.Errorf("written %q", got)
	}
	if err := h.Remove(filepath.Join(dir, "sub")); err == nil {
		t.Error("a full folder removed without RemoveAll")
	}
	if err := h.RemoveAll(filepath.Join(dir, "sub")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sub")); !os.IsNotExist(err) {
		t.Error("sub is still there")
	}
}

// A command's output (the process id line kept back) and exit code; a
// stop kills what it started too.
func TestShell(t *testing.T) {
	dir := t.TempDir()
	h := hostIn(t, dir)
	var out bytes.Buffer
	exit, err := h.Shell(context.Background(), "echo out; echo err >&2; exit 3", &out)
	if err != nil || exit.Code == nil || *exit.Code != 3 || !strings.Contains(out.String(), "out\n") ||
		!strings.Contains(out.String(), "err\n") || strings.Contains(out.String(), h.pidMark()) || strings.Contains(out.String(), "LOGOS") {
		t.Fatalf("exit %+v %v, out %q", exit, err, out.String())
	}

	pidFile := filepath.Join(dir, "child.pid")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _ = h.Shell(ctx, "sleep 30 & echo $! > "+pidFile+"; wait", &bytes.Buffer{})
		close(done)
	}()
	var pid int
	for range 100 {
		if b, err := os.ReadFile(pidFile); err == nil && len(bytes.TrimSpace(b)) > 0 {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("the command did not start its child")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the stop did not end the command")
	}
	for range 50 {
		if syscall.Kill(pid, 0) != nil {
			return // the child went with it
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the child %d outlived the stop", pid)
}

// The hello says the server as uname and id say it, and its machine id.
func TestHello(t *testing.T) {
	h := hostIn(t, t.TempDir())
	hi := h.Hello()
	me, _ := user.Current()
	host, _ := os.Hostname()
	if hi.OS != runtime.GOOS || hi.Arch != runtime.GOARCH || hi.User != me.Username || hi.Host != host || hi.PID != 0 {
		t.Fatalf("hello %+v", hi)
	}
	if want := protocol.IntegrityUser; os.Geteuid() == 0 && hi.Integrity != protocol.IntegrityRoot || os.Geteuid() != 0 && hi.Integrity != want {
		t.Errorf("integrity %d", hi.Integrity)
	}
	if hi.MaxTasks == nil || *hi.MaxTasks != 4 || hi.X["host_key"] != h.c.Fingerprint() || !strings.HasPrefix(hi.X["ssh_server"].(string), "SSH-2.0-") {
		t.Errorf("max tasks %v, x %v", hi.MaxTasks, hi.X)
	}
	if _, err := os.Stat("/etc/machine-id"); err == nil {
		if hi.MachineSource != protocol.MachineLinuxMachineID || len(hi.MachineValue) != 32 {
			t.Errorf("machine %d %q", hi.MachineSource, hi.MachineValue)
		}
	} else if hi.MachineSource != protocol.MachineSSHHostKey || len(hi.MachineValue) != 64 {
		t.Errorf("machine %d %q", hi.MachineSource, hi.MachineValue)
	}
}

// df's lines, GNU's with types and POSIX's without: those that hold files,
// with their space and kind; a mount point may hold spaces.
func TestParseDF(t *testing.T) {
	gnu := `Filesystem     Type     1024-blocks      Used Available Capacity Mounted on
/dev/sda2      ext4       102626232  52374412  45013672      54% /
tmpfs          tmpfs        8122852         0   8122852       0% /dev/shm
proc           proc               0         0         0       -  /proc
srv:/export    nfs4       209715200 104857600 104857600      50% /mnt/my share
/dev/sr0       iso9660       700000    700000         0     100% /media/cd
`
	vols := parseDF(gnu)
	if len(vols) != 4 {
		t.Fatalf("%d volumes: %+v", len(vols), vols)
	}
	root, shm, share, cd := vols[0], vols[1], vols[2], vols[3]
	if root.Path != "/" || root.Kind != protocol.VolumeFixed || root.FS != "ext4" || *root.Size != 102626232*1024 || *root.Free != 45013672*1024 {
		t.Errorf("root %+v", root)
	}
	if shm.Kind != protocol.VolumeRAM || shm.Device != "" || share.Kind != protocol.VolumeNetwork || share.Path != "/mnt/my share" ||
		cd.Kind != protocol.VolumeOptical {
		t.Errorf("shm %+v share %+v cd %+v", shm, share, cd)
	}
	posix := `Filesystem   1024-blocks      Used Available Capacity Mounted on
/dev/disk1s1   488245288 221034528 254012616    47%    /
map auto_home          0         0         0   100%    /System/Volumes/Data/home
`
	vols = parseDF(posix)
	if len(vols) != 1 || vols[0].Path != "/" || vols[0].Kind != protocol.VolumeFixed || vols[0].FS != "" {
		t.Errorf("posix %+v", vols)
	}
	if got := parseDFAll(gnu); len(got) != 5 || got[3] != "/mnt/my share" {
		t.Errorf("mount points %q", got)
	}
	if unescapeMount(`/mnt/my\040share`) != "/mnt/my share" {
		t.Error("unescape")
	}
}

// On the test's machine: its volumes, and a path's file system as the
// mount it is under.
func TestVolumesAndDevices(t *testing.T) {
	h := hostIn(t, t.TempDir())
	vols, err := h.Volumes()
	if err != nil || len(vols) == 0 {
		t.Fatalf("volumes %+v %v", vols, err)
	}
	root, ok := h.device("/")
	if !ok {
		t.Fatal("no mounts known")
	}
	if _, err := os.Stat("/proc/self"); err == nil {
		if proc, _ := h.device("/proc"); proc == root {
			t.Error("/proc on the root's file system")
		}
		if self, _ := h.device("/proc/self/fd"); self == root {
			t.Error("under /proc on the root's file system")
		}
	}
}
