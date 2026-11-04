//go:build unix

package minion

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// osHost is the machine the tests run on, through the os package: a host
// as simple as a Unix one gets.
type osHost struct{}

func (osHost) Abs(p string) (string, error) { return filepath.Abs(p) }
func (osHost) Sep() string                  { return "/" }
func (osHost) Dir(p string) string          { return filepath.Dir(p) }
func (osHost) Join(dir, name string) string { return filepath.Join(dir, name) }
func (osHost) Base(p string) string         { return filepath.Base(p) }

func infoOf(fi fs.FileInfo) Info {
	i := Info{Mode: fi.Mode(), Size: fi.Size()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		i.Dev, i.HasDev = uint64(st.Dev), true //nolint:unconvert // Dev's type differs by OS
	}
	return i
}

func (osHost) ReadDir(p string) ([]Entry, error) {
	dir, err := os.ReadDir(p)
	out := make([]Entry, 0, len(dir))
	for _, e := range dir {
		d := Entry{LsEntry: protocol.LsEntry{Name: e.Name(), Hidden: strings.HasPrefix(e.Name(), ".")}}
		switch m := e.Type(); {
		case m.IsDir():
			d.Type = protocol.EntryDir
		case m&fs.ModeSymlink != 0:
			d.Type = protocol.EntryLink
			d.Target, _ = os.Readlink(filepath.Join(p, e.Name()))
		case m.IsRegular():
			d.Type = protocol.EntryFile
		default:
			d.Type = protocol.EntryOther
		}
		if fi, err := e.Info(); err == nil {
			if !fi.IsDir() {
				size := uint64(max(fi.Size(), 0))
				d.Size = &size
			}
			mod := fi.ModTime().Unix()
			d.Modified = &mod
			info := infoOf(fi)
			d.Dev, d.HasDev = info.Dev, info.HasDev
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				d.OwnerName, d.GroupName = strconv.Itoa(int(st.Uid)), strconv.Itoa(int(st.Gid))
				if u, err := user.LookupId(d.OwnerName); err == nil {
					d.OwnerName = u.Username
				}
				if g, err := user.LookupGroupId(d.GroupName); err == nil {
					d.GroupName = g.Name
				}
			}
		}
		out = append(out, d)
	}
	return out, err
}

func (osHost) Stat(p string) (Info, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return Info{}, err
	}
	return infoOf(fi), nil
}

func (osHost) Lstat(p string) (Info, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return Info{}, err
	}
	return infoOf(fi), nil
}

type osFile struct{ *os.File }

func (f osFile) Stat() (Info, error) {
	fi, err := f.File.Stat()
	if err != nil {
		return Info{}, err
	}
	return infoOf(fi), nil
}

func (osHost) Open(p string) (ReadFile, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	return osFile{f}, nil
}

func (osHost) WriteAt(p string, off int64, data []byte, create bool) error {
	flags := os.O_WRONLY
	if create {
		flags |= os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(p, flags, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(data, off); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (osHost) CreateTemp(dir, pattern string) (WriteFile, error) { return os.CreateTemp(dir, pattern) }
func (osHost) Chmod(p string, mode fs.FileMode) error            { return os.Chmod(p, mode) }
func (osHost) Rename(from, to string) error                      { return os.Rename(from, to) }
func (osHost) Remove(p string) error                             { return os.Remove(p) }
func (osHost) RemoveAll(p string) error                          { return os.RemoveAll(p) }

// Shell runs /bin/sh in a process group of its own, the whole group
// killed on a cancel: what the command started holds its output open.
func (osHost) Shell(ctx context.Context, command string, out io.Writer) (Exit, error) {
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		return Exit{}, NotStarted(err)
	}
	err := cmd.Wait()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return Exit{}, err
	}
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return Exit{Signal: ws.Signal().String()}, nil
	}
	code := int64(cmd.ProcessState.ExitCode())
	return Exit{Code: &code}, nil
}

// Volumes: the root's, which holds every folder a test uses.
func (osHost) Volumes() ([]protocol.Volume, error) {
	return []protocol.Volume{{Path: "/", Kind: protocol.VolumeFixed, FS: "ext4", Device: "/dev/sda1"}}, nil
}

// testOps are the commands under numbers of a test's own: each command's
// number is its Command's.
func testOps(cmds ...Command) map[uint64]Command {
	ops := map[uint64]Command{}
	for _, c := range cmds {
		ops[uint64(c)] = c //nolint:gosec // a small command
	}
	return ops
}

// newTestRunner runs cmds on the test's machine.
func newTestRunner(cmds ...Command) *Runner {
	return newRunnerWith(Config{}, cmds...)
}

// newRunnerWith is newTestRunner with more of the config: Ops, Host and
// MaxTasks are filled in when cfg leaves them out.
func newRunnerWith(cfg Config, cmds ...Command) *Runner {
	if cfg.Ops == nil {
		cfg.Ops = testOps(cmds...)
	}
	if cfg.Host == nil {
		cfg.Host = osHost{}
	}
	if cfg.MaxTasks == 0 {
		cfg.MaxTasks = protocol.DefaultMaxTasks
	}
	return NewRunner(cfg)
}

// waitEnd waits for a runner's one task to end, and returns it.
func waitEnd(t *testing.T, r *Runner, within time.Duration) *Task {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		if len(r.tasks) == 1 && r.tasks[0].ended {
			task := r.tasks[0]
			r.mu.Unlock()
			return task
		}
		r.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no end within %s", within)
	return nil
}

// closeDir makes dir one the test may not list (no mode bits), undone
// before the test's temporary folder is removed. It says whether the test
// may list it all the same: root may.
func closeDir(t *testing.T, dir string) bool {
	t.Helper()
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	_, err := os.ReadDir(dir)
	return err == nil
}
