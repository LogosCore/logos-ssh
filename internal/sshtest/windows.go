//go:build unix

package sshtest

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

// Exec runs a command as a test's Windows server runs it: its output to out
// and errOut, its exit status returned. Its ctx ends on a signal, on which
// Windows's OpenSSH ends all the command started, and when the test ends;
// a channel closing alone leaves it running, as on Windows.
type Exec func(ctx context.Context, command string, out, errOut io.Writer) int

// WindowsVersion is the version Windows's OpenSSH says.
const WindowsVersion = "SSH-2.0-OpenSSH_for_Windows_9.5"

// NewWindows starts a server that answers as Windows's OpenSSH does: its
// version says so, its SFTP's root lists one drive, C:, which is dir, and
// SFTP starts in C:\Users\<user> (made in dir); a link to a folder reads as
// the folder it points to, as a junction does over Windows's SFTP, and a
// read-only file (no owner's write bit) is not removed. Its commands are
// exec's: it runs no shell.
func NewWindows(t testing.TB, dir string, exec Exec) *Server {
	t.Helper()
	s := newServer(t, dir, WindowsVersion)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s.exec, s.execCtx = exec, ctx
	home := filepath.Join(dir, "Users", s.User)
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	s.sftpOf = func(ch io.ReadWriteCloser) sftpServer {
		return sftp.NewRequestServer(ch, winHandlers(dir, "/C:/Users/"+s.User))
	}
	return s
}

// sftpServer is an SFTP server over a channel: a plain one or a request
// server.
type sftpServer interface {
	Serve() error
	Close() error
}

// winFS is the file system a test's Windows server serves over SFTP: /C:/
// is dir, and a relative path is from start.
type winFS struct{ dir, start string }

func winHandlers(dir, start string) sftp.Handlers {
	w := winFS{dir, start}
	return sftp.Handlers{FileGet: w, FilePut: w, FileCmd: w, FileList: w}
}

// local is an SFTP path's file: /C:/x is dir/x; root when the path is the
// SFTP root (its drives), and false for one on no drive.
func (w winFS) local(p string) (file string, root bool, err error) {
	p = path.Clean("/" + p)
	switch {
	case p == "/":
		return "", true, nil
	case strings.EqualFold(p, "/C:"):
		return w.dir, false, nil
	case len(p) > 4 && strings.EqualFold(p[:4], "/C:/"):
		return filepath.Join(w.dir, filepath.FromSlash(p[4:])), false, nil
	}
	return "", false, os.ErrNotExist
}

func (w winFS) file(p string) (string, error) {
	f, root, err := w.local(p)
	if err == nil && root {
		err = os.ErrPermission
	}
	return f, err
}

func (w winFS) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	f, err := w.file(r.Filepath)
	if err != nil {
		return nil, err
	}
	return os.Open(f) //nolint:gosec // a test's folder
}

func (w winFS) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	f, err := w.file(r.Filepath)
	if err != nil {
		return nil, err
	}
	fl := r.Pflags()
	flags := os.O_WRONLY
	if fl.Read {
		flags = os.O_RDWR
	}
	for _, x := range []struct {
		on   bool
		flag int
	}{{fl.Creat, os.O_CREATE}, {fl.Trunc, os.O_TRUNC}, {fl.Excl, os.O_EXCL}, {fl.Append, os.O_APPEND}} {
		if x.on {
			flags |= x.flag
		}
	}
	return os.OpenFile(f, flags, 0o644) //nolint:gosec // a test's folder
}

func (w winFS) Filecmd(r *sftp.Request) error {
	f, err := w.file(r.Filepath)
	if err != nil {
		return err
	}
	switch r.Method {
	case "Setstat":
		attrs, flags := r.Attributes(), r.AttrFlags()
		if flags.Permissions {
			if err := os.Chmod(f, attrs.FileMode().Perm()); err != nil {
				return err
			}
		}
		if flags.Size {
			return os.Truncate(f, int64(attrs.Size)) //nolint:gosec // a test's size
		}
		return nil
	case "Rename":
		to, err := w.file(r.Target)
		if err != nil {
			return err
		}
		// Windows's plain rename does not replace a file.
		if _, err := os.Lstat(to); err == nil {
			return errors.New("the target exists")
		}
		return os.Rename(f, to)
	case "Mkdir":
		return os.Mkdir(f, 0o755)
	case "Rmdir":
		// A junction goes as itself.
		if fi, err := os.Lstat(f); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
			return os.Remove(f)
		}
		return syscall.Rmdir(f)
	case "Remove":
		fi, err := os.Lstat(f)
		if err != nil {
			return err
		}
		if st, err := os.Stat(f); err == nil && st.IsDir() {
			return errors.New("a folder: not a file")
		}
		if fi.Mode().IsRegular() && fi.Mode().Perm()&0o200 == 0 {
			return os.ErrPermission // read-only
		}
		return os.Remove(f)
	}
	return errors.New("not served: " + r.Method)
}

// PosixRename replaces what is at the target, as Windows's posix-rename
// does.
func (w winFS) PosixRename(r *sftp.Request) error {
	from, err := w.file(r.Filepath)
	if err != nil {
		return err
	}
	to, err := w.file(r.Target)
	if err != nil {
		return err
	}
	return os.Rename(from, to)
}

func (w winFS) StatVFS(*sftp.Request) (*sftp.StatVFS, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(w.dir, &st); err != nil {
		return nil, err
	}
	return &sftp.StatVFS{Bsize: uint64(st.Bsize), Frsize: uint64(st.Bsize), Blocks: st.Blocks, Bfree: st.Bfree, Bavail: st.Bavail, //nolint:gosec,unconvert // sizes
		Namemax: 255}, nil
}

func (w winFS) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	f, root, err := w.local(r.Filepath)
	if err != nil {
		return nil, err
	}
	switch r.Method {
	case "List":
		if root {
			return listerAt{driveInfo{}}, nil
		}
		entries, err := os.ReadDir(f)
		if err != nil {
			return nil, err
		}
		infos := make([]os.FileInfo, 0, len(entries))
		for _, e := range entries {
			if fi, err := winStat(filepath.Join(f, e.Name())); err == nil {
				infos = append(infos, fi)
			}
		}
		return listerAt(infos), nil
	case "Stat":
		if root {
			return listerAt{driveInfo{}}, nil
		}
		fi, err := os.Stat(f)
		if err != nil {
			return nil, err
		}
		return listerAt{fi}, nil
	}
	return nil, errors.New("not served: " + r.Method)
}

func (w winFS) Lstat(r *sftp.Request) (sftp.ListerAt, error) {
	f, root, err := w.local(r.Filepath)
	if err != nil {
		return nil, err
	}
	if root {
		return listerAt{driveInfo{}}, nil
	}
	fi, err := winStat(f)
	if err != nil {
		return nil, err
	}
	return listerAt{fi}, nil
}

// Readlink is a file link's target; a junction's says nothing, as over
// Windows's SFTP.
func (w winFS) Readlink(p string) (string, error) {
	f, err := w.file(p)
	if err != nil {
		return "", err
	}
	if st, err := os.Stat(f); err == nil && st.IsDir() {
		return "", errors.New("bad message")
	}
	return os.Readlink(f)
}

func (w winFS) RealPath(p string) (string, error) {
	if !path.IsAbs(p) {
		p = path.Join(w.start, p)
	}
	p = path.Clean(p)
	if strings.EqualFold(p, "/C:") {
		return "/C:/", nil
	}
	return p, nil
}

// winStat is a file as Windows's SFTP says it: a link to a folder (a
// junction) as the folder, any other link as the link.
func winStat(f string) (os.FileInfo, error) {
	fi, err := os.Lstat(f)
	if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		return fi, err
	}
	if st, err := os.Stat(f); err == nil && st.IsDir() {
		return namedInfo{st, fi.Name()}, nil
	}
	return fi, nil
}

// namedInfo is a file's info under another name: a junction's, the folder
// it points to's under its own.
type namedInfo struct {
	os.FileInfo
	name string
}

func (n namedInfo) Name() string { return n.name }

// driveInfo is the C: drive, as the SFTP root lists it.
type driveInfo struct{}

func (driveInfo) Name() string       { return "C:" }
func (driveInfo) Size() int64        { return 0 }
func (driveInfo) Mode() fs.FileMode  { return fs.ModeDir | 0o700 }
func (driveInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (driveInfo) IsDir() bool        { return true }
func (driveInfo) Sys() any           { return nil }

type listerAt []os.FileInfo

func (l listerAt) ListAt(out []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(out, l[offset:])
	if offset+int64(n) >= int64(len(l)) {
		return n, io.EOF
	}
	return n, nil
}
