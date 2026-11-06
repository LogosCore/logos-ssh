// Package sshhost is the server the SSH minion acts on (docs:
// contracts/agentless-channels/): its files over SFTP, its commands in exec
// channels. A Unix server's run in /bin/sh, as BOB's minion runs them on
// Unix; a Windows server's (Windows's OpenSSH) in its default shell, cmd.exe
// unless its administrator chose another, with paths as Windows writes them
// (windows.go, winpath.go).
package sshhost

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-ssh/internal/minion"
	"github.com/logoscore/logos-ssh/internal/sshconn"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Host is a server reached over SSH: the minion's Host.
type Host struct {
	c *sshconn.Conn

	mu sync.Mutex
	// sftpWD is the login's folder as SFTP says it (/home/me,
	// /C:/Users/me), read once; drive whether it is a drive's, as Windows's
	// OpenSSH says its folders.
	sftpWD string
	drive  bool
	// users and groups are the server's names by id, from /etc/passwd and
	// /etc/group, read once.
	named         bool
	users, groups map[uint32]string
	// mounts are the server's mount points, longest first, read once: SFTP
	// says no file system a file is on, so the mount a path is under says
	// it (a walk staying on its file system).
	mounted bool
	mounts  []string
}

// New is the server c reaches.
func New(c *sshconn.Conn) *Host { return &Host{c: c} }

var _ minion.Host = (*Host)(nil)

func (h *Host) ftp() (*sftp.Client, error) { return h.c.SFTP() }

// pathErr says which path an error was about, as the os package's errors
// do: fs.ErrNotExist and fs.ErrPermission show through.
func pathErr(op, p string, err error) error {
	if err == nil {
		return nil
	}
	return &fs.PathError{Op: op, Path: p, Err: err}
}

// login is the login's folder as SFTP says it, and whether it is a
// drive's: read once.
func (h *Host) login() (string, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sftpWD != "" {
		return h.sftpWD, h.drive, nil
	}
	f, err := h.ftp()
	if err != nil {
		return "", false, err
	}
	wd, err := f.Getwd()
	if err != nil {
		return "", false, fmt.Errorf("the login's folder: %w", err)
	}
	h.sftpWD, h.drive = wd, driveSFTP(wd)
	return wd, h.drive, nil
}

// drives reports whether the server's SFTP says a drive's folders
// (/C:/Users/me), as Windows's OpenSSH does: its paths are then Windows's
// (C:\Users\me), as core and the minion's commands have them, and each SFTP
// call takes its path through remote.
func (h *Host) drives() bool {
	_, drive, err := h.login()
	return err == nil && drive
}

// windows reports whether the server is a Windows one: its version says so
// (OpenSSH_for_Windows), or its SFTP says drives. It runs commands in its
// default shell, and the minion asks it of itself in PowerShell.
func (h *Host) windows() bool {
	return strings.Contains(h.c.Version, "OpenSSH_for_Windows") || h.drives()
}

// remote is a path as the server's SFTP takes it: a Windows one from its
// drive (C:\Users is /C:/Users), any other as it is.
func (h *Host) remote(p string) string {
	if h.drives() {
		return sftpPath(p)
	}
	return p
}

// Abs is a path from the login's folder (the user's home, where SFTP
// starts), clean; "~" is that folder. A Windows server's is read the
// Windows way (winAbs): / as \, a drive alone its root.
func (h *Host) Abs(p string) (string, error) {
	if h.drives() {
		wd, err := h.wd()
		if err != nil {
			return "", err
		}
		return winAbs(wd, p), nil
	}
	switch {
	case p == "" || p == "~":
		p = "."
	case strings.HasPrefix(p, "~/"):
		p = p[2:]
	}
	if path.IsAbs(p) {
		return path.Clean(p), nil
	}
	cwd, err := h.wd()
	if err != nil {
		return "", err
	}
	return path.Join(cwd, p), nil
}

// wd is the login's folder, as the server's paths are written.
func (h *Host) wd() (string, error) {
	wd, drive, err := h.login()
	if err != nil {
		return "", err
	}
	if drive {
		return fromSFTP(wd), nil
	}
	return wd, nil
}

func (h *Host) Sep() string {
	if h.drives() {
		return `\`
	}
	return "/"
}

func (h *Host) Dir(p string) string {
	if h.drives() {
		return winDir(p)
	}
	return path.Dir(p)
}

func (h *Host) Join(dir, name string) string {
	if h.drives() {
		return winJoin(dir, name)
	}
	return path.Join(dir, name)
}

func (h *Host) Base(p string) string {
	if h.drives() {
		return winBase(p)
	}
	return path.Base(p)
}

// ReadDir lists a folder in name order: links as links, with their
// targets; owners and groups by name where the server's files say them.
//
// A Windows server's SFTP says no owners, modes of its own making rather
// than a file's attributes (which a listing's modes are on Windows), and a
// junction as the folder it points to. Its entries' attributes come from
// cmd's dir instead, asked as SFTP lists (winAttrs): hidden by its
// attribute too, and a junction a link to its target, as BOB's minion lists
// one, which walks do not enter. Where cmd cannot say, they say no mode.
func (h *Host) ReadDir(p string) ([]minion.Entry, error) {
	f, err := h.ftp()
	if err != nil {
		return nil, err
	}
	type said struct {
		attrs map[string]winEntry
		ok    bool
	}
	var asked chan said
	if h.drives() {
		asked = make(chan said, 1)
		go func() {
			attrs, ok := h.winAttrs(p)
			asked <- said{attrs, ok}
		}()
	}
	infos, err := f.ReadDir(h.remote(p))
	if err != nil {
		return nil, pathErr("readdir", p, err)
	}
	slices.SortFunc(infos, func(a, b os.FileInfo) int { return strings.Compare(a.Name(), b.Name()) })
	win := h.windows()
	var users, groups map[uint32]string
	if !win {
		users, groups = h.names()
	}
	var attrs said
	if asked != nil {
		attrs = <-asked
	}
	entries := make([]minion.Entry, 0, len(infos))
	for _, fi := range infos {
		m := fi.Mode()
		e := minion.Entry{LsEntry: protocol.LsEntry{Name: fi.Name(), Type: entryType(m), Hidden: strings.HasPrefix(fi.Name(), ".")}}
		if !m.IsDir() {
			size := uint64(max(fi.Size(), 0))
			e.Size = &size
		}
		mod := fi.ModTime().Unix()
		e.Modified = &mod
		if st, ok := fi.Sys().(*sftp.FileStat); ok && !win {
			e.Mode = st.Mode
			e.OwnerName, e.GroupName = nameOf(users, st.UID), nameOf(groups, st.GID)
		}
		at := h.Join(p, fi.Name())
		if e.Type == protocol.EntryLink {
			if target, err := f.ReadLink(h.remote(at)); err == nil {
				if h.drives() {
					target = winTarget(target)
				}
				e.Target = target
			}
		}
		if attrs.ok {
			a := attrs.attrs[fi.Name()]
			e.Mode, e.Hidden = a.attrs, e.Hidden || a.attrs&attrHidden != 0
			if m.IsDir() {
				e.Mode |= attrDirectory
			}
			switch {
			case a.junction && m.IsDir():
				e.Type, e.Target = protocol.EntryLink, a.target
				e.Mode |= attrReparse
			case e.Type == protocol.EntryLink:
				e.Mode |= attrReparse
			}
		}
		e.Dev, e.HasDev = h.device(at)
		entries = append(entries, e)
	}
	return entries, nil
}

func entryType(m fs.FileMode) int {
	switch {
	case m.IsDir():
		return protocol.EntryDir
	case m&fs.ModeSymlink != 0:
		return protocol.EntryLink
	case m.IsRegular():
		return protocol.EntryFile
	}
	return protocol.EntryOther
}

func nameOf(names map[uint32]string, id uint32) string {
	if n, ok := names[id]; ok {
		return n
	}
	return strconv.FormatUint(uint64(id), 10)
}

// names are the server's user and group names by id, read once from
// /etc/passwd and /etc/group; none where it keeps them elsewhere.
func (h *Host) names() (map[uint32]string, map[uint32]string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.named {
		h.named = true
		h.users, h.groups = h.idFile("/etc/passwd"), h.idFile("/etc/group")
	}
	return h.users, h.groups
}

// idFile reads a passwd- or group-like file: name:x:id:...
func (h *Host) idFile(p string) map[uint32]string {
	out := map[uint32]string{}
	f, err := h.ftp()
	if err != nil {
		return out
	}
	file, err := f.Open(p)
	if err != nil {
		return out
	}
	defer func() { _ = file.Close() }() // read only: nothing to lose on close
	sc := bufio.NewScanner(io.LimitReader(file, 4<<20))
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 4)
		if len(parts) < 3 || parts[0] == "" || strings.HasPrefix(parts[0], "#") {
			continue
		}
		if id, err := strconv.ParseUint(parts[2], 10, 32); err == nil {
			if _, ok := out[uint32(id)]; !ok {
				out[uint32(id)] = parts[0]
			}
		}
	}
	return out
}

func info(fi os.FileInfo) minion.Info { return minion.Info{Mode: fi.Mode(), Size: fi.Size()} }

func (h *Host) Stat(p string) (minion.Info, error) {
	f, err := h.ftp()
	if err != nil {
		return minion.Info{}, err
	}
	fi, err := f.Stat(h.remote(p))
	if err != nil {
		return minion.Info{}, pathErr("stat", p, err)
	}
	i := info(fi)
	i.Dev, i.HasDev = h.device(p)
	return i, nil
}

// device is the file system p is on, as the mount it is under (its place
// among the mounts, from 1), a Windows server's as its drive: false when
// the server's mounts are not known.
func (h *Host) device(p string) (uint64, bool) {
	if h.drives() {
		return winDevice(p)
	}
	mounts := h.mountPoints()
	for i, m := range mounts {
		if p == m || m == "/" || strings.HasPrefix(p, m+"/") {
			return uint64(i + 1), true //nolint:gosec // a small place
		}
	}
	return 0, false
}

// mountPoints are the server's mount points, longest first: Linux's
// /proc/self/mounts over SFTP, else what df says.
func (h *Host) mountPoints() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.mounted {
		return h.mounts
	}
	h.mounted = true
	var points []string
	if f, err := h.ftp(); err == nil {
		if file, err := f.Open("/proc/self/mounts"); err == nil {
			sc := bufio.NewScanner(io.LimitReader(file, 4<<20))
			for sc.Scan() {
				if fields := strings.Fields(sc.Text()); len(fields) >= 2 {
					points = append(points, unescapeMount(fields[1]))
				}
			}
			_ = file.Close() // read only: nothing to lose on close
		}
	}
	if len(points) == 0 {
		if out, err := h.run("df -kP", 30*time.Second); err == nil {
			points = append(points, parseDFAll(out)...)
		}
	}
	slices.SortFunc(points, func(a, b string) int { return len(b) - len(a) })
	h.mounts = slices.Compact(points)
	return h.mounts
}

// unescapeMount undoes /proc/self/mounts' octal escapes (a space is \040).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Lstat is the path itself, a link not followed: a Windows junction, which
// SFTP reads as its folder, a link too (as cmd's dir says of its parent's
// entries).
func (h *Host) Lstat(p string) (minion.Info, error) {
	f, err := h.ftp()
	if err != nil {
		return minion.Info{}, err
	}
	fi, err := f.Lstat(h.remote(p))
	if err != nil {
		return minion.Info{}, pathErr("lstat", p, err)
	}
	i := info(fi)
	if fi.IsDir() && h.drives() {
		if junction, _ := h.junction(p); junction {
			i.Mode = fs.ModeSymlink | i.Mode.Perm()
		}
	}
	return i, nil
}

// readFile is a server's file open to read.
type readFile struct{ *sftp.File }

func (r readFile) Stat() (minion.Info, error) {
	fi, err := r.File.Stat()
	if err != nil {
		return minion.Info{}, err
	}
	return info(fi), nil
}

func (h *Host) Open(p string) (minion.ReadFile, error) {
	f, err := h.ftp()
	if err != nil {
		return nil, err
	}
	file, err := f.Open(h.remote(p))
	if err != nil {
		return nil, pathErr("open", p, err)
	}
	return readFile{file}, nil
}

// writeFile is a server's file open to write.
type writeFile struct {
	*sftp.File
	name string
}

func (w writeFile) Name() string { return w.name }

// Sync commits the file where the server can (OpenSSH's fsync extension);
// a server without it keeps the file as its file system does.
func (w writeFile) Sync() error {
	err := w.File.Sync()
	var se *sftp.StatusError
	if errors.As(err, &se) && se.FxCode() == sftp.ErrSSHFxOpUnsupported {
		return nil
	}
	return err
}

func (h *Host) CreateTemp(dir, pattern string) (minion.WriteFile, error) {
	f, err := h.ftp()
	if err != nil {
		return nil, err
	}
	prefix, suffix := pattern, ""
	if i := strings.LastIndex(pattern, "*"); i >= 0 {
		prefix, suffix = pattern[:i], pattern[i+1:]
	}
	name := h.Join(dir, prefix+randomHex(8)+suffix)
	file, err := f.OpenFile(h.remote(name), os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return nil, pathErr("create", name, err)
	}
	return writeFile{File: file, name: name}, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (h *Host) WriteAt(p string, off int64, data []byte, create bool) error {
	f, err := h.ftp()
	if err != nil {
		return err
	}
	flags := os.O_WRONLY
	if create {
		flags |= os.O_CREATE | os.O_TRUNC
	}
	file, err := f.OpenFile(h.remote(p), flags)
	if err != nil {
		return pathErr("open", p, err)
	}
	if len(data) > 0 {
		if _, err := file.WriteAt(data, off); err != nil {
			_ = file.Close() // the write's error says it
			return pathErr("write", p, err)
		}
	}
	return pathErr("close", p, file.Close())
}

// Chmod sets a file's permission bits; on a Windows server, its read-only
// attribute (set without an owner's write bit), as Windows's OpenSSH takes
// them.
func (h *Host) Chmod(p string, mode fs.FileMode) error {
	f, err := h.ftp()
	if err != nil {
		return err
	}
	return pathErr("chmod", p, f.Chmod(h.remote(p), mode))
}

// Rename moves a file to to, replacing a file there: at once where the
// server renames the POSIX way (OpenSSH, Windows's too), else by removing it
// first.
func (h *Host) Rename(from, to string) error {
	f, err := h.ftp()
	if err != nil {
		return err
	}
	src, dst := h.remote(from), h.remote(to)
	if _, ok := f.HasExtension("posix-rename@openssh.com"); ok {
		return pathErr("rename", to, f.PosixRename(src, dst))
	}
	if _, err := f.Lstat(dst); err == nil {
		if err := f.Remove(dst); err != nil {
			return pathErr("remove", to, err)
		}
	}
	return pathErr("rename", to, f.Rename(src, dst))
}

// Remove removes a file, a link or an empty folder. A Windows server
// removes no read-only file: its read-only attribute goes first, as Go's
// os.Remove has it on Windows.
func (h *Host) Remove(p string) error {
	f, err := h.ftp()
	if err != nil {
		return err
	}
	at := h.remote(p)
	err = f.Remove(at)
	if err != nil && h.windows() {
		if fi, lerr := f.Lstat(at); lerr == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o200 == 0 && f.Chmod(at, 0o600) == nil {
			err = f.Remove(at)
		}
	}
	return pathErr("remove", p, err)
}

// RemoveAll removes a folder with what is in it; a Windows server's through
// winRemoveAll, which enters no junction.
func (h *Host) RemoveAll(p string) error {
	if h.drives() {
		return h.winRemoveAll(p)
	}
	f, err := h.ftp()
	if err != nil {
		return err
	}
	return pathErr("remove", p, f.RemoveAll(h.remote(p)))
}

// pidMark starts the first line a shell command writes: its shell's
// process id, which is its process group's, for stopping all it started.
// Random to the connection: nothing on the server reads as the minion's
// (the line is in the command's argv, which ps shows).
func (h *Host) pidMark() string { return h.elev().marker + ":" }

// Shell runs a command line in /bin/sh on a Unix server, its output (stdout
// and stderr, as they come) written to out. Stopped (ctx done), the
// command's whole process group is killed: what it started too, unless it
// left the group.
//
// A Windows server runs the line as typed in its default shell (cmd.exe /c
// "<line>", as cmd.exe /d /s /c runs it for BOB's minion on Windows), and a
// stop is a KILL signal, on which Windows's OpenSSH ends all the command
// started; closing the channel alone would leave it running.
func (h *Host) Shell(ctx context.Context, command string, out io.Writer) (minion.Exit, error) {
	return h.ShellStarted(ctx, command, out, func() {})
}

// ShellStarted is Shell, calling started once the command has what it runs
// in: the login's channel to come, or a shell elevated as the session's
// become, held. A become or an unbecome after that changes nothing for it.
func (h *Host) ShellStarted(ctx context.Context, command string, out io.Writer, started func()) (minion.Exit, error) {
	if h.Acting() != nil {
		// The session became another user: in a shell elevated so, never
		// as the login.
		return h.shellAs(ctx, command, out, started)
	}
	started()
	win := h.windows()
	s, err := h.c.Session()
	if err != nil {
		return minion.Exit{}, minion.NotStarted(err)
	}
	defer func() { _ = s.Close() }() // ended, or killed: nothing more to say
	// A Windows command's output has no mark to look for.
	w := &shellOut{w: out, seen: win, mark: h.pidMark()}
	s.Stdout, s.Stderr = w, stderrOf{w}
	line := command
	if !win {
		// The login's shell execs /bin/sh, which keeps its process id: the
		// session's process, and the process group sshd made for the
		// session.
		line = "exec /bin/sh -c " + shellQuote("echo "+w.mark+"$$; "+command)
	}
	if err := s.Start(line); err != nil {
		return minion.Exit{}, minion.NotStarted(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		if !win {
			h.kill(w.pid())
		}
		_ = s.Signal(ssh.SIGKILL)
		_ = s.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		return minion.Exit{}, ctx.Err()
	}
	var exitErr *ssh.ExitError
	switch {
	case err == nil:
		zero := int64(0)
		return minion.Exit{Code: &zero}, nil
	case errors.As(err, &exitErr) && exitErr.Signal() != "":
		return minion.Exit{Signal: exitErr.Signal()}, nil
	case errors.As(err, &exitErr):
		code := int64(exitErr.ExitStatus())
		return minion.Exit{Code: &code}, nil
	}
	return minion.Exit{}, err
}

// kill kills the process group pid leads, through a session of its own.
func (h *Host) kill(pid int) {
	if pid <= 1 {
		return
	}
	s, err := h.c.Session()
	if err != nil {
		return
	}
	defer func() { _ = s.Close() }() // best effort
	done := make(chan struct{})
	go func() {
		_ = s.Run(fmt.Sprintf("/bin/sh -c 'kill -s KILL -- -%d 2>/dev/null || kill -s KILL %d'", pid, pid))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

// shellQuote quotes s for a POSIX shell: in single quotes, each of its own
// written '\”.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// shellOut takes a command's output: its stdout, the first line (its
// process id) kept back, and its stderr (stderrOf), both passed on in the
// order they come. The streams come apart, so only stdout's first line can
// be the mark.
type shellOut struct {
	mu   sync.Mutex
	w    io.Writer
	head []byte
	seen bool
	id   int
	mark string
}

func (o *shellOut) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.seen {
		return o.write(p, len(p))
	}
	o.head = append(o.head, p...)
	i := bytes.IndexByte(o.head, '\n')
	if i < 0 && len(o.head) < 64 {
		return len(p), nil
	}
	o.seen = true
	line, rest := o.head, []byte(nil)
	if i >= 0 {
		line, rest = o.head[:i], o.head[i+1:]
	}
	if id, ok := strings.CutPrefix(string(line), o.mark); ok {
		o.id, _ = strconv.Atoi(strings.TrimSpace(id))
	} else {
		rest = o.head // no mark: all of it is the command's
	}
	o.head = nil
	return o.write(rest, len(p))
}

// stderrOf is a command's stderr, passed on as it comes.
type stderrOf struct{ o *shellOut }

func (e stderrOf) Write(p []byte) (int, error) {
	e.o.mu.Lock()
	defer e.o.mu.Unlock()
	return e.o.write(p, len(p))
}

func (o *shellOut) write(b []byte, n int) (int, error) {
	if len(b) > 0 {
		if _, err := o.w.Write(b); err != nil {
			return 0, err
		}
	}
	return n, nil
}

func (o *shellOut) pid() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.id
}

// run runs a command line of the channel's own on the server: its output,
// within wait.
func (h *Host) run(command string, wait time.Duration) (string, error) {
	s, err := h.c.Session()
	if err != nil {
		return "", err
	}
	defer func() { _ = s.Close() }() // read: nothing more to say
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := s.Output(command)
		done <- result{out, err}
	}()
	select {
	case r := <-done:
		return string(r.out), r.err
	case <-time.After(wait):
		return "", fmt.Errorf("%q did not end within %s", command, wait)
	}
}

// Volumes are the server's mounted file systems, as df says them (GNU's
// with their types, else POSIX's): those that hold files, with their
// space. A Windows server's are its drives (winVolumes).
func (h *Host) Volumes() ([]protocol.Volume, error) {
	if h.windows() {
		return h.winVolumes()
	}
	out, err := h.run("df -kPT 2>/dev/null || df -kP", 30*time.Second)
	if err != nil && out == "" {
		return nil, fmt.Errorf("df: %w", err)
	}
	return parseDF(out), nil
}

// pseudoFS hold no files of the server's: the kernel's views, cgroups and
// their like (as BOB's minion leaves them out).
var pseudoFS = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "cgroup": true, "cgroup2": true, "mqueue": true,
	"debugfs": true, "tracefs": true, "securityfs": true, "pstore": true, "bpf": true, "configfs": true, "fusectl": true,
	"hugetlbfs": true, "autofs": true, "binfmt_misc": true, "efivarfs": true, "nsfs": true, "rpc_pipefs": true,
	"selinuxfs": true, "nfsd": true,
}

// networkFS are file systems on another machine.
var networkFS = map[string]bool{
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "smbfs": true, "afs": true, "ceph": true, "glusterfs": true,
	"fuse.sshfs": true, "9p": true, "davfs": true, "fuse.rclone": true, "lustre": true, "gpfs": true,
}

// parseDFAll is every mount point df -kP (or -kPT) says, pseudo file
// systems too.
func parseDFAll(out string) []string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	at := 5
	if len(lines) > 0 && strings.Contains(lines[0], "Type") {
		at = 6
	}
	var points []string
	for _, line := range lines[min(1, len(lines)):] {
		if f := strings.Fields(line); len(f) > at {
			points = append(points, strings.Join(f[at:], " "))
		}
	}
	return points
}

// parseDF reads df -kP's lines (with a Type column when df -kPT made
// them): each mount's point, device, file system and space.
func parseDF(out string) []protocol.Volume {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 {
		return nil
	}
	typed := strings.Contains(lines[0], "Type")
	var vols []protocol.Volume
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		want := 6
		if typed {
			want = 7
		}
		if len(f) < want {
			continue
		}
		v := protocol.Volume{Device: f[0], Kind: protocol.VolumeOther}
		at := 1
		if typed {
			v.FS, at = f[1], 2
		}
		blocks, err1 := strconv.ParseUint(f[at], 10, 64)
		avail, err2 := strconv.ParseUint(f[at+2], 10, 64)
		// The mount point is the rest: it may hold spaces.
		v.Path = strings.Join(f[at+4:], " ")
		if pseudoFS[v.FS] || err1 != nil || err2 != nil || blocks == 0 || !strings.HasPrefix(v.Path, "/") {
			continue
		}
		size, free := blocks*1024, avail*1024
		v.Size, v.Free = &size, &free
		switch {
		case networkFS[v.FS] || strings.Contains(v.Device, ":/") || strings.HasPrefix(v.Device, "//"):
			v.Kind = protocol.VolumeNetwork
		case v.FS == "tmpfs" || v.FS == "ramfs":
			v.Kind = protocol.VolumeRAM
		case v.FS == "iso9660" || v.FS == "udf":
			v.Kind = protocol.VolumeOptical
		case strings.HasPrefix(v.Device, "/dev/") || v.FS == "zfs" || v.FS == "apfs":
			v.Kind = protocol.VolumeFixed
		}
		if v.Device == v.FS || v.Device == "none" {
			v.Device = ""
		}
		vols = append(vols, v)
	}
	return vols
}

// Version is the minion's own version, in its hello.
var Version = "dev"

var machineIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Hello is the server as the minion says it in its hello: its OS and
// architecture, host name and user (uname, id; a Windows server's as
// winHello reads them), its machine id (the server's own when it keeps
// one, else its host key's), and the SSH server's version and host key.
func (h *Host) Hello() protocol.HelloItem {
	most := uint64(4)
	hi := protocol.HelloItem{T: protocol.ItemHello, OS: "unknown", Arch: "unknown", Version: Version, MaxTasks: &most,
		X: map[string]any{"ssh_server": h.c.Version, "host_key": h.c.Fingerprint()}}
	if h.windows() {
		h.winHello(&hi)
		return hi
	}
	if out, err := h.run("uname -snm; id -un; id -u", 15*time.Second); err == nil {
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) > 0 {
			if f := strings.Fields(lines[0]); len(f) >= 3 {
				hi.OS, hi.Host, hi.Arch = goOS(f[0]), f[1], goArch(f[len(f)-1])
			}
		}
		if len(lines) > 1 {
			hi.User = strings.TrimSpace(lines[1])
		}
		if len(lines) > 2 {
			if uid, err := strconv.Atoi(strings.TrimSpace(lines[2])); err == nil {
				hi.Integrity = protocol.IntegrityUser
				if uid == 0 {
					hi.Integrity = protocol.IntegrityRoot
				}
			}
		}
	}
	hi.MachineSource, hi.MachineValue = h.machineID()
	return hi
}

// machineID is the server's machine id, read over SFTP: its own
// (/etc/machine-id, so a machine BOB's minion reaches too is one machine
// in the file browser), else the SHA-256 of its host key, in hex.
func (h *Host) machineID() (int, string) {
	if f, err := h.ftp(); err == nil {
		for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			file, err := f.Open(p)
			if err != nil {
				continue
			}
			b, _ := io.ReadAll(io.LimitReader(file, 128))
			_ = file.Close() // read only: nothing to lose on close
			if id := strings.ToLower(strings.TrimSpace(string(b))); machineIDPattern.MatchString(id) && id != strings.Repeat("0", 32) {
				return protocol.MachineLinuxMachineID, id
			}
		}
	}
	return h.hostKeyID()
}

// hostKeyID is the machine id of a server that says none of its own: the
// SHA-256 of its host key (its SSH wire form), in hex.
func (h *Host) hostKeyID() (int, string) {
	sum := sha256.Sum256(h.c.HostKey.Marshal())
	return protocol.MachineSSHHostKey, hex.EncodeToString(sum[:])
}

// goOS is uname -s in Go's names.
func goOS(s string) string {
	switch s {
	case "Linux":
		return "linux"
	case "Darwin":
		return "darwin"
	case "SunOS":
		return "solaris"
	}
	return strings.ToLower(s)
}

// goArch is uname -m in Go's names.
func goArch(s string) string {
	switch s {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	case "i386", "i486", "i586", "i686", "x86":
		return "386"
	case "armv6l", "armv7l", "armv7", "arm":
		return "arm"
	}
	return strings.ToLower(s)
}
