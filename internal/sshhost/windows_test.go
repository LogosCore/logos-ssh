//go:build unix

package sshhost

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-ssh/internal/connection"
	"github.com/logoscore/logos-ssh/internal/sshconn"
	"github.com/logoscore/logos-ssh/internal/sshtest"
)

// What a Windows server's cmd says of a folder (a win11 server's, its names
// shortened) reads as each entry's attributes, and its junctions with their
// targets.
func TestParseWinDir(t *testing.T) {
	out := "LOGOS-UTF8 \r\n Volume in drive C has no label.\r\n Volume Serial Number is 1234-ABCD\r\n\r\n Directory of C:\\Users\\user\\AppData\\Local\r\n\r\n" +
		"23.10.2026  22:00    <JUNCTION>     Application Data [C:\\Users\\user\\AppData\\Local]\r\n" +
		"23.10.2026  22:00    <JUNCTION>     a [b] [C:\\x [y]]\r\n" +
		"23.10.2026  22:00    <SYMLINKD>     All Users [C:\\ProgramData]\r\n" +
		"23.10.2026  22:00    <JUNCTION>     disk2 [\\??\\Volume{6a1b}\\]\r\n" +
		"               0 File(s)              0 bytes\r\n" +
		"LOGOS-L \r\nApplication Data\r\na [b]\r\nAll Users\r\n" +
		"LOGOS-H \r\nApplication Data\r\nIconCache.db\r\n" +
		"LOGOS-S \r\nApplication Data\r\n" +
		"LOGOS-R \r\n" +
		"LOGOS-A \r\nIconCache.db\r\n"
	got, ok := parseWinDir(out)
	if !ok {
		t.Fatal("not read as UTF-8")
	}
	want := map[string]winEntry{
		"Application Data": {attrs: attrReparse | attrHidden | attrSystem, junction: true, target: `C:\Users\user\AppData\Local`},
		"a [b]":            {attrs: attrReparse, junction: true, target: `C:\x [y]`},
		"All Users":        {attrs: attrReparse},
		"disk2":            {junction: true, target: `\??\Volume{6a1b}\`},
		"IconCache.db":     {attrs: attrHidden | attrArchive},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%q: %+v, want %+v", name, got[name], w)
		}
	}
	if _, ok := parseWinDir("Active code page: 866\r\nLOGOS-L\r\nx\r\n"); ok {
		t.Error("output without the UTF-8 mark read as UTF-8")
	}
}

// A script goes as UTF-16 in base64; what it says comes back as hex of
// UTF-16, whatever the console's code page.
func TestPowerShellValues(t *testing.T) {
	script := "o name 'Пользователь'"
	cmd := psCommand(script)
	b64, ok := strings.CutPrefix(cmd, "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ")
	if !ok {
		t.Fatalf("command %q", cmd)
	}
	if got := decodeScript(t, b64); got != script {
		t.Fatalf("the script decodes to %q", got)
	}
	vals := psValues("user=" + psHex(`DESKTOP-1\Пользователь`) + "\r\nnoise\r\nbad=zz\r\n")
	if vals["user"] != `DESKTOP-1\Пользователь` || len(vals) != 1 {
		t.Fatalf("values %q", vals)
	}
}

// cmd's fallback hello: the marked line, whoami's after it, the
// MachineGuid and the mandatory label (a win11 server's output).
func TestCmdHelloValues(t *testing.T) {
	out := "LOGOS|DESKTOP-4VC4EKT|AMD64 \r\ndesktop-4vc4ekt\\user\r\n\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\r\n" +
		"    MachineGuid    REG_SZ    34c32f24-2db3-4b29-bf21-b94b36628172\r\n\r\n" +
		"\"Everyone\",\"Well-known group\",\"S-1-1-0\",\"Mandatory group\"\r\n\"Mandatory Label\\High Mandatory Level\",\"Label\",\"S-1-16-12288\",\"\"\r\n"
	vals := cmdHelloValues(out)
	want := map[string]string{"host": "DESKTOP-4VC4EKT", "arch": "AMD64", "user": `desktop-4vc4ekt\user`,
		"guid": "34c32f24-2db3-4b29-bf21-b94b36628172", "label": "S-1-16-12288"}
	for k, v := range want {
		if vals[k] != v {
			t.Errorf("%s: %q, want %q", k, vals[k], v)
		}
	}
}

// A drive's line and what follows it: its label, file system and share; an
// empty DVD drive says no media.
func TestParseWinVolumes(t *testing.T) {
	out := "drive=C:,3,84706062336,35696390144\r\nlabel=" + psHex("Система") + "\r\nfs=" + psHex("NTFS") + "\r\n" +
		"drive=D:,5,,\r\n" + "drive=Z:,4,1000,10\r\nshare=" + psHex(`\\srv\share`) + "\r\n" + "drive=Q:,1,,\r\n"
	vols := parseWinVolumes(out)
	if len(vols) != 3 {
		t.Fatalf("volumes %+v", vols)
	}
	c, d, z := vols[0], vols[1], vols[2]
	if c.Path != `C:\` || c.Kind != protocol.VolumeFixed || c.Label != "Система" || c.FS != "NTFS" || *c.Size != 84706062336 || *c.Free != 35696390144 {
		t.Errorf("C: %+v", c)
	}
	if d.Path != `D:\` || d.Kind != protocol.VolumeOptical || !d.NoMedia || d.Size != nil {
		t.Errorf("D: %+v", d)
	}
	if z.Kind != protocol.VolumeNetwork || z.Device != `\\srv\share` {
		t.Errorf("Z: %+v", z)
	}
}

func psHex(s string) string {
	var b strings.Builder
	for _, c := range utf16.Encode([]rune(s)) {
		fmt.Fprintf(&b, "%04x", c)
	}
	return b.String()
}

func decodeScript(t *testing.T, b64 string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b)%2 != 0 {
		t.Fatalf("not base64 UTF-16: %v", err)
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}

// fakeWindows answers what the minion asks a Windows server, from dir (C:\):
// cmd's dir of a folder (a link to a folder a junction, attrs the
// attributes by path, read-only by the file's mode), the hello's and the
// volumes' scripts (hello and volumes their output; "" fails the script),
// and the commands a test runs: echo, exit /b, and block, which waits for
// a stop.
type fakeWindows struct {
	dir            string
	attrs          map[string]string
	hello, volumes string
	fallback       string
	ran            []string
}

var dirPart = regexp.MustCompile(`dir /a:([lhsra])( /b)? "([^"]*)"`)

func (w *fakeWindows) exec(ctx context.Context, command string, out, _ io.Writer) int {
	w.ran = append(w.ran, command)
	switch {
	case strings.HasPrefix(command, "powershell.exe "):
		script := decodeScriptQuiet(command[strings.LastIndex(command, " ")+1:])
		switch {
		case strings.Contains(script, "Win32_ComputerSystemProduct") && w.hello != "":
			_, _ = io.WriteString(out, w.hello)
			return 0
		case strings.Contains(script, "Win32_LogicalDisk") && w.volumes != "":
			_, _ = io.WriteString(out, w.volumes)
			return 0
		}
		return 1
	case strings.Contains(command, "LOGOS-UTF8"):
		return w.dirOf(command, out)
	case strings.HasPrefix(command, "echo LOGOS^|"):
		_, _ = io.WriteString(out, w.fallback)
		return 0
	case strings.HasPrefix(command, "echo "):
		_, _ = io.WriteString(out, strings.TrimPrefix(command, "echo ")+"\r\n")
		return 0
	case strings.HasPrefix(command, "exit /b "):
		var code int
		_, _ = fmt.Sscanf(command, "exit /b %d", &code)
		return code
	case command == "block":
		_, _ = io.WriteString(out, "waiting\r\n")
		<-ctx.Done()
		return 1
	}
	_, _ = io.WriteString(out, "'"+command+"' is not recognized\r\n")
	return 1
}

func decodeScriptQuiet(b64 string) string {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}

// local is a Windows path's file in dir.
func (w *fakeWindows) local(p string) string {
	return filepath.Join(w.dir, filepath.FromSlash(strings.ReplaceAll(strings.TrimPrefix(p, `C:\`), `\`, "/")))
}

// windowsPath is a file in dir as Windows writes it.
func (w *fakeWindows) windowsPath(f string) string {
	rel, _ := filepath.Rel(w.dir, f)
	return winClean(`C:\` + strings.ReplaceAll(rel, "/", `\`))
}

func (w *fakeWindows) dirOf(command string, out io.Writer) int {
	parts := dirPart.FindAllStringSubmatch(command, -1)
	if len(parts) == 0 {
		return 1
	}
	folder := parts[0][3]
	entries, err := os.ReadDir(w.local(folder))
	if err != nil {
		return 1
	}
	var b strings.Builder
	b.WriteString("LOGOS-UTF8 \r\n Volume in drive C has no label.\r\n\r\n Directory of " + folder + "\r\n\r\n")
	has := func(e os.DirEntry, attr byte) bool {
		full := filepath.Join(w.local(folder), e.Name())
		fi, err := os.Lstat(full)
		if err != nil {
			return false
		}
		switch attr {
		case 'l':
			return fi.Mode()&fs.ModeSymlink != 0
		case 'r':
			if fi.Mode().IsRegular() && fi.Mode().Perm()&0o200 == 0 {
				return true
			}
		}
		return strings.ContainsRune(strings.ToLower(w.attrs[winJoin(folder, e.Name())]), rune(attr))
	}
	for _, e := range entries {
		full := filepath.Join(w.local(folder), e.Name())
		if st, err := os.Stat(full); err == nil && st.IsDir() && has(e, 'l') {
			target, _ := filepath.EvalSymlinks(full)
			fmt.Fprintf(&b, "01.11.2026  10:00    <JUNCTION>     %s [%s]\r\n", e.Name(), w.windowsPath(target))
		}
	}
	for _, attr := range []byte("lhsra") {
		fmt.Fprintf(&b, "LOGOS-%c \r\n", attr-'a'+'A')
		for _, e := range entries {
			if has(e, attr) {
				b.WriteString(e.Name() + "\r\n")
			}
		}
	}
	_, _ = io.WriteString(out, b.String())
	return 0
}

// winHost is a Host over a test's Windows server, its C: drive dir.
func winHost(t *testing.T, w *fakeWindows) (*Host, *sshtest.Server) {
	t.Helper()
	srv := sshtest.NewWindows(t, w.dir, w.exec)
	tg, err := connection.ReadTarget(srv.Values(), srv.Credentials())
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := sshconn.Dial(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return New(c), srv
}

// A Windows server's paths are Windows's, its listings say attributes,
// a junction is a link to its target, and files read, write, move and go
// over SFTP's /C:/ paths; a removal reaches through no junction.
func TestWindowsFiles(t *testing.T) {
	w := &fakeWindows{dir: t.TempDir(), attrs: map[string]string{}}
	h, _ := winHost(t, w)
	home := filepath.Join(w.dir, "Users", "tester")
	target := filepath.Join(w.dir, "Target")
	for _, d := range []string{filepath.Join(home, "Docs"), target} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for f, data := range map[string]string{filepath.Join(home, "NTUSER.DAT"): "hive", filepath.Join(home, "ro.txt"): "ro", filepath.Join(target, "keep.txt"): "keep"} {
		if err := os.WriteFile(f, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(home, "ro.txt"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, "Junction")); err != nil {
		t.Fatal(err)
	}
	w.attrs[`C:\Users\tester\NTUSER.DAT`] = "AH"

	if h.Sep() != `\` {
		t.Fatalf("sep %q", h.Sep())
	}
	if abs, err := h.Abs("~/Docs"); err != nil || abs != `C:\Users\tester\Docs` {
		t.Fatalf("abs %q %v", abs, err)
	}
	if abs, _ := h.Abs("c:"); abs != `C:\` {
		t.Fatalf("a drive alone: %q", abs)
	}
	entries, err := h.ReadDir(`C:\Users\tester`)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]int{}
	for i, e := range entries {
		names[e.Name] = i
	}
	docs, hive, jn, ro := entries[names["Docs"]], entries[names["NTUSER.DAT"]], entries[names["Junction"]], entries[names["ro.txt"]]
	if docs.Type != protocol.EntryDir || protocol.RenderMode("windows", docs.Mode) != "d-----" || docs.OwnerName != "" || docs.Dev != 3 {
		t.Errorf("a folder: %+v %s", docs, protocol.RenderMode("windows", docs.Mode))
	}
	if !hive.Hidden || protocol.RenderMode("windows", hive.Mode) != "-a-h--" {
		t.Errorf("a hidden file: %+v %s", hive, protocol.RenderMode("windows", hive.Mode))
	}
	if jn.Type != protocol.EntryLink || jn.Target != `C:\Target` || protocol.RenderMode("windows", jn.Mode) != "d----l" {
		t.Errorf("a junction: %+v %s", jn, protocol.RenderMode("windows", jn.Mode))
	}
	if protocol.RenderMode("windows", ro.Mode) != "--r---" {
		t.Errorf("a read-only file: %s", protocol.RenderMode("windows", ro.Mode))
	}
	if i, err := h.Lstat(`C:\Users\tester\Junction`); err != nil || i.Mode&fs.ModeSymlink == 0 {
		t.Errorf("a junction's lstat: %v %v", i.Mode, err)
	}
	if i, err := h.Stat(`C:\Users\tester\Junction`); err != nil || !i.IsDir() {
		t.Errorf("a junction's stat: %v %v", i.Mode, err)
	}

	// Write a file in place of one, as an upload does.
	tmp, err := h.CreateTemp(`C:\Users\tester\Docs`, ".a.txt.*.part")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tmp.Name(), `C:\Users\tester\Docs\.a.txt.`) {
		t.Fatalf("temp %q", tmp.Name())
	}
	if _, err := tmp.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(tmp.Sync(), tmp.Close()); err != nil {
		t.Fatal(err)
	}
	dest := h.Join(`C:\Users\tester\Docs`, "a.txt")
	if err := h.WriteAt(dest, 0, []byte("old"), true); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(h.Chmod(tmp.Name(), 0o644), h.Rename(tmp.Name(), dest)); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(home, "Docs", "a.txt")); err != nil || string(b) != "new" {
		t.Fatalf("replaced: %q %v", b, err)
	}

	// A read-only file goes; a removal goes round the junction, not into it.
	if err := h.Remove(`C:\Users\tester\ro.txt`); err != nil {
		t.Fatalf("a read-only file: %v", err)
	}
	if err := h.RemoveAll(`C:\Users\tester`); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(home); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the folder stays: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "keep.txt")); err != nil {
		t.Errorf("the junction's target lost its file: %v", err)
	}
}

// A folder named for a variable is not told apart: no attributes, and a
// removal does not reach into it.
func TestWindowsUntoldFolder(t *testing.T) {
	w := &fakeWindows{dir: t.TempDir()}
	h, _ := winHost(t, w)
	odd := filepath.Join(w.dir, "Users", "tester", "%TEMP%")
	if err := os.MkdirAll(filepath.Join(odd, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := h.RemoveAll(`C:\Users\tester\%TEMP%`); err == nil || !strings.Contains(err.Error(), "cannot be told") {
		t.Fatalf("removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(odd, "x")); err != nil {
		t.Fatal(err)
	}
}

// A Windows server runs a command as typed, its exit code said; a stop is
// a signal, which ends the command there.
func TestWindowsShell(t *testing.T) {
	w := &fakeWindows{dir: t.TempDir()}
	h, srv := winHost(t, w)
	var out bytes.Buffer
	exit, err := h.Shell(context.Background(), `echo "a&b" & echo c`, &out)
	if err != nil || exit.Code == nil || *exit.Code != 0 || out.String() != "\"a&b\" & echo c\r\n" {
		t.Fatalf("exit %+v %v %q", exit, err, out.String())
	}
	if exit, _ := h.Shell(context.Background(), "exit /b 3", io.Discard); exit.Code == nil || *exit.Code != 3 {
		t.Fatalf("exit %+v", exit)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	out.Reset()
	start := time.Now()
	if _, err := h.Shell(ctx, "block", &out); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a stopped command: %v", err)
	}
	if srv.Signals.Load() == 0 || time.Since(start) > 2*time.Second || out.String() != "waiting\r\n" {
		t.Fatalf("signals %d, took %s, out %q", srv.Signals.Load(), time.Since(start), out.String())
	}
	if slices.ContainsFunc(w.ran, func(c string) bool { return strings.Contains(c, "/bin/sh") }) {
		t.Fatalf("ran %q", w.ran)
	}
}

// A Windows server's hello: from PowerShell, its SMBIOS UUID the machine id
// (BOB's on Windows); from cmd when PowerShell does not run, the
// MachineGuid; the host key's when neither says.
func TestWindowsHello(t *testing.T) {
	w := &fakeWindows{dir: t.TempDir()}
	h, _ := winHost(t, w)
	w.hello = "host=" + psHex("DESKTOP-4VC4EKT") + "\r\narch=" + psHex("AMD64") + "\r\nuser=" + psHex(`DESKTOP-4VC4EKT\user`) +
		"\r\ndomain=" + psHex("WORKGROUP") + "\r\nuuid=" + psHex("D5AE7456-84CA-4245-9ED3-7D1177481EAC") +
		"\r\nguid=" + psHex("34c32f24-2db3-4b29-bf21-b94b36628172") + "\r\nlabel=" + psHex(`"Mandatory Label\High Mandatory Level","Label","S-1-16-12288",""`) + "\r\n"
	hi := h.Hello()
	if err := hi.Validate(); err != nil {
		t.Fatal(err)
	}
	if hi.OS != "windows" || hi.Arch != "amd64" || hi.Host != "DESKTOP-4VC4EKT" || hi.User != `DESKTOP-4VC4EKT\user` || hi.Domain != "WORKGROUP" ||
		hi.Integrity != protocol.IntegrityHigh || hi.PID != 0 ||
		protocol.MachineID(hi.MachineSource, hi.MachineValue) != "smbios-uuid:d5ae7456-84ca-4245-9ed3-7d1177481eac" {
		t.Fatalf("hello %+v", hi)
	}

	w.hello = ""
	w.fallback = "LOGOS|DESKTOP-4VC4EKT|ARM64 \r\ndesktop-4vc4ekt\\user\r\n    MachineGuid    REG_SZ    34C32F24-2DB3-4B29-BF21-B94B36628172\r\n" +
		"\"Mandatory Label\\Medium Mandatory Level\",\"Label\",\"S-1-16-8192\",\"\"\r\n"
	hi = h.Hello()
	if hi.Arch != "arm64" || hi.User != `desktop-4vc4ekt\user` || hi.Integrity != protocol.IntegrityMedium ||
		protocol.MachineID(hi.MachineSource, hi.MachineValue) != "win-machine-guid:34c32f24-2db3-4b29-bf21-b94b36628172" {
		t.Fatalf("cmd's hello %+v", hi)
	}

	w.fallback = ""
	hi = h.Hello()
	if hi.OS != "windows" || hi.MachineSource != protocol.MachineSSHHostKey || hi.Integrity != protocol.IntegrityUser || hi.Validate() != nil {
		t.Fatalf("a hello with nothing said %+v", hi)
	}
}

// A Windows server's volumes are its drives: from PowerShell, else those
// SFTP's root lists, with their space.
func TestWindowsVolumes(t *testing.T) {
	w := &fakeWindows{dir: t.TempDir()}
	h, _ := winHost(t, w)
	w.volumes = "drive=C:,3,100,40\r\nfs=" + psHex("NTFS") + "\r\ndrive=D:,5,,\r\n"
	vols, err := h.Volumes()
	if err != nil || len(vols) != 2 || vols[0].Path != `C:\` || vols[0].FS != "NTFS" || !vols[1].NoMedia {
		t.Fatalf("volumes %+v %v", vols, err)
	}
	w.volumes = ""
	vols, err = h.Volumes()
	if err != nil || len(vols) != 1 || vols[0].Path != `C:\` || vols[0].Size == nil || *vols[0].Size == 0 {
		t.Fatalf("from SFTP's root %+v %v", vols, err)
	}
}
