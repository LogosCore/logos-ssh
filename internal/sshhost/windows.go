package sshhost

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// A Windows server (docs: contracts/agentless-channels/, Windows servers):
// Windows's OpenSSH, whose SFTP says a drive's folders (/C:/Users/me) and
// which runs a command line in the server's default shell (cmd.exe /c,
// unless an administrator chose another). What the minion asks of the
// server itself it asks PowerShell (powershell.exe, on every Windows since
// 7 and Server 2008 R2), in a script of its own: its hello, the drives. The
// script keeps to what constrained language mode allows (cmdlets, CIM,
// core types), and says each value as hex of its UTF-16, since what a
// Windows command writes is in the console's code page.

// psCommand is the command line running script in PowerShell: the script
// as UTF-16 in base64 (-EncodedCommand), which no shell's quoting touches.
func psCommand(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " + base64.StdEncoding.EncodeToString(b)
}

// psPrelude starts each script: errors and progress quiet, and o, which
// writes a key and its value (as hex of its UTF-16) on a line, nothing for
// an empty value.
const psPrelude = `$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
function o($k, $v) { $s = "$v".Trim(); if ($s) { $k + '=' + (($s.ToCharArray() | ForEach-Object { '{0:x4}' -f [int]$_ }) -join '') } }
`

// psValues reads a script's output: each line's key and value.
func psValues(out string) map[string]string {
	vals := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || k == "" {
			continue
		}
		if s, ok := psText(v); ok {
			vals[k] = s
		}
	}
	return vals
}

// psText is a value o wrote: hex of its UTF-16.
func psText(h string) (string, bool) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b)%2 != 0 {
		return "", false
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
	}
	return string(utf16.Decode(u)), true
}

// winHelloScript reads what a Windows hello says, as BOB's minion has it on
// Windows: the host's DNS name, the machine's architecture, the user
// (DOMAIN\user), the domain the host is joined to (its DNS name) or its
// workgroup, the SMBIOS UUID and the install's MachineGuid (its machine
// id), and the login's mandatory label (whoami /groups: S-1-16-<rid>).
var winHelloScript = psPrelude + `o host (hostname.exe)
$a = $env:PROCESSOR_ARCHITEW6432; if (-not $a) { $a = $env:PROCESSOR_ARCHITECTURE }; o arch $a
$u = ''; try { $u = [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch {}; if (-not $u) { $u = whoami.exe }; o user $u
$cs = Get-CimInstance Win32_ComputerSystem
if ($cs.PartOfDomain) { o domain $cs.Domain } else { o domain $cs.Workgroup }
o uuid (Get-CimInstance Win32_ComputerSystemProduct).UUID
o guid (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
o label ((whoami.exe /groups /fo csv /nh) -join ' ')
`

// winHelloFallback is the hello's values through cmd, for a server whose
// PowerShell does not run: the host and architecture on a line of their
// own, the user (whoami), the MachineGuid and the groups.
const winHelloFallback = `echo LOGOS^|%COMPUTERNAME%^|%PROCESSOR_ARCHITECTURE% & whoami & reg query HKLM\SOFTWARE\Microsoft\Cryptography /v MachineGuid & whoami /groups /fo csv /nh`

var (
	labelPattern = regexp.MustCompile(`S-1-16-(\d+)`)
	guidPattern  = regexp.MustCompile(`(?i)MachineGuid\s+REG_SZ\s+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`)
	uuidPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// winHello fills a Windows server's part of hi: from PowerShell, else from
// cmd; what neither says stays as it is.
func (h *Host) winHello(hi *protocol.HelloItem) {
	hi.OS = "windows"
	vals := map[string]string{}
	if out, err := h.run(psCommand(winHelloScript), 60*time.Second); err == nil || out != "" {
		vals = psValues(out)
	}
	if vals["host"] == "" && vals["user"] == "" {
		if out, err := h.run(winHelloFallback, 30*time.Second); err == nil || out != "" {
			vals = cmdHelloValues(out)
		}
	}
	if v := vals["host"]; v != "" {
		hi.Host = v
	}
	if v := vals["arch"]; v != "" {
		hi.Arch = goArch(strings.ToLower(v))
	}
	hi.User, hi.Domain = vals["user"], vals["domain"]
	if m := labelPattern.FindStringSubmatch(vals["label"]); m != nil {
		if rid, err := strconv.ParseUint(m[1], 10, 32); err == nil {
			hi.Integrity = integrityOfRID(uint32(rid))
		}
	}
	if hi.Integrity == 0 {
		hi.Integrity = protocol.IntegrityUser
	}
	hi.MachineSource, hi.MachineValue = h.winMachineID(vals)
}

// cmdHelloValues reads winHelloFallback's output, in the code page of the
// server's console, which ASCII reads the same in: what else a name holds
// is lost.
func cmdHelloValues(out string) map[string]string {
	vals := map[string]string{}
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "LOGOS|")
		if !ok {
			continue
		}
		if host, arch, ok := strings.Cut(rest, "|"); ok {
			vals["host"], vals["arch"] = strings.ToValidUTF8(host, "?"), arch
		}
		// whoami's line comes next: DOMAIN\user.
		if i+1 < len(lines) {
			if u := strings.TrimSpace(lines[i+1]); strings.Contains(u, `\`) && !strings.HasPrefix(u, "HKEY_") && !strings.HasPrefix(u, `"`) {
				vals["user"] = strings.ToValidUTF8(u, "?")
			}
		}
		break
	}
	if m := guidPattern.FindStringSubmatch(out); m != nil {
		vals["guid"] = m[1]
	}
	if m := labelPattern.FindString(out); m != "" {
		vals["label"] = m
	}
	return vals
}

// winMachineID is a Windows server's machine id, as BOB's minion reads it
// on Windows (the same machine is one in the file browser whichever minion
// reached it): the SMBIOS UUID, else the MachineGuid, else the SHA-256 of
// the server's host key.
func (h *Host) winMachineID(vals map[string]string) (int, string) {
	if v := strings.ToLower(strings.TrimSpace(vals["uuid"])); uuidPattern.MatchString(v) && !protocol.PlaceholderMachineUUID(v) {
		return protocol.MachineSMBIOSUUID, v
	}
	if v := strings.ToLower(strings.Trim(strings.TrimSpace(vals["guid"]), "{}")); uuidPattern.MatchString(v) && !protocol.PlaceholderMachineUUID(v) {
		return protocol.MachineWinMachineGUID, v
	}
	return h.hostKeyID()
}

// integrityOfRID is a Windows mandatory label's level by its RID, as BOB's
// minion has it: below medium (0x2000) low, below high (0x3000) medium,
// below system (0x4000) high, and system from there.
func integrityOfRID(rid uint32) int {
	switch {
	case rid < 0x2000:
		return protocol.IntegrityLow
	case rid < 0x3000:
		return protocol.IntegrityMedium
	case rid < 0x4000:
		return protocol.IntegrityHigh
	}
	return protocol.IntegritySystem
}

// winVolumesScript lists the server's drives (Win32_LogicalDisk): each one's
// letter, drive type, label, file system, size, free space and, for a
// network drive, its share.
var winVolumesScript = psPrelude + `foreach ($d in Get-CimInstance Win32_LogicalDisk) {
	'drive=' + $d.DeviceID + ',' + [int]$d.DriveType + ',' + $d.Size + ',' + $d.FreeSpace
	o label $d.VolumeName
	o fs $d.FileSystem
	o share $d.ProviderName
}
`

// parseWinVolumes reads winVolumesScript's output: a drive's line, then its
// label, file system and share, each on its own line when it has one.
func parseWinVolumes(out string) []protocol.Volume {
	var vols []protocol.Volume
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		if k == "drive" {
			if vol, ok := winDrive(v); ok {
				vols = append(vols, vol)
			}
			continue
		}
		s, ok := psText(v)
		if !ok || len(vols) == 0 {
			continue
		}
		last := &vols[len(vols)-1]
		switch k {
		case "label":
			last.Label = s
		case "fs":
			last.FS = s
		case "share":
			last.Device = s
		}
	}
	return vols
}

// winDrive is a drive's line: C:,3,<size>,<free>. A drive without a size is
// one with nothing in it (an empty DVD drive), as BOB's minion says it.
func winDrive(line string) (protocol.Volume, bool) {
	f := strings.Split(line, ",")
	if len(f) != 4 || len(f[0]) != 2 || f[0][1] != ':' || !isLetter(f[0][0]) {
		return protocol.Volume{}, false
	}
	t, err := strconv.Atoi(f[1])
	if err != nil || t == 1 { // 1: no root folder, no drive
		return protocol.Volume{}, false
	}
	v := protocol.Volume{Path: strings.ToUpper(f[0]) + `\`, Kind: driveKind(t)}
	size, err1 := strconv.ParseUint(f[2], 10, 64)
	free, err2 := strconv.ParseUint(f[3], 10, 64)
	if err1 == nil && err2 == nil {
		v.Size, v.Free = &size, &free
	} else {
		v.NoMedia = true
	}
	return v, true
}

// driveKind is a drive's kind by its type (Win32_LogicalDisk's DriveType,
// GetDriveType's numbers).
func driveKind(t int) string {
	switch t {
	case 2:
		return protocol.VolumeRemovable
	case 3:
		return protocol.VolumeFixed
	case 4:
		return protocol.VolumeNetwork
	case 5:
		return protocol.VolumeOptical
	case 6:
		return protocol.VolumeRAM
	}
	return protocol.VolumeOther
}

// winVolumes are a Windows server's drives: from PowerShell, else the
// drives SFTP's root lists, with their space where the server says it
// (statvfs@openssh.com).
func (h *Host) winVolumes() ([]protocol.Volume, error) {
	out, err := h.run(psCommand(winVolumesScript), 60*time.Second)
	if vols := parseWinVolumes(out); len(vols) > 0 {
		return vols, nil
	}
	f, ferr := h.ftp()
	if ferr != nil {
		return nil, fmt.Errorf("the drives: %w", firstErr(err, ferr))
	}
	infos, rerr := f.ReadDir("/")
	if rerr != nil {
		return nil, fmt.Errorf("the drives: %w", firstErr(err, rerr))
	}
	var vols []protocol.Volume
	for _, fi := range infos {
		name := fi.Name()
		if len(name) != 2 || name[1] != ':' || !isLetter(name[0]) {
			continue
		}
		v := protocol.Volume{Path: strings.ToUpper(name) + `\`, Kind: protocol.VolumeOther}
		if st, err := f.StatVFS("/" + name + "/"); err == nil {
			size, free := st.TotalSpace(), st.Frsize*st.Bavail
			v.Size, v.Free = &size, &free
		}
		vols = append(vols, v)
	}
	return vols, nil
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// The attributes a listing says of a Windows server's file, as BOB's minion
// sends them (FILE_ATTRIBUTE_*: core shows them as PowerShell's Mode does).
const (
	attrReadOnly  = 0x1
	attrHidden    = 0x2
	attrSystem    = 0x4
	attrDirectory = 0x10
	attrArchive   = 0x20
	attrReparse   = 0x400
)

// winEntry is what cmd's dir says of a folder's entry that SFTP does not:
// its attributes (but the folder's, which SFTP says), and whether it is a
// junction, with its target. Windows's SFTP reads a junction as the folder
// it points to, and follows it: a walk would loop through one that points
// above it (AppData\Local\Application Data), and a removal would reach
// through one into what it points to.
type winEntry struct {
	attrs    uint32
	junction bool
	target   string
}

// winDirCommand asks cmd's dir of a folder's entries, in UTF-8 (chcp 65001,
// said by a mark when it took): its reparse points' lines (a junction's
// names its target), then the names with each attribute, each part after a
// mark of its own.
func winDirCommand(dir string) string {
	q := `"` + dir + `"`
	return `chcp 65001 >nul && echo LOGOS-UTF8 & dir /a:l ` + q + ` & echo LOGOS-L & dir /a:l /b ` + q +
		` & echo LOGOS-H & dir /a:h /b ` + q + ` & echo LOGOS-S & dir /a:s /b ` + q +
		` & echo LOGOS-R & dir /a:r /b ` + q + ` & echo LOGOS-A & dir /a:a /b ` + q
}

// junctionTarget finds where a junction's target starts in its line.
var junctionTarget = regexp.MustCompile(`\s\[([A-Za-z]:\\|\\\\|\\\?\?\\)`)

// attrOfMark is the attribute each part of winDirCommand's output names.
var attrOfMark = map[string]uint32{"L": attrReparse, "H": attrHidden, "S": attrSystem, "R": attrReadOnly, "A": attrArchive}

// parseWinDir reads winDirCommand's output: each entry it names, by name;
// false when it is not in UTF-8 (a name it holds would not be SFTP's).
func parseWinDir(out string) (map[string]winEntry, bool) {
	entries := map[string]winEntry{}
	part, utf8 := "", false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if mark, ok := strings.CutPrefix(strings.TrimSpace(line), "LOGOS-"); ok {
			if mark == "UTF8" {
				utf8, part = true, "D"
				continue
			}
			if _, ok := attrOfMark[mark]; ok {
				part = mark
				continue
			}
		}
		if line == "" || !strings.ContainsFunc(line, func(r rune) bool { return r != ' ' }) {
			continue
		}
		if part == "D" {
			// 23.10.2026  22:00    <JUNCTION>     Application Data [C:\Users\me\AppData\Local]
			i := strings.Index(line, "<JUNCTION>")
			if i < 0 {
				continue
			}
			// A name holds no \ or :, and a junction's target is absolute:
			// the first " [" before a drive's path, a share's or a volume's
			// (\??\Volume{…}\) starts it.
			name, target := strings.TrimSpace(line[i+len("<JUNCTION>"):]), ""
			if m := junctionTarget.FindStringIndex(name); m != nil && strings.HasSuffix(name, "]") {
				name, target = name[:m[0]], strings.ToValidUTF8(name[m[0]+2:len(name)-1], "?")
			}
			e := entries[name]
			e.junction, e.target = true, target
			entries[name] = e
			continue
		}
		if a, ok := attrOfMark[part]; ok {
			e := entries[line]
			e.attrs |= a
			entries[line] = e
		}
	}
	return entries, utf8
}

// envPattern finds what cmd would read as an environment variable in a
// command line, quotes or not: %NAME%.
var envPattern = regexp.MustCompile(`%[^%]+%`)

// winAttrs is what cmd's dir says of the entries of the Windows folder dir
// (winEntry), by name; false when it could not say it in full: its output
// not UTF-8, or a path cmd would read otherwise (one naming a variable).
func (h *Host) winAttrs(dir string) (map[string]winEntry, bool) {
	if envPattern.MatchString(dir) {
		return nil, false
	}
	// dir fails (no file found) where no entry has an attribute: what it
	// said is what counts.
	out, err := h.run(winDirCommand(dir), 30*time.Second)
	if err != nil && out == "" {
		return nil, false
	}
	return parseWinDir(out)
}

// junction reports whether the Windows folder p is a junction, as cmd's dir
// says among its parent's entries; known false when it cannot say.
func (h *Host) junction(p string) (junction, known bool) {
	parent := winDir(p)
	if parent == p {
		return false, true // a root
	}
	attrs, ok := h.winAttrs(parent)
	return ok && attrs[winBase(p)].junction, ok
}

// winRemoveAll removes a Windows folder with what is in it, as Go's
// os.RemoveAll does on Windows: a junction or a link as itself, never what
// it points to. A folder whose junctions cmd cannot tell apart is not
// reached through: the removal stops there.
func (h *Host) winRemoveAll(p string) error {
	f, err := h.ftp()
	if err != nil {
		return err
	}
	fi, err := f.Lstat(sftpPath(p))
	if err != nil {
		return pathErr("lstat", p, err)
	}
	if !fi.IsDir() {
		return h.Remove(p) // a file, or a link SFTP says is one
	}
	switch junction, known := h.junction(p); {
	case !known:
		return fmt.Errorf("%s: whether it is a junction cannot be told: not removed", p)
	case junction:
		return h.Remove(p)
	}
	return h.winRemoveTree(p)
}

// winRemoveTree removes the folder dir and all in it, entering only
// folders: junctions and links go as themselves.
func (h *Host) winRemoveTree(dir string) error {
	f, err := h.ftp()
	if err != nil {
		return err
	}
	infos, err := f.ReadDir(sftpPath(dir))
	if err != nil {
		return pathErr("readdir", dir, err)
	}
	attrs, ok := h.winAttrs(dir)
	if !ok {
		return fmt.Errorf("%s: its junctions cannot be told apart: not removed", dir)
	}
	for _, fi := range infos {
		at := winJoin(dir, fi.Name())
		if fi.IsDir() && !attrs[fi.Name()].junction {
			if err := h.winRemoveTree(at); err != nil {
				return err
			}
			continue
		}
		if err := h.Remove(at); err != nil {
			return err
		}
	}
	return h.Remove(dir)
}
