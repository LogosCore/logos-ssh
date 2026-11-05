package sshhost

import "strings"

// Windows paths (docs: contracts/agentless-channels/, Windows servers): core
// and the minion's commands have them as Windows writes them (C:\Users\me,
// \\server\share\x), as BOB's minion says them on Windows, and Windows's
// OpenSSH serves SFTP with each drive a folder of its root (/C:/Users/me).
// Every SFTP call takes its path through sftpPath, and what SFTP says comes
// back through fromSFTP.

func isLetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

func isSep(c byte) bool { return c == '\\' || c == '/' }

// winVolumeLen is the length of a Windows path's volume: 2 for a drive's
// ("C:"), the share's for one on a share (\\server\share); 0 for none. /
// counts as \.
func winVolumeLen(p string) int {
	if len(p) >= 2 && p[1] == ':' && isLetter(p[0]) {
		return 2
	}
	if len(p) < 5 || !isSep(p[0]) || !isSep(p[1]) || isSep(p[2]) {
		return 0
	}
	// \\server\share: a server and a share, neither empty.
	server := strings.IndexAny(p[2:], `\/`)
	if server <= 0 {
		return 0
	}
	at := 2 + server + 1
	share := strings.IndexAny(p[at:], `\/`)
	switch {
	case share < 0 && at < len(p):
		return len(p)
	case share <= 0:
		return 0
	}
	return at + share
}

// winClean is a Windows path clean: \ between its parts, none doubled, no
// . or .., a drive's letter upper case; a root keeps its \ (C:\,
// \\server\share\).
func winClean(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	n := winVolumeLen(p)
	volume, rest := p[:n], p[n:]
	if n == 2 {
		volume = strings.ToUpper(volume)
	}
	// A share's path is from the share's root, whether it says \ or not.
	rooted := strings.HasPrefix(rest, `\`) || n > 2
	var parts []string
	for _, s := range strings.Split(rest, `\`) {
		switch {
		case s == "" || s == ".":
		case s == ".." && len(parts) > 0 && parts[len(parts)-1] != "..":
			parts = parts[:len(parts)-1]
		case s == ".." && rooted:
			// Above a root is the root.
		default:
			parts = append(parts, s)
		}
	}
	out := volume
	if rooted {
		out += `\`
	}
	out += strings.Join(parts, `\`)
	if out == "" {
		return "."
	}
	return out
}

// winAbs is a path an operator gave made absolute the Windows way, from wd
// (the login's folder, C:\Users\me): / read as \; "", "." and "~" wd, and
// "~\x" in it; a drive alone its root, as BOB's minion has it (Windows'
// current folder on a drive is not the server's to keep), and a drive's
// path without its \ (C:x) from that root too; one from \ (\Windows) on
// wd's drive; anything else from wd. An SFTP path pasted as it is (/C:/x)
// is the drive's.
func winAbs(wd, p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	switch {
	case p == "" || p == "." || p == "~":
		return winClean(wd)
	case strings.HasPrefix(p, `~\`):
		return winClean(wd + `\` + p[2:])
	case len(p) >= 3 && p[0] == '\\' && isLetter(p[1]) && p[2] == ':' && (len(p) == 3 || p[3] == '\\'):
		p = p[1:]
	}
	if n := winVolumeLen(p); n == 2 {
		if len(p) == 2 || p[2] != '\\' {
			p = p[:2] + `\` + p[2:]
		}
		return winClean(p)
	} else if n > 0 {
		return winClean(p)
	}
	if strings.HasPrefix(p, `\`) {
		return winClean(wd[:winVolumeLen(wd)] + p)
	}
	return winClean(wd + `\` + p)
}

// winDir is a Windows path's parent; a root (C:\, \\server\share\) is its
// own.
func winDir(p string) string {
	p = winClean(p)
	n := winVolumeLen(p)
	i := strings.LastIndex(p[n:], `\`)
	switch {
	case i < 0 && n == 0:
		return "."
	case i < 0:
		return p[:n]
	case i == 0:
		return p[:n+1]
	}
	return p[:n+i]
}

// winJoin is name in the folder dir.
func winJoin(dir, name string) string {
	if name == "" {
		return winClean(dir)
	}
	return winClean(dir + `\` + name)
}

// winBase is a Windows path's last part: what follows its last \ or /, past
// its drive (C:x is x); \ for a root, "." for nothing.
func winBase(p string) string {
	p = p[winVolumeLen(p):]
	for len(p) > 1 && isSep(p[len(p)-1]) {
		p = p[:len(p)-1]
	}
	switch {
	case p == "":
		return "."
	case len(p) == 1 && isSep(p[0]):
		return `\`
	}
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		p = p[i+1:]
	}
	return p
}

// sftpPath is a Windows path as Windows's SFTP server takes it: a drive's
// from / (C:\Users is /C:/Users, C:\ is /C:/), a share's with / for \
// (//server/share/x).
func sftpPath(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if len(p) >= 2 && p[1] == ':' && isLetter(p[0]) {
		return "/" + p
	}
	return p
}

// fromSFTP is a path Windows's SFTP server says as Windows writes it:
// /C:/Users is C:\Users, /C: C:\.
func fromSFTP(p string) string {
	if len(p) >= 3 && p[0] == '/' && isLetter(p[1]) && p[2] == ':' && (len(p) == 3 || p[3] == '/') {
		p = p[1:]
	}
	if len(p) == 2 && p[1] == ':' && isLetter(p[0]) {
		p += `\`
	}
	return winClean(p)
}

// driveSFTP reports whether an SFTP path is a drive's (/C:/Users/me): the
// way Windows's OpenSSH says its folders.
func driveSFTP(p string) bool {
	return len(p) >= 3 && p[0] == '/' && isLetter(p[1]) && p[2] == ':' && (len(p) == 3 || p[3] == '/')
}

// winTarget is a link's target as Windows's SFTP server says it, as Windows
// writes it: a drive's path from its root, any other with \.
func winTarget(t string) string {
	if driveSFTP(t) {
		return fromSFTP(t)
	}
	return strings.ReplaceAll(t, "/", `\`)
}

// winDevice is the file system a Windows path is on, for a walk that stays
// on one: its drive (A: is 1); false for a share's, whose server says
// nothing of it.
func winDevice(p string) (uint64, bool) {
	if winVolumeLen(p) != 2 {
		return 0, false
	}
	c := p[0]
	if 'a' <= c && c <= 'z' {
		c -= 'a' - 'A'
	}
	return uint64(c-'A') + 1, true
}
