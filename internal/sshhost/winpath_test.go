package sshhost

import "testing"

// Windows paths read as BOB's minion reads them on Windows: / as \, a drive
// alone its root, \ from the login's drive, the drive letter upper case;
// SFTP's /C:/ form there and back.
func TestWinPaths(t *testing.T) {
	const wd = `C:\Users\me`
	for _, c := range []struct{ in, want string }{
		{"", wd}, {".", wd}, {"~", wd}, {"~/Desktop", `C:\Users\me\Desktop`}, {`~\Desktop\..\x`, `C:\Users\me\x`},
		{"Desktop", `C:\Users\me\Desktop`}, {`..\..`, `C:\`}, {`..\..\..\..`, `C:\`},
		{"c:", `C:\`}, {"d:x", `D:\x`}, {"c:/windows/../users", `C:\users`}, {`C:\Windows\\System32\.`, `C:\Windows\System32`},
		{"/", `C:\`}, {`\Windows`, `C:\Windows`}, {"/C:/Users", `C:\Users`}, {"/c:", `C:\`},
		{`\\srv\share`, `\\srv\share\`}, {`\\srv\share\x\..\y`, `\\srv\share\y`}, {`//srv/share/x`, `\\srv\share\x`},
	} {
		if got := winAbs(wd, c.in); got != c.want {
			t.Errorf("winAbs(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	for _, c := range []struct{ in, dir, base string }{
		{`C:\Users\me`, `C:\Users`, "me"}, {`C:\Users`, `C:\`, "Users"}, {`C:\`, `C:\`, `\`},
		{`\\srv\share\x`, `\\srv\share\`, "x"}, {`\\srv\share\`, `\\srv\share\`, `\`},
	} {
		if got := winDir(c.in); got != c.dir {
			t.Errorf("winDir(%q) = %q, want %q", c.in, got, c.dir)
		}
		if got := winBase(c.in); got != c.base {
			t.Errorf("winBase(%q) = %q, want %q", c.in, got, c.base)
		}
	}
	for _, c := range []struct{ in, want string }{{"report.pdf", "report.pdf"}, {`..\..\evil.txt`, "evil.txt"}, {"a/b", "b"}, {"C:evil", "evil"}, {"", "."}} {
		if got := winBase(c.in); got != c.want {
			t.Errorf("winBase(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := winJoin(`C:\`, "Users"); got != `C:\Users` {
		t.Errorf("winJoin = %q", got)
	}
	for _, c := range []struct{ win, sftp string }{{`C:\Users\me`, "/C:/Users/me"}, {`C:\`, "/C:/"}, {`\\srv\share\x`, "//srv/share/x"}} {
		if got := sftpPath(c.win); got != c.sftp {
			t.Errorf("sftpPath(%q) = %q, want %q", c.win, got, c.sftp)
		}
	}
	for _, c := range []struct{ sftp, win string }{{"/C:/Users/me", `C:\Users\me`}, {"/C:", `C:\`}, {"/C:/", `C:\`}, {"/d:/x/", `D:\x`}} {
		if got := fromSFTP(c.sftp); got != c.win {
			t.Errorf("fromSFTP(%q) = %q, want %q", c.sftp, got, c.win)
		}
	}
	if !driveSFTP("/C:/Users") || !driveSFTP("/C:") || driveSFTP("/home/me") || driveSFTP("/Cx/") {
		t.Error("driveSFTP")
	}
	if got := winTarget("/C:/ProgramData"); got != `C:\ProgramData` {
		t.Errorf("winTarget = %q", got)
	}
	if got := winTarget("../x"); got != `..\x` {
		t.Errorf("winTarget relative = %q", got)
	}
	if d, ok := winDevice(`c:\x`); !ok || d != 3 {
		t.Errorf("winDevice = %d %v", d, ok)
	}
	if _, ok := winDevice(`\\srv\share\x`); ok {
		t.Error("a share's device")
	}
}
