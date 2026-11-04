package minion

import (
	"fmt"
	"io/fs"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// rm removes a file, a link (itself, never what it points to) or a folder
// (docs: contracts/task-results-and-actions, delete_path): a folder with
// what is in it only when recursive says so; never a file system's root.
// The output says what went.
func (r *Runner) rm(t *Task, args protocol.Args) {
	out, errText := removePath(r.host, args)
	if errText != "" {
		r.End(t, false, nil, errText)
		return
	}
	r.Write(t, []byte(out), nil)
	r.End(t, true, nil, "")
}

// removePath carries out rm on host: what went (its output), or why
// nothing did.
func removePath(host Host, args protocol.Args) (out, errText string) {
	path, _ := protocol.ArgString(args, ArgRmPath)
	recursive, _ := args[ArgRmRecursive].(bool)
	if path == "" {
		return "", "no path"
	}
	abs, err := host.Abs(path)
	if err != nil {
		return "", err.Error()
	}
	if host.Dir(abs) == abs {
		return "", abs + " is a filesystem's root: not removed"
	}
	info, err := host.Lstat(abs)
	if err != nil {
		return "", err.Error()
	}
	kind := "file"
	switch {
	case info.Mode&fs.ModeSymlink != 0:
		kind = "link"
	case info.IsDir():
		kind = "folder"
		if !recursive {
			if entries, err := host.ReadDir(abs); err == nil && len(entries) > 0 {
				return "", fmt.Sprintf("%s is not empty (%d entries): remove it with recursive", abs, len(entries))
			}
		}
	case !info.Mode.IsRegular():
		kind = "other"
	}
	if info.IsDir() && recursive {
		err = host.RemoveAll(abs)
	} else {
		err = host.Remove(abs)
	}
	if err != nil {
		return "", err.Error()
	}
	return fmt.Sprintf("removed %s (%s)\n", abs, kind), ""
}
