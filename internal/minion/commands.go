package minion

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// Command is a command the minion carries out on its host. The SSH
// factory's build schema numbers them (op), and their params as below
// (num); Config.Ops and Caller.Ops map the numbers to them.
type Command int

// The runner's commands, with the actions and results core knows them by
// (docs: contracts/task-results-and-actions/).
const (
	// CmdLs lists a folder: action list_dir, result dir_listing.
	CmdLs Command = iota + 1
	// CmdWalk lists a folder and the folders under it: action walk_dir,
	// result dir_walk.
	CmdWalk
	// CmdDownload sends a file to core: action download_file, result
	// file_download.
	CmdDownload
	// CmdStreamDownload streams a file to core as its downloader takes it:
	// action stream_file, result file_stream.
	CmdStreamDownload
	// CmdUpload puts a file core sends on the host: action upload_file,
	// result file_upload.
	CmdUpload
	// CmdStreamUpload puts a file core streams on the host: action
	// upload_stream, result file_upload.
	CmdStreamUpload
	// CmdRm removes a path: action delete_path.
	CmdRm
	// CmdShell runs a command line in the host's shell.
	CmdShell
	// CmdVolumes lists the host's volumes: action list_volumes, result
	// volumes.
	CmdVolumes
)

// The commands' params, by number (num).
const (
	ArgLsPath = 1

	ArgDownloadPath       = 1
	ArgStreamDownloadPath = 1

	ArgUploadFile      = 1
	ArgUploadPath      = 2
	ArgUploadOverwrite = 3

	ArgStreamUploadStream    = 1
	ArgStreamUploadPath      = 2
	ArgStreamUploadOverwrite = 3

	ArgRmPath      = 1
	ArgRmRecursive = 2

	ArgWalkPath       = 1
	ArgWalkDepth      = 2
	ArgWalkMaxFolders = 3
	ArgWalkHidden     = 4
	ArgWalkOneFS      = 5

	ArgShellCommand = 1
	ArgShellTimeout = 2
)

// ls lists a folder: a listing (docs: contracts/minion-messages/tasks-and-results,
// Listings), from which core makes the task's dir_listing. A folder it
// cannot read is a listing that says so, and the task fails.
func (r *Runner) ls(t *Task, args protocol.Args) {
	path, _ := protocol.ArgString(args, ArgLsPath)
	if path == "" {
		path = "."
	}
	abs, err := r.host.Abs(path)
	if err != nil {
		r.End(t, false, nil, err.Error())
		return
	}
	entries, err := r.host.ReadDir(abs)
	if err != nil && len(entries) == 0 {
		// Not a folder at all is no listing: only one it may not read.
		if errors.Is(err, fs.ErrPermission) {
			r.list(t, abs, r.host.Sep(), r.parent(abs), nil, false, protocol.ListingErrDenied)
		}
		r.End(t, false, nil, err.Error())
		return
	}
	// Entries read before an error: what there is, said partial.
	r.list(t, abs, r.host.Sep(), r.parent(abs), entries, err != nil, 0)
	r.End(t, true, nil, "")
}

// parent is a folder's parent, as a listing says it: "" for a root.
func (r *Runner) parent(abs string) string {
	parent := r.host.Dir(abs)
	if parent == abs {
		return ""
	}
	return parent
}

// taskWriter feeds a running command's output to its task as it comes.
type taskWriter struct {
	r *Runner
	t *Task
}

func (w taskWriter) Write(p []byte) (int, error) {
	w.r.Write(w.t, append([]byte(nil), p...), nil)
	return len(p), nil
}

// shell runs a command line in the host's shell, its output streamed,
// within its timeout (30 seconds unless the task says).
func (r *Runner) shell(ctx context.Context, t *Task, args protocol.Args) {
	ok, exit, errText := runShell(ctx, r.host, args, 0, taskWriter{r: r, t: t})
	r.End(t, ok, exit, errText)
}

// defaultShellTimeout is how long a shell command runs unless its task
// says.
const defaultShellTimeout = 30 * time.Second

// runShell runs a shell task's command on host, its output written to out,
// within its timeout (most: at most this long, when not 0): whether it ran
// to its end, its exit code, and why it failed (or what killed it).
func runShell(ctx context.Context, host Host, args protocol.Args, most time.Duration, out io.Writer) (bool, *int64, string) {
	command, _ := protocol.ArgString(args, ArgShellCommand)
	timeout, ok := protocol.ArgDuration(args, ArgShellTimeout)
	if !ok || timeout <= 0 {
		timeout = defaultShellTimeout
	}
	// A call's deadline, when it comes first, stops the command there.
	cut := most > 0 && timeout > most
	if cut {
		timeout = most
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	exit, err := host.Shell(ctx, command, out)
	switch {
	case errors.Is(err, ErrNotStarted):
		return false, nil, err.Error()
	case errors.Is(ctx.Err(), context.DeadlineExceeded) && cut:
		return false, nil, fmt.Sprintf("stopped at the call's deadline, after %s: a command meant to run longer needs a bind-persistent connection",
			timeout.Round(time.Second))
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return false, nil, fmt.Sprintf("stopped after its timeout, %s", timeout)
	case errors.Is(ctx.Err(), context.Canceled):
		return false, nil, "cancelled"
	case err != nil:
		return false, nil, err.Error()
	case exit.Signal != "":
		// Killed by a signal: no exit code, said in err.
		return true, nil, "killed by " + exit.Signal
	}
	return true, exit.Code, ""
}

// volumes lists the host's volumes (docs: contracts/task-results-and-actions,
// volumes). They go as the task's data in parts that keep within the
// connection's message size, as a listing's pieces do; core joins them,
// and makes each a folder of the machine's file browser (a drive one of
// its roots).
func (r *Runner) volumes(t *Task) {
	vols, err := r.host.Volumes()
	if err != nil {
		r.End(t, false, nil, err.Error())
		return
	}
	r.mu.Lock()
	budget := r.perMessageLocked() / 2
	r.mu.Unlock()
	for _, part := range volumeParts(vols, r.host.Sep(), budget) {
		r.Write(t, nil, part)
	}
	r.End(t, true, nil, "")
}

// volumeParts are the volumes in parts of at most budget bytes each (one
// volume at least, so a part always moves on); one part, with none, when
// the host has none.
func volumeParts(vols []protocol.Volume, sep string, budget int) []protocol.Volumes {
	parts := []protocol.Volumes{{Sep: sep}}
	used := 16
	for _, v := range vols {
		size := 64
		if b, err := protocol.WireResultData(protocol.Volumes{Sep: sep, Volumes: []protocol.Volume{v}}); err == nil {
			size = len(b)
		}
		last := &parts[len(parts)-1]
		if len(last.Volumes) > 0 && used+size > budget {
			parts = append(parts, protocol.Volumes{Sep: sep})
			last, used = &parts[len(parts)-1], 16
		}
		last.Volumes = append(last.Volumes, v)
		used += size
	}
	return parts
}

// argBool is a bool arg, or def when the task has none.
func argBool(args protocol.Args, key uint64, def bool) bool {
	if v, ok := args[key].(bool); ok {
		return v
	}
	return def
}
