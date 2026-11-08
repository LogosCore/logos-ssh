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
	// CmdBecome elevates the session: shell commands from then on run as
	// another user (become.go).
	CmdBecome
	// CmdUnbecome: shell commands run as the login again.
	CmdUnbecome
	// CmdTunnel is a tunnel core puts its fronts in front of (SOCKS, an
	// HTTP proxy, a port forward, a terminal, a VPN): streams through the
	// session's SSH connection, until cancelled (tunnel.go).
	CmdTunnel
	// CmdReverseTunnel listens on the server (a remote forward) and opens
	// a stream to core for each connection that comes.
	CmdReverseTunnel
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

	ArgTunnelTimeout    = 2
	ArgTunnelMaxStreams = 3

	ArgReverseBind       = 1
	ArgReverseListen     = 2
	ArgReverseTimeout    = 3
	ArgReverseMaxStreams = 4
	ArgReverseUDP        = 5

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
// within its timeout (30 seconds unless the task says). One that ran as
// another than core took it to (a become before it ended after its ack)
// says who, before its end.
func (r *Runner) shell(ctx context.Context, t *Task, args protocol.Args) {
	end := runShell(ctx, r.host, args, 0, taskWriter{r: r, t: t}, t.started)
	if end.notAs {
		if msg, first := becomeFailure(r.host); first {
			r.feedback.Report(protocol.FeedbackError, "become_failed", t.id, "%s", msg)
		}
	}
	if end.ran && !ranAsSaid(end.as, t.said) {
		r.identity(ranIdentity(t.id, end.as))
	}
	r.End(t, end.ok, end.exit, end.err)
}

// defaultShellTimeout is how long a shell command runs unless its task
// says.
const defaultShellTimeout = 30 * time.Second

// shellEnd is how a shell task ended.
type shellEnd struct {
	// ok: it ran to its end; exit, its exit code; err, why it failed (or
	// what killed it).
	ok   bool
	exit *int64
	err  string
	// notAs: it could not run as the acting user (a become that no longer
	// elevates on this connection), so it did not run.
	notAs bool
	// ran: the command started, as as says (nil: the login).
	ran bool
	as  *Ran
}

// StartedShell is a host whose shell says when a command has what it runs
// in (sshhost: the login's channel, or the shell a become elevated, held):
// a become after that changes nothing for it.
type StartedShell interface {
	// ShellStarted is Shell, calling started once the command has it.
	ShellStarted(ctx context.Context, command string, out io.Writer, started func()) (Exit, error)
}

// runShell runs a shell task's command on host, its output written to out,
// within its timeout (most: at most this long, when not 0); started, when
// not nil, once it has what it runs in.
func runShell(ctx context.Context, host Host, args protocol.Args, most time.Duration, out io.Writer, started func()) shellEnd {
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
	var exit Exit
	var err error
	if h, ok := host.(StartedShell); ok && started != nil {
		exit, err = h.ShellStarted(ctx, command, out, started)
	} else {
		if started != nil {
			started()
		}
		exit, err = host.Shell(ctx, command, out)
	}
	end := shellEnd{ran: true, as: exit.As}
	switch {
	case errors.Is(err, ErrBecome):
		// Not run: never as the login instead.
		return shellEnd{err: err.Error(), notAs: true}
	case errors.Is(err, ErrNotStarted):
		return shellEnd{err: err.Error()}
	case errors.Is(ctx.Err(), context.DeadlineExceeded) && cut:
		end.err = fmt.Sprintf("stopped at the call's deadline, after %s: a command meant to run longer needs a bind-persistent connection",
			timeout.Round(time.Second))
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		end.err = fmt.Sprintf("stopped after its timeout, %s", timeout)
	case errors.Is(ctx.Err(), context.Canceled):
		end.err = "cancelled"
	case err != nil:
		end.err = err.Error()
	case exit.Signal != "":
		// Killed by a signal: no exit code, said in err.
		end.ok, end.err = true, "killed by "+exit.Signal
	default:
		end.ok, end.exit = true, exit.Code
	}
	return end
}

// becomeFailure is why the host's shell commands cannot run as the acting
// user, and whether it is the first time asked (for the operators, once).
func becomeFailure(h Host) (string, bool) {
	b, ok := h.(Becomer)
	if !ok {
		return "", false
	}
	why, first := b.BecomeFailure()
	if why == "" {
		return "", false
	}
	return fmt.Sprintf("Shell commands cannot run as the user the session became, on this connection: %s. Their tasks fail rather than run as %s: run become again, or unbecome.",
		why, b.Login()), first
}

// become elevates the session (a become task): its identity is said for
// the session, naming the task, before the task's end.
func (r *Runner) become(ctx context.Context, t *Task, args protocol.Args) {
	text, id, errText := doBecome(ctx, r.host, t.id, args)
	if errText != "" {
		r.End(t, false, nil, errText)
		return
	}
	r.identity(id)
	r.Write(t, []byte(text), nil)
	r.End(t, true, nil, "")
}

// unbecome takes the session back to the login (an unbecome task).
func (r *Runner) unbecome(t *Task) {
	text, id, errText := doUnbecome(r.host, t.id)
	if errText != "" {
		r.End(t, false, nil, errText)
		return
	}
	r.identity(id)
	r.Write(t, []byte(text), nil)
	r.End(t, true, nil, "")
}

// doBecome elevates host as a become task's args say: what the task
// answers, the session's identity now, or why it failed.
func doBecome(ctx context.Context, h Host, task []byte, args protocol.Args) (string, protocol.IdentityItem, string) {
	b, ok := h.(Becomer)
	if !ok {
		return "", protocol.IdentityItem{}, "become: this host's shell cannot run as another user"
	}
	want, err := BecomeArgs(task, args)
	if err != nil {
		return "", protocol.IdentityItem{}, err.Error()
	}
	got, err := b.Become(ctx, want)
	if err != nil {
		return "", protocol.IdentityItem{}, err.Error()
	}
	return becameText(want, got, b.Login()), becameIdentity(want, got), ""
}

// doUnbecome takes host back to its login: what the task answers, and the
// session's identity now (the process's own).
func doUnbecome(h Host, task []byte) (string, protocol.IdentityItem, string) {
	b, ok := h.(Becomer)
	if !ok {
		return "", protocol.IdentityItem{}, "unbecome: this host's shell cannot run as another user"
	}
	was := b.Acting()
	b.Unbecome()
	text := fmt.Sprintf("Shell commands run as %s again.\n", b.Login())
	if was == nil {
		text = fmt.Sprintf("The session had not become anyone: shell commands run as %s.\n", b.Login())
	}
	return text, ownIdentity(protocol.IdentitySession, task), ""
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
