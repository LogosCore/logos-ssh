package minion

import (
	"context"
	"errors"
	"io/fs"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// walkBacklog is how many listing pieces a walk lets wait to be sent before
// it reads on: it goes as fast as the channel takes them, and no faster.
const walkBacklog = 16

// walkReport is how often a walk says where it stands (its data).
const walkReport = 2 * time.Second

// walk lists a folder and the folders under it, breadth first (the top
// levels first), each a listing as it is read (docs:
// contracts/minion-messages/tasks-and-results, Listings), and says where it
// stands as a dir_walk: the folders and entries so far, those not read,
// those not entered (deeper than depth, past max_folders, another file
// system, hidden when not wanted). Links are not followed. A depth or
// max_folders of 0 is no limit.
func (r *Runner) walk(ctx context.Context, t *Task, args protocol.Args) {
	path, _ := protocol.ArgString(args, ArgWalkPath)
	if path == "" {
		path = "."
	}
	depth, _ := protocol.ArgInt(args, ArgWalkDepth)
	// 0, or none: no limit.
	most, _ := protocol.ArgInt(args, ArgWalkMaxFolders)
	hidden := argBool(args, ArgWalkHidden, true)
	oneFS := argBool(args, ArgWalkOneFS, true)

	root, err := r.host.Abs(path)
	if err != nil {
		r.End(t, false, nil, err.Error())
		return
	}
	info, err := r.host.Stat(root)
	if err != nil {
		r.End(t, false, nil, err.Error())
		return
	}
	if !info.IsDir() {
		r.End(t, false, nil, root+" is not a directory")
		return
	}
	sep := r.host.Sep()

	type folder struct {
		path  string
		level int64
	}
	queue := []folder{{root, 0}}
	w := protocol.DirWalk{Root: root}
	reported := time.Now()
	for len(queue) > 0 {
		if !r.waitBacklog(ctx, t) {
			w.Current = ""
			r.Write(t, nil, w)
			r.End(t, false, nil, "cancelled")
			return
		}
		if most > 0 && int64(w.Folders+w.Unread) >= most { //nolint:gosec // counts of folders
			w.Skipped += uint64(len(queue))
			break
		}
		f := queue[0]
		queue = queue[1:]
		w.Current = f.path
		entries, err := r.host.ReadDir(f.path)
		if err != nil && len(entries) == 0 {
			// Gone since its folder was read is no listing; one it may
			// not read says so.
			w.Unread++
			if errors.Is(err, fs.ErrPermission) {
				r.list(t, f.path, sep, r.parent(f.path), nil, false, protocol.ListingErrDenied)
			}
			continue
		}
		for _, e := range entries {
			// A link to a folder is a link: not followed.
			if e.Type != protocol.EntryDir {
				continue
			}
			switch {
			case !hidden && e.Hidden,
				depth > 0 && f.level+1 > depth:
				w.Skipped++
				continue
			}
			if oneFS && info.HasDev && e.HasDev && e.Dev != info.Dev {
				w.Skipped++
				continue
			}
			queue = append(queue, folder{r.host.Join(f.path, e.Name), f.level + 1})
		}
		r.list(t, f.path, sep, r.parent(f.path), entries, err != nil, 0)
		w.Folders++
		w.Entries += uint64(len(entries))
		if time.Since(reported) >= walkReport {
			r.Write(t, nil, w)
			reported = time.Now()
		}
	}
	w.Current = ""
	r.Write(t, nil, w)
	r.End(t, true, nil, "")
}

// waitBacklog waits while the task has walkBacklog pieces or more waiting
// to be sent; false when the task is cancelled.
func (r *Runner) waitBacklog(ctx context.Context, t *Task) bool {
	for {
		if ctx.Err() != nil {
			return false
		}
		r.mu.Lock()
		waiting := len(t.pieces)
		r.mu.Unlock()
		if waiting < walkBacklog {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(50 * time.Millisecond):
		}
	}
}
