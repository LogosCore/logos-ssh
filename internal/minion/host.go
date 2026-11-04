package minion

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// Host is what the minion's commands act on: a server reached over SSH and
// SFTP (docs: contracts/agentless-channels/), or in tests the test's own
// machine. Paths are the host's own: absolute, with its separators, as Abs
// makes them.
//
// Errors that say a path is missing or may not be read wrap
// fs.ErrNotExist and fs.ErrPermission, as the os package's do: a listing
// tells a folder it may not read from one that is not there by them.
type Host interface {
	// Abs is a path an operator gave, made absolute and clean the host's
	// way (a Windows host reads "C:" as its root, say).
	Abs(path string) (string, error)
	// Sep is the host's path separator: "/" or `\`.
	Sep() string
	// Dir is a path's parent; a root is its own (Dir("/") is "/").
	Dir(path string) string
	// Join is name in the folder dir.
	Join(dir, name string) string
	// Base is a path's last element.
	Base(path string) string

	// ReadDir lists a folder: its entries as a listing sends them (a link
	// as the link, with its target). Entries read before an error come with
	// the error.
	ReadDir(path string) ([]Entry, error)
	// Stat is a path's file, links followed; Lstat the path itself.
	Stat(path string) (Info, error)
	Lstat(path string) (Info, error)
	// Open opens a file to read.
	Open(path string) (ReadFile, error)
	// CreateTemp creates a new file in dir, its name pattern's with the
	// last "*" replaced by something random, to write.
	CreateTemp(dir, pattern string) (WriteFile, error)
	// WriteAt writes data into the file at path from off, creating the file
	// first, or emptying the one there, when create says.
	WriteAt(path string, off int64, data []byte, create bool) error
	Chmod(path string, mode fs.FileMode) error
	// Rename moves a file to to, replacing a file there.
	Rename(from, to string) error
	// Remove removes a file, a link or an empty folder; RemoveAll a folder
	// with what is in it.
	Remove(path string) error
	RemoveAll(path string) error

	// Shell runs a command line in the host's shell, its output (stdout and
	// stderr) written to out as it comes, until it ends or ctx is done:
	// then it stops the command and all the command started. It returns how
	// the command ended; an error wrapping ErrNotStarted when it could not
	// start, another when it could not run to its end.
	Shell(ctx context.Context, command string, out io.Writer) (Exit, error)
	// Volumes are the host's volumes: its drives, the file systems it has
	// mounted.
	Volumes() ([]protocol.Volume, error)
}

// Entry is a folder's entry as a host reads it: as a listing sends it, with
// its owner and group by name, which each piece numbers once.
type Entry struct {
	protocol.LsEntry
	// OwnerName and GroupName are the entry's owner and group, by name;
	// empty where the host keeps none.
	OwnerName, GroupName string
	// Dev is the file system the entry is on, when HasDev: a walk that stays
	// on one file system enters no folder of another.
	Dev    uint64
	HasDev bool
}

// Info is what a host says of a file.
type Info struct {
	// Mode is the file's type and permission bits, as the os package has
	// them (fs.ModeDir, fs.ModeSymlink, ...).
	Mode fs.FileMode
	Size int64
	// Dev is the file system the file is on, when HasDev.
	Dev    uint64
	HasDev bool
}

// IsDir reports whether the file is a folder.
func (i Info) IsDir() bool { return i.Mode.IsDir() }

// ReadFile is a file open to read.
type ReadFile interface {
	io.ReaderAt
	io.Closer
	// Stat is the open file's.
	Stat() (Info, error)
}

// WriteFile is a file open to write.
type WriteFile interface {
	io.Writer
	io.Closer
	// Sync commits what was written to the host's storage.
	Sync() error
	// Name is the file's path.
	Name() string
}

// Exit is how a command ended: its exit code, or the signal that killed it.
type Exit struct {
	// Code is its exit code; nil when a signal killed it.
	Code *int64
	// Signal names the signal that killed it ("killed"); empty when it
	// exited.
	Signal string
}

// ErrNotStarted is what a host's Shell error wraps when the command could
// not start: NotStarted makes one.
var ErrNotStarted = errors.New("could not start")

// NotStarted is err as a command that could not start: "could not start:
// <err>".
func NotStarted(err error) error {
	return fmt.Errorf("%w: %w", ErrNotStarted, err)
}
