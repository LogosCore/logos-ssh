// Package ops numbers the SSH minion's commands: the factory's build schema
// declares them by these numbers (op), and the channel's minion carries
// them out by them. Their params' numbers are the minion's (minion.Arg…).
package ops

import "github.com/logoscore/logos-ssh/internal/minion"

// The commands' numbers.
const (
	Shell          = 1
	Ls             = 2
	Walk           = 3
	Download       = 4
	StreamDownload = 5
	Upload         = 6
	StreamUpload   = 7
	Rm             = 8
	Volumes        = 9
)

// Commands are the minion's commands by number: the factory builds them
// all, and the minion carries out each.
var Commands = map[uint64]minion.Command{
	Shell: minion.CmdShell, Ls: minion.CmdLs, Walk: minion.CmdWalk, Download: minion.CmdDownload,
	StreamDownload: minion.CmdStreamDownload, Upload: minion.CmdUpload, StreamUpload: minion.CmdStreamUpload,
	Rm: minion.CmdRm, Volumes: minion.CmdVolumes,
}

// Numbers are the commands' numbers, in order.
func Numbers() []uint64 {
	return []uint64{Shell, Ls, Walk, Download, StreamDownload, Upload, StreamUpload, Rm, Volumes}
}

// MaxTasks is how many tasks the minion runs at once: a call brings this
// many at most, and a persistent connection's allowance is this.
const MaxTasks = 4
