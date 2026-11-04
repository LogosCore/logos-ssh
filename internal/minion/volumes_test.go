//go:build unix

package minion

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// Volumes go in parts within the budget, one volume at least each, in
// order; a host with none still sends one part, saying so.
func TestVolumeParts(t *testing.T) {
	var vols []protocol.Volume
	for i := range 40 {
		vols = append(vols, protocol.Volume{Path: "/mnt/disk" + strconv.Itoa(i), Kind: protocol.VolumeFixed, FS: "ext4", Device: "/dev/sdb" + strconv.Itoa(i)})
	}
	parts := volumeParts(vols, "/", 400)
	if len(parts) < 4 {
		t.Fatalf("%d parts", len(parts))
	}
	n := 0
	for i, p := range parts {
		b, err := protocol.WireResultData(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > 400 || len(p.Volumes) == 0 || p.Sep != "/" {
			t.Fatalf("part %d: %d bytes, %d volumes", i, len(b), len(p.Volumes))
		}
		for _, v := range p.Volumes {
			if v.Path != vols[n].Path {
				t.Fatalf("out of order at %d: %s", n, v.Path)
			}
			n++
		}
	}
	if n != len(vols) {
		t.Fatalf("%d of %d volumes", n, len(vols))
	}
	if one := volumeParts(vols[:1], "/", 10); len(one) != 1 || len(one[0].Volumes) != 1 {
		t.Fatalf("a volume over the budget: %+v", one)
	}
	if none := volumeParts(nil, "/", 400); len(none) != 1 || none[0].Volumes != nil {
		t.Fatalf("none: %+v", none)
	}
}

// The command: the host's volumes as the task's data, as core reads it
// (named, checked), its parts within a small connection's messages.
func TestVolumesTask(t *testing.T) {
	r := newTestRunner(CmdVolumes)
	r.SetLimit(protocol.MinConnectionMessage)
	r.start(protocol.TaskItem{T: protocol.ItemTask, Task: make([]byte, 16), Cmd: uint64(CmdVolumes)})
	waitEnd(t, r, 10*time.Second)
	parts := drain(r)
	last := parts[len(parts)-1]
	if !last.Done || !*last.OK {
		t.Fatalf("the task: %+v", last)
	}
	var vols []protocol.Volume
	for _, p := range parts {
		if len(p.Data) == 0 {
			continue
		}
		v, err := protocol.ReadVolumes(p.Seq, asCore(t, protocol.ResultVolumes, p.Data))
		if err != nil {
			t.Fatal(err)
		}
		vols = append(vols, v.Volumes...)
	}
	if len(vols) == 0 {
		t.Fatal("no volumes: the host has one at least, where the minion runs")
	}
	// The minion's own folder is on one of them.
	wd, _ := filepath.Abs(".")
	for _, v := range vols {
		if rel, err := filepath.Rel(v.Path, wd); err == nil && filepath.IsLocal(rel) {
			return
		}
	}
	t.Fatalf("no volume holds %s: %+v", wd, vols)
}
