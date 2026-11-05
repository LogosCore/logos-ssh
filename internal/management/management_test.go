package management

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/logoscore/logos-golang-module-core/pkg/mgmt"
	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-ssh/internal/agent"
	"github.com/logoscore/logos-ssh/internal/config"
)

func TestManifest(t *testing.T) {
	if _, err := mgmt.New(Manifest(config.Config{CallTimeout: 2 * time.Minute})); err != nil {
		t.Fatal(err)
	}
}

// The call timeout starts as the env says and changes live; a value that
// does not read is refused, the one in force kept.
func TestCallTimeoutLive(t *testing.T) {
	cfg := config.Config{ChannelID: "ssh-test", CallTimeout: 90 * time.Second}
	a := agent.New("http://core.invalid", cfg.ChannelID, 1)
	a.SetCallTimeout(cfg.CallTimeout)
	var level slog.LevelVar
	s, err := New(cfg, a, &level)
	if err != nil {
		t.Fatal(err)
	}
	if r := s.ApplyConfig(context.Background(), protocol.ManagementConfig{Revision: 1, Values: map[string]any{}}); len(r.Rejected) > 0 || a.CallTimeout() != 90*time.Second {
		t.Fatalf("the default: %+v, %s", r, a.CallTimeout())
	}
	if r := s.ApplyConfig(context.Background(), protocol.ManagementConfig{Revision: 2, Values: map[string]any{"call_timeout": "45s"}}); len(r.Rejected) > 0 || a.CallTimeout() != 45*time.Second {
		t.Fatalf("applied: %+v, %s", r, a.CallTimeout())
	}
	if r := s.ApplyConfig(context.Background(), protocol.ManagementConfig{Revision: 3, Values: map[string]any{"call_timeout": "an hour"}}); len(r.Rejected) == 0 || a.CallTimeout() != 45*time.Second {
		t.Fatalf("a bad value: %+v, %s", r, a.CallTimeout())
	}
}
