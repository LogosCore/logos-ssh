package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/logoscore/logos-golang-module-core/pkg/mgmt"
	"github.com/logoscore/logos-golang-protocol/protocol"
)

// The SSH factory's own management: its log level. factory-core adds the builds
// section (max_concurrent_builds, drain/resume, build counters) next to it.

// logLevels maps the log_level values onto slog levels, most verbose first.
var logLevels = []struct {
	value, label, description string
	level                     slog.Level
}{
	{"debug", "Debug", "Builds refused while busy or draining, plus everything below.", slog.LevelDebug},
	{"info", "Info", "Builds accepted, finished and reported, and management changes, plus everything below.", slog.LevelInfo},
	{"warn", "Warn", "Build requests that do not fit the schema and results core could not be sent, plus errors.", slog.LevelWarn},
	{"error", "Error", "Errors only.", slog.LevelError},
}

func slogLevel(v any) slog.Level {
	for _, l := range logLevels {
		if l.value == v {
			return l.level
		}
	}
	return slog.LevelInfo
}

// manifest is the SSH factory's own management manifest. Its property comes after
// the builds section's max_concurrent_builds (order 1).
func manifest() protocol.ManagementManifest {
	levels := make([]protocol.EnumOption, len(logLevels))
	for i, l := range logLevels {
		levels[i] = protocol.EnumOption{Value: l.value, Label: l.label, Description: l.description}
	}
	return protocol.ManagementManifest{
		SchemaVersion: protocol.ManagementSchemaV1,
		Properties: []protocol.PropertySpec{
			{FieldSpec: protocol.FieldSpec{
				Key: "log_level", Type: protocol.FieldEnum, Label: "Log level",
				Description: "Level of the factory's own output (stderr). The Logs tab has its own level.",
				Group:       "Logging", Order: 2, Default: "info", Options: levels,
			}, Apply: protocol.ApplyLive},
		},
	}
}

// newManagement is the SSH factory's own management server: log_level drives level.
func newManagement(level *slog.LevelVar) (*mgmt.Server, error) {
	s, err := mgmt.New(manifest())
	if err != nil {
		return nil, err
	}
	s.OnApply(func(ctx context.Context, live map[string]any) error {
		lvl := slogLevel(live["log_level"])
		if level.Level() == lvl {
			return nil
		}
		level.Set(lvl)
		slog.Info("management: config applied", "by", actorName(mgmt.ActorFromContext(ctx)), "log_level", lvl.String())
		return nil
	})
	return s, nil
}

func actorName(a *protocol.Actor) string {
	switch {
	case a == nil:
		return "core"
	case a.Name != "":
		return fmt.Sprintf("%s %s (%s)", a.Type, a.Name, a.ID)
	default:
		return a.Type + " " + a.ID
	}
}
