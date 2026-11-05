// Package management declares what core may manage on the SSH channel (its
// call timeout and log level; drain, resume, and closing its connections
// and the logins calls keep) and what it shows (the control link, calls,
// connections), bound to the agent. How the channel reaches core stays
// env-only.
package management

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/logoscore/logos-golang-module-core/pkg/mgmt"
	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-ssh/internal/agent"
	"github.com/logoscore/logos-ssh/internal/config"
)

var logLevels = []struct {
	value, label, description string
	level                     slog.Level
}{
	{"debug", "Debug", "Every call, and what the minion does with each task, plus everything below.", slog.LevelDebug},
	{"info", "Info", "Failed calls, opens and closed connections, startup and config changes.", slog.LevelInfo},
	{"warn", "Warn", "The control link going down only.", slog.LevelWarn},
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

// Manifest is the management manifest.
// Manifest is the channel's manifest, its call timeout's default cfg's.
func Manifest(cfg config.Config) protocol.ManagementManifest {
	levels := make([]protocol.EnumOption, len(logLevels))
	for i, l := range logLevels {
		levels[i] = protocol.EnumOption{Value: l.value, Label: l.label, Description: l.description}
	}
	return protocol.ManagementManifest{
		SchemaVersion: protocol.ManagementSchemaV1,
		Properties: []protocol.PropertySpec{
			{FieldSpec: protocol.FieldSpec{
				Key: "call_timeout", Type: protocol.FieldDuration, Label: "Call timeout",
				Description: "How long a call may take: its login and its tasks, a shell command stopped when it runs out. " +
					"Core's deadline (2 minutes) applies when shorter. A command meant to run longer needs a bind-persistent connection.",
				Group: "Calls", Order: 1, Default: cfg.CallTimeout.String(), Min: "1s", Max: "10m",
			}, Apply: protocol.ApplyLive},
			{FieldSpec: protocol.FieldSpec{
				Key: "log_level", Type: protocol.FieldEnum, Label: "Log level",
				Description: "Level of the channel's own output (stderr). The Logs tab has its own level.",
				Group:       "Logging", Order: 1, Default: "info", Options: levels,
			}, Apply: protocol.ApplyLive},
		},
		Actions: []protocol.ActionSpec{
			{
				Name: "drain", Label: "Drain", Risk: protocol.RiskHigh,
				Description: "Take no more calls or opens: each fails until resumed. Connections open stay.",
				Confirm:     "Calls and opens through this channel fail until it is resumed.",
				AvailableWhen: []protocol.ActionCondition{
					{Status: "draining", Op: protocol.OpEq, Value: false, Message: "Already draining"},
				},
			},
			{
				Name: "resume", Label: "Resume", Risk: protocol.RiskLow, Description: "Take calls and opens again after a drain.",
				AvailableWhen: []protocol.ActionCondition{
					{Status: "draining", Op: protocol.OpEq, Value: true, Message: "Not draining"},
				},
			},
			{
				Name: "close_connections", Label: "Close connections", Risk: protocol.RiskHigh,
				Description: "Close every persistent connection and every login a call kept: core sees each session not connected, and opens again as each target's policy says.",
				Confirm:     "Every SSH connection through this channel closes.",
			},
		},
		Status: []protocol.StatusSpec{
			{Key: "link_up", Type: protocol.FieldBool, Label: "Control link",
				Description: "Whether the control link to core is open: core calls and opens through it."},
			{Key: "connections_open", Type: protocol.FieldInt, Label: "Connections open", Description: "Persistent connections (bind-persistent)."},
			{Key: "logins_kept", Type: protocol.FieldInt, Label: "Logins kept", Description: "SSH connections calls keep for the next call."},
			{Key: "calls_total", Type: protocol.FieldInt, Label: "Calls"},
			{Key: "calls_failed_total", Type: protocol.FieldInt, Label: "Calls failed",
				Description: "Nothing answered, not an SSH server, a host key not the one given, or a login refused."},
			{Key: "opens_total", Type: protocol.FieldInt, Label: "Opens"},
			{Key: "opens_failed_total", Type: protocol.FieldInt, Label: "Opens failed"},
			{Key: "draining", Type: protocol.FieldBool, Label: "Draining", Alert: true},
		},
	}
}

// New is the management server for a; log_level drives level.
func New(cfg config.Config, a *agent.Agent, level *slog.LevelVar) (*mgmt.Server, error) {
	s, err := mgmt.New(Manifest(cfg), mgmt.WithSource(protocol.Source{Service: protocol.ServiceChannel, Instance: cfg.ChannelID}))
	if err != nil {
		return nil, err
	}
	s.OnApply(func(ctx context.Context, live map[string]any) error {
		timeout := a.CallTimeout()
		if v := live["call_timeout"]; v != nil {
			d, err := protocol.ParseDuration(v)
			if err != nil {
				return fmt.Errorf("call_timeout: %w", err)
			}
			timeout = d
		}
		lvl := slogLevel(live["log_level"])
		if level.Level() == lvl && a.CallTimeout() == timeout {
			return nil
		}
		a.SetCallTimeout(timeout)
		level.Set(lvl)
		slog.Info("management: config applied", "by", actorName(mgmt.ActorFromContext(ctx)), "call_timeout", timeout.String(),
			"log_level", lvl.String())
		return nil
	})
	s.Status(func() map[string]any {
		st := a.Stats()
		return map[string]any{"link_up": st.LinkUp, "connections_open": st.Open, "logins_kept": st.LoginsKept,
			"calls_total": st.Calls, "calls_failed_total": st.CallsFailed, "opens_total": st.Opens,
			"opens_failed_total": st.OpensFailed, "draining": st.Draining}
	})
	s.Action("drain", func(_ context.Context, _ map[string]any, actor *protocol.Actor) (any, error) {
		was := a.Draining()
		a.SetDraining(true)
		slog.Info("management: drained", "by", actorName(actor))
		return map[string]any{"draining": true, "was_draining": was}, nil
	})
	s.Action("resume", func(_ context.Context, _ map[string]any, actor *protocol.Actor) (any, error) {
		was := a.Draining()
		a.SetDraining(false)
		slog.Info("management: resumed", "by", actorName(actor))
		return map[string]any{"draining": false, "was_draining": was}, nil
	})
	s.Action("close_connections", func(_ context.Context, _ map[string]any, actor *protocol.Actor) (any, error) {
		n := a.CloseAll("closed by an operator")
		slog.Info("management: connections closed", "by", actorName(actor), "connections", n)
		return map[string]any{"closed": n}, nil
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
