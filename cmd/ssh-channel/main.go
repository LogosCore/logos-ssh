// Command ssh-channel is the SSH channel (docs: contracts/agentless-channels/):
// an agentless channel, the minion of the SSH servers it reaches. Core calls
// it (bind-call) and opens connections through it (bind-persistent) over the
// control link; it logs in to the server and runs the minion's tasks there,
// over SSH and SFTP, nothing installed on the server.
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/logoscore/logos-golang-channel-core/v3/pkg/channel"
	"github.com/logoscore/logos-golang-channel-core/v3/pkg/linkclient"
	"github.com/logoscore/logos-golang-module-core/pkg/lifecycle"
	"github.com/logoscore/logos-golang-module-core/pkg/logging"
	"github.com/logoscore/logos-golang-module-core/pkg/logstream"
	"github.com/logoscore/logos-golang-module-core/pkg/module"
	"github.com/logoscore/logos-ssh/internal/agent"
	"github.com/logoscore/logos-ssh/internal/config"
	"github.com/logoscore/logos-ssh/internal/connection"
	"github.com/logoscore/logos-ssh/internal/icon"
	"github.com/logoscore/logos-ssh/internal/management"
	"github.com/logoscore/logos-ssh/internal/sshhost"
)

// version is reported at registration and in the minion's hello; set with
// -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var envFile string
	flag.StringVar(&envFile, "config", ".env", "path to .env fallback file")
	flag.Parse()
	cfg, err := config.LoadFromEnv(envFile)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	var level slog.LevelVar
	logs := logstream.New(cfg.ChannelID)
	logger, err := logging.New(cfg.LogFormat, os.Stderr, &level, logs)
	if err != nil {
		log.Fatalf("logging: %v", err)
	}
	slog.SetDefault(logger)
	sshhost.Version = "logos-ssh/" + version

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a := agent.New(cfg.CoreBaseURL, cfg.ChannelID, cfg.MaxConnections)
	a.SetCallTimeout(cfg.CallTimeout)
	mgmtSrv, err := management.New(cfg, a, &level)
	if err != nil {
		slog.Warn("management disabled", "err", err)
	}
	slog.Info("logos-ssh channel starting", "channel_id", cfg.ChannelID, "core", cfg.CoreBaseURL, "max_connections", cfg.MaxConnections,
		"call_timeout", cfg.CallTimeout.String())

	regCtx, stopReg := context.WithCancel(context.Background())
	regDone := make(chan struct{})
	go func() {
		defer close(regDone)
		schema := connection.Schema()
		mc := channel.Config{
			Config: module.Config{
				AMQPURL: cfg.RabbitMQURL,
				Identity: lifecycle.Identity{
					ModuleType:  channel.ModuleType,
					ModuleName:  "ssh",
					Instance:    cfg.ChannelID,
					Version:     version,
					Description: "SSH: the minion of the servers it logs in to (agentless: nothing installed on them), per call or over a connection kept open",
					Icon:        icon.Dark,
					IconLight:   icon.Light,
				},
			},
			Connection: &schema,
		}
		if mgmtSrv != nil {
			mc.Management, mc.Logs = mgmtSrv, logs
		}
		if err := channel.Run(regCtx, mc); err != nil {
			fatal("control plane failed", "err", err)
		}
	}()

	// The control link: core refuses it until the instance is registered,
	// and the client keeps trying.
	linkCtx, stopLink := context.WithCancel(context.Background())
	linkDone := make(chan struct{})
	go func() {
		defer close(linkDone)
		err := linkclient.Run(linkCtx, linkclient.Options{
			BaseURL: cfg.CoreBaseURL, Instance: cfg.ChannelID, Handler: a.Call, Opener: a.Open, OnState: a.SetLinkUp,
		})
		if err != nil {
			fatal("control link", "err", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")
	// No new calls or opens; the connections close (core sees them not
	// connected and opens again by policy once a channel is back), then it
	// deregisters.
	a.SetDraining(true)
	a.Close("the channel is stopping")
	stopLink()
	select {
	case <-linkDone:
	case <-time.After(5 * time.Second):
	}
	stopReg()
	<-regDone
}

func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}
