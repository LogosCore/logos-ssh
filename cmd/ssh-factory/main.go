// Command ssh-factory is the SSH factory (docs: contracts/agentless-channels/):
// it builds descriptions of SSH builds, servers the SSH channel reaches and
// acts as the minion of. A build takes seconds and holds no program and no
// keys: its messages go unsealed (crypto none), only through the SSH
// channel's agentless kinds.
package main

import (
	"context"
	"log"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/logoscore/logos-golang-factory-core/pkg/factory"
	"github.com/logoscore/logos-golang-module-core/pkg/lifecycle"
	"github.com/logoscore/logos-golang-module-core/pkg/logging"
	"github.com/logoscore/logos-golang-module-core/pkg/logstream"
	"github.com/logoscore/logos-golang-module-core/pkg/module"
	"github.com/logoscore/logos-ssh/internal/icon"
)

// version is reported at registration; set with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	instance := env("FACTORY_ID", "ssh-factory-local")

	var level slog.LevelVar
	logs := logstream.New(instance)
	logger, err := logging.New(os.Getenv("LOG_FORMAT"), os.Stderr, &level, logs)
	if err != nil {
		log.Fatalf("logging: %v", err)
	}
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	slog.Info("logos-ssh factory starting", "instance", instance, "version", version)
	mgmtSrv, err := newManagement(&level)
	if err != nil {
		fatal("management", "err", err)
	}
	schema := buildSchema
	err = factory.Run(ctx, factory.Config{
		Config: module.Config{
			AMQPURL: amqpURL(),
			Identity: lifecycle.Identity{
				ModuleName:  "ssh",
				Instance:    instance,
				Version:     version,
				Description: "SSH: builds for servers the SSH channel reaches and acts as the minion of (agentless: nothing installed on them)",
				Icon:        icon.Dark,
				IconLight:   icon.Light,
			},
			Management: mgmtSrv,
			Logs:       logs,
		},
		Build:               &schema,
		Builder:             sshFactory{},
		MaxConcurrentBuilds: 8,
	})
	if err != nil {
		fatal("control plane failed", "err", err)
	}
	slog.Info("bye")
}

func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

func amqpURL() string {
	u := url.URL{
		Scheme: "amqp",
		User:   url.UserPassword(env("RABBITMQ_USER", "guest"), env("RABBITMQ_PASSWORD", "guest")),
		Host:   net.JoinHostPort(env("RABBITMQ_HOST", "localhost"), env("RABBITMQ_PORT", "5672")),
		// amqp091 takes the vhost from the path minus its leading "/".
		Path: "/" + env("RABBITMQ_VHOST", "/"),
	}
	return u.String()
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
