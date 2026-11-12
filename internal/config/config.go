// Package config reads the SSH channel's settings from the environment (and a
// .env file as fallback).
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Config is what the process runs with.
type Config struct {
	// ChannelID is the instance id core knows the process by.
	ChannelID string
	// CoreBaseURL is core's base URL: the control link and connection
	// sockets open under it.
	CoreBaseURL string
	// MaxConnections bounds the persistent connections open at once
	// (MAX_CONNECTIONS, 1000).
	MaxConnections int
	// CallTimeout bounds each call (CALL_TIMEOUT, 2m: what core waits for
	// one); core's deadline, when shorter, wins.
	CallTimeout time.Duration
	// RabbitMQURL is the AMQP URL for registering with core.
	RabbitMQURL string
	// LogFormat is the stderr log format: "json" (default) or "text".
	LogFormat string
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// LoadFromEnv reads the config; envFile, when it exists, fills in what the
// environment does not set.
func LoadFromEnv(envFile string) (Config, error) {
	if envFile != "" {
		_ = godotenv.Load(envFile)
	}
	cfg := Config{
		ChannelID:   envOr("CHANNEL_ID", "ssh-local"),
		CoreBaseURL: strings.TrimRight(envOr("LOGOS_CORE_BASE_URL", "http://localhost:8002"), "/"),
	}
	if u, err := url.Parse(cfg.CoreBaseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return Config{}, fmt.Errorf("LOGOS_CORE_BASE_URL must be http(s)://host[:port], got %q", cfg.CoreBaseURL)
	}
	n, err := strconv.Atoi(envOr("MAX_CONNECTIONS", "1000"))
	if err != nil || n < 1 || n > 100000 {
		return Config{}, fmt.Errorf("MAX_CONNECTIONS must be an integer from 1 to 100000")
	}
	cfg.MaxConnections = n
	d, err := time.ParseDuration(envOr("CALL_TIMEOUT", "2m"))
	if err != nil || d < time.Second || d > 10*time.Minute {
		return Config{}, fmt.Errorf("CALL_TIMEOUT must be a duration from 1s to 10m (e.g. 2m)")
	}
	cfg.CallTimeout = d
	// Core's broker: its user is logos-core's RABBITMQ_DEFAULT_USER; its
	// password (RABBITMQ_DEFAULT_PASS) has no default that could fit.
	password := os.Getenv("RABBITMQ_PASSWORD")
	if password == "" {
		return Config{}, fmt.Errorf("RABBITMQ_PASSWORD is required: core's broker password (logos-core's RABBITMQ_DEFAULT_PASS)")
	}
	vhost := envOr("RABBITMQ_VHOST", "/")
	cfg.RabbitMQURL = (&url.URL{
		Scheme: "amqp",
		User:   url.UserPassword(envOr("RABBITMQ_USER", "logos"), password),
		Host:   net.JoinHostPort(envOr("RABBITMQ_HOST", "localhost"), envOr("RABBITMQ_PORT", "5672")),
		// amqp091 takes the vhost from the path minus its leading "/".
		Path: "/" + vhost,
	}).String()
	cfg.LogFormat = strings.ToLower(envOr("LOG_FORMAT", "json"))
	if cfg.LogFormat != "json" && cfg.LogFormat != "text" {
		return Config{}, fmt.Errorf("LOG_FORMAT must be json or text")
	}
	return cfg, nil
}
