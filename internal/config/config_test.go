package config

import "testing"

// The broker's defaults are core's dev stack's (user logos, on localhost);
// its password has none, so the channel does not start without it.
func TestBroker(t *testing.T) {
	for _, k := range []string{"RABBITMQ_USER", "RABBITMQ_HOST", "RABBITMQ_PORT", "RABBITMQ_VHOST"} {
		t.Setenv(k, "")
	}
	t.Setenv("RABBITMQ_PASSWORD", "secret")
	cfg, err := LoadFromEnv("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RabbitMQURL != "amqp://logos:secret@localhost:5672//" {
		t.Fatalf("broker: %s", cfg.RabbitMQURL)
	}
	t.Setenv("RABBITMQ_PASSWORD", "")
	if _, err := LoadFromEnv(""); err == nil {
		t.Fatal("no RABBITMQ_PASSWORD: taken")
	}
}
