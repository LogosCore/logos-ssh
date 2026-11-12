package main

import "testing"

// The broker's defaults are core's dev stack's (user logos, on localhost);
// its password has none, so the factory does not start without it.
func TestAMQPURL(t *testing.T) {
	for _, k := range []string{"RABBITMQ_USER", "RABBITMQ_HOST", "RABBITMQ_PORT", "RABBITMQ_VHOST"} {
		t.Setenv(k, "")
	}
	t.Setenv("RABBITMQ_PASSWORD", "secret")
	if u, err := amqpURL(); err != nil || u != "amqp://logos:secret@localhost:5672//" {
		t.Fatalf("broker: %q, %v", u, err)
	}
	t.Setenv("RABBITMQ_PASSWORD", "")
	if _, err := amqpURL(); err == nil {
		t.Fatal("no RABBITMQ_PASSWORD: taken")
	}
}
