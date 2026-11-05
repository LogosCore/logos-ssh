package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"

	"github.com/logoscore/logos-golang-factory-core/pkg/factorytest"
	"github.com/logoscore/logos-golang-module-core/pkg/mgmt"
	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-ssh/internal/ops"
)

// The schema is valid as core checks it: the AES suite, the SSH channel's
// two kinds; its commands are the minion's, by the same numbers.
func TestSchema(t *testing.T) {
	if err := protocol.ValidateBuildSchema(buildSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := mgmt.New(manifest()); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if buildSchema.Crypto != protocol.CryptoAES256CBCHMACSHA256 {
		t.Fatalf("crypto %q", buildSchema.Crypto)
	}
	var declared []uint64
	for _, c := range buildSchema.Commands {
		op := uint64(c.Op) //nolint:gosec // an op, 1 to 65535
		if _, ok := ops.Commands[op]; !ok {
			t.Errorf("%s: op %d is not the minion's", c.ID, c.Op)
		}
		declared = append(declared, op)
	}
	for _, op := range ops.Numbers() {
		if !slices.Contains(declared, op) {
			t.Errorf("op %d: the minion's, not declared", op)
		}
	}
}

// testMaterial are a build's keys as core sends them in the build request:
// they stay with core, never in the description.
var testMaterial = json.RawMessage(`{"enc_key":"` + secretKey + `","mac_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}`)

const secretKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="

func request(commands []string) protocol.BuildRequest {
	return protocol.BuildRequest{
		BuildID: "5b0c4f6e-8a1d-4c2b-9e7f-3d2a1b0c9e8f", Target: targetServer, Platform: "any/any", SchemaVersion: 1,
		Commands: commands,
		Connections: []protocol.BuildConnection{
			{Endpoint: protocol.ChannelEndpointExport{Format: "logos.channel-endpoint.v2", Name: "ssh per call",
				Channel: protocol.ExportChannel{ModuleName: channelModule, SchemaVersion: 1}, Kind: protocol.KindBindCall,
				Params: map[string]any{"call_reuse": "30s"}}},
			{Endpoint: protocol.ChannelEndpointExport{Format: "logos.channel-endpoint.v2", Name: "ssh kept open",
				Channel: protocol.ExportChannel{ModuleName: channelModule, SchemaVersion: 1}, Kind: protocol.KindBindPersistent,
				Params: map[string]any{"keepalive": "30s"}}},
		},
		Crypto: &protocol.BuildCrypto{Suite: protocol.CryptoAES256CBCHMACSHA256, Material: testMaterial},
	}
}

// A build is its description: what it has, nothing to deploy, nothing
// secret; a read-only build has the commands picked and no others.
func TestBuild(t *testing.T) {
	res, artifact := factorytest.Build(t, buildSchema, sshFactory{}, factorytest.NewStore(t), request([]string{"ls", "walk", "download", "volumes"}))
	if res.Status != protocol.BuildSucceeded {
		t.Fatalf("result %+v", res)
	}
	var d description
	if err := json.Unmarshal(artifact, &d); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(artifact, []byte(secretKey)) || bytes.Contains(artifact, []byte("mac_key")) {
		t.Fatal("the build's keys are in its description")
	}
	if d.BuildID != "5b0c4f6e-8a1d-4c2b-9e7f-3d2a1b0c9e8f" || !slices.Equal(d.Commands, []string{"ls", "walk", "download", "volumes"}) ||
		len(d.Connections) != 2 || d.Connections[1].Kind != protocol.KindBindPersistent || d.Connections[0].Endpoint != "ssh per call" {
		t.Fatalf("description %+v", d)
	}
	// Every command, as core sends a build that keeps the defaults.
	var all []string
	for _, c := range buildSchema.Commands {
		all = append(all, c.ID)
	}
	_, artifact = factorytest.Build(t, buildSchema, sshFactory{}, factorytest.NewStore(t), request(all))
	var every description
	if err := json.Unmarshal(artifact, &every); err != nil || !slices.Equal(every.Commands, all) {
		t.Fatalf("commands %v %v", every.Commands, err)
	}
}
