package main

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/logoscore/logos-golang-factory-core/pkg/factory"
	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-ssh/internal/connection"
	"github.com/logoscore/logos-ssh/internal/minion"
	"github.com/logoscore/logos-ssh/internal/ops"
)

// buildSchema is what the SSH factory builds (docs:
// contracts/agentless-channels/): servers reached over SSH, the SSH channel
// acting as their minion. A build holds no program and no keys: it is a
// description of what it has. Its keys stay with core, which gives them to
// the SSH channel (the minion) with each call and open. Commands added
// later need no new version.
var buildSchema = protocol.BuildSchema{
	SchemaVersion: protocol.BuildSchemaV3,
	Version:       1,
	Channels: []protocol.BuildChannel{{
		ModuleName: channelModule, Num: 1, Versions: []int{connection.Version},
		Kinds: []protocol.BuildKind{{Kind: protocol.KindBindCall}, {Kind: protocol.KindBindPersistent}},
	}},
	Crypto: protocol.CryptoAES256CBCHMACSHA256,
	Targets: []protocol.BuildTarget{{
		ID: targetServer, Label: "SSH server", Format: "json", Platforms: []string{"any/any"},
		Description: "A server reached over SSH: the SSH channel acts as its minion, and nothing is installed on it. The build's file says what it has; add a target to the build (host, the credentials to log in with) for each server.",
	}},
	Commands: []protocol.BuildCommand{
		{
			ID: "shell", Op: ops.Shell, Label: "Run a shell command", Default: true,
			Description: "Runs a command line in /bin/sh on the server and answers with its output and exit status. Through a call it ends within the call; a long one needs a persistent connection.",
			Params: []protocol.FieldSpec{
				{Key: "command", Num: minion.ArgShellCommand, Type: protocol.FieldString, Label: "Command", Required: true, Order: 1},
				{Key: "timeout", Num: minion.ArgShellTimeout, Type: protocol.FieldDuration, Label: "Timeout", Default: "30s", Order: 2},
			},
		},
		{
			ID: "ls", Op: ops.Ls, Label: "List a directory", Default: true,
			Description: "Lists a folder on the server; a relative path is from the login's home.",
			Result:      protocol.ResultDirListing, Action: protocol.ActionListDir,
			Params: []protocol.FieldSpec{{Key: "path", Num: minion.ArgLsPath, Type: protocol.FieldString, Label: "Path", Default: "."}},
		},
		{
			ID: "walk", Op: ops.Walk, Label: "Walk a directory", Default: true,
			Description: "Lists a directory and the folders under it into core's file browser; links are not followed.",
			Action:      protocol.ActionWalkDir, Result: protocol.ResultDirWalk,
			Params: []protocol.FieldSpec{
				{Key: "path", Num: minion.ArgWalkPath, Type: protocol.FieldString, Label: "Path", Required: true, Order: 1},
				{Key: "depth", Num: minion.ArgWalkDepth, Type: protocol.FieldInt, Label: "Depth", Default: 5, Order: 2,
					Description: "How many levels of folders under it to go down; 0 for all."},
				{Key: "max_folders", Num: minion.ArgWalkMaxFolders, Type: protocol.FieldInt, Label: "At most", Default: 10000, Order: 3,
					Description: "Folders to list before it stops; 0 for no limit (stop it from its task)."},
				{Key: "hidden", Num: minion.ArgWalkHidden, Type: protocol.FieldBool, Label: "Into hidden folders", Default: true, Order: 4},
				{Key: "one_fs", Num: minion.ArgWalkOneFS, Type: protocol.FieldBool, Label: "Stay on its file system", Default: true, Order: 5,
					Description: "Folders another file system is mounted on (/proc, a share) are not entered, as the server's mount table says."},
			},
		},
		{
			ID: "download", Op: ops.Download, Label: "Download a file", Default: true,
			Description: "Sends a file from the server to core, over SFTP.",
			Result:      protocol.ResultFileDownload, Action: protocol.ActionDownloadFile,
			Params: []protocol.FieldSpec{{Key: "path", Num: minion.ArgDownloadPath, Type: protocol.FieldString, Label: "Path", Required: true}},
		},
		{
			ID: "stream_download", Op: ops.StreamDownload, Label: "Stream a file", Default: true,
			Description: "Streams a file of any size from the server to whoever downloads it; core keeps none of it.",
			Result:      protocol.ResultFileStream, Action: protocol.ActionStreamFile,
			Params: []protocol.FieldSpec{{Key: "path", Num: minion.ArgStreamDownloadPath, Type: protocol.FieldString, Label: "Path", Required: true}},
		},
		{
			ID: "upload", Op: ops.Upload, Label: "Upload a file", Default: true,
			Description: "Puts a file from core on the server, over SFTP.",
			Result:      protocol.ResultFileUpload, Action: protocol.ActionUploadFile,
			Params: []protocol.FieldSpec{
				{Key: "file", Num: minion.ArgUploadFile, Type: protocol.FieldFile, Label: "File", Required: true, Order: 1},
				{Key: "path", Num: minion.ArgUploadPath, Type: protocol.FieldString, Label: "Path", Required: true, Order: 2,
					Description: "Where it goes on the server; a folder takes it under its own name."},
				{Key: "overwrite", Num: minion.ArgUploadOverwrite, Type: protocol.FieldBool, Label: "Overwrite", Default: false, Order: 3,
					Description: "Replace a file already there."},
			},
		},
		{
			ID: "stream_upload", Op: ops.StreamUpload, Label: "Stream a file up", Default: true,
			Description: "Puts a file of any size on the server as it is uploaded; core keeps none of it.",
			Result:      protocol.ResultFileUpload, Action: protocol.ActionUploadStream,
			Params: []protocol.FieldSpec{
				{Key: "stream", Num: minion.ArgStreamUploadStream, Type: protocol.FieldStream, Label: "File", Order: 1,
					Description: "Picked in the browser, it goes once the task is queued. Left out, upload it with curl from the task's view."},
				{Key: "path", Num: minion.ArgStreamUploadPath, Type: protocol.FieldString, Label: "Path", Required: true, Order: 2,
					Description: "Where it goes on the server. A folder takes a picked file under its own name; with curl, name the file."},
				{Key: "overwrite", Num: minion.ArgStreamUploadOverwrite, Type: protocol.FieldBool, Label: "Overwrite", Default: false, Order: 3,
					Description: "Replace a file already there."},
			},
		},
		{
			ID: "rm", Op: ops.Rm, Label: "Delete a file or folder", Default: true,
			Description: "Removes a file, a link (not what it points to) or a folder on the server; never a file system's root.",
			Action:      protocol.ActionDeletePath,
			Params: []protocol.FieldSpec{
				{Key: "path", Num: minion.ArgRmPath, Type: protocol.FieldString, Label: "Path", Required: true, Order: 1},
				{Key: "recursive", Num: minion.ArgRmRecursive, Type: protocol.FieldBool, Label: "With what is in it", Default: false, Order: 2,
					Description: "A folder that is not empty goes with everything in it."},
			},
		},
		{
			ID: "volumes", Op: ops.Volumes, Label: "List volumes", Default: true,
			Description: "Lists the server's mounted file systems (df), with their space; the file browser shows them as its roots.",
			Action:      protocol.ActionListVolumes, Result: protocol.ResultVolumes,
		},
		{
			ID: "become", Op: ops.Become, Label: "Become another user", Default: true,
			Description: "Shell commands from now on run as another user (root unless you say), in shells elevated once on the connection through sudo or su, until unbecome. " +
				"File commands still run as the login. A password goes only when the server asks; sudo's is the login's own unless you give one, su's the user's.",
			Params: []protocol.FieldSpec{
				{Key: "user", Num: minion.ArgBecomeUser, Type: protocol.FieldString, Label: "User", Default: "root", MaxLength: 32, Order: 1,
					Description: "A user name; through sudo also #uid."},
				{Key: "method", Num: minion.ArgBecomeMethod, Type: protocol.FieldEnum, Label: "Method", Default: minion.BecomeSudo, Order: 2,
					Options: []protocol.EnumOption{
						{Value: minion.BecomeSudo, Label: "sudo", Description: "sudo -u <user>: the login's password, if sudo asks."},
						{Value: minion.BecomeSudoSu, Label: "sudo su", Description: "sudo su <user>, for sudoers that allow only su: the login's password, if sudo asks."},
						{Value: minion.BecomeSu, Label: "su", Description: "su <user>, with the user's password, in a terminal script(1) makes on the server."},
					}},
				{Key: "password", Num: minion.ArgBecomePassword, Type: protocol.FieldCredential, Label: "Password", Order: 3,
					Accept:      []string{protocol.CredentialTypePlaintext},
					Description: "sudo's (instead of the login's own) or su's (the user's): given only when the server asks."},
			},
		},
		{
			ID: "unbecome", Op: ops.Unbecome, Label: "Unbecome", Default: true,
			Description: "Shell commands run as the login again; the elevated shells close.",
		},
		{
			ID: "tunnel", Op: ops.Tunnel, Label: "Tunnel", Default: true,
			Description: "Opens a tunnel through the SSH server on one of core's operational ports: a SOCKS proxy, an HTTP proxy, a port forward, a terminal or a VPN, as its front says. " +
				"Each connection a tool makes through it, the server makes (SSH's port forwarding: its AllowTcpForwarding and PermitOpen decide); a terminal's, the login's shell (or the program it says) in a terminal on the server. " +
				"TCP only: SSH carries no UDP and no ping. Over a connection that stays open (bind-persistent); it runs until stopped, or until that connection drops.",
			Action: protocol.ActionTunnel,
			Kinds:  []string{protocol.KindBindPersistent},
			// TCP connections (direct-tcpip; TLS on top, the minion's), unix
			// sockets (OpenSSH's direct-streamlocal), processes (a session
			// with a pty, else pipes) and accepts (SOCKS BIND: a remote
			// forward for one connection).
			Opens: []string{protocol.OpenTCP, protocol.OpenUnix, protocol.OpenTLS, protocol.OpenProcess, protocol.OpenAccept},
			// Core adds the front, the port, a forward's destination, when it
			// stops the tunnel idle and the bandwidth cap
			// (protocol.TunnelCoreParams): no num, never sent.
			Params: []protocol.FieldSpec{
				{Key: "timeout", Num: minion.ArgTunnelTimeout, Type: protocol.FieldDuration, Label: "Connect timeout", Default: "10s", Order: 10, Advanced: true,
					Description: "How long the server tries to connect to a destination.",
					When: &protocol.FieldCondition{Key: protocol.ParamFront,
						Values: []string{protocol.FrontSOCKS, protocol.FrontHTTP, protocol.FrontForward, protocol.FrontVPN}}},
				{Key: "max_streams", Num: minion.ArgTunnelMaxStreams, Type: protocol.FieldInt, Label: "Connections at once", Default: 256, Min: 1, Max: 4096,
					Order: 11, Advanced: true, Description: "How many of the tools' connections the tunnel carries at once."},
			},
		},
		{
			ID: "reverse_tunnel", Op: ops.ReverseTunnel, Label: "Reverse tunnel", Default: true,
			Description: "Has the SSH server listen on a TCP port (a remote forward): each connection to it, core connects to a destination from its own network (an operator's handler, a server core reaches). " +
				"The server listens on its loopback alone unless its GatewayPorts lets it listen where asked. Over a connection that stays open (bind-persistent); it runs until stopped, or until that connection drops.",
			Action: protocol.ActionReverseTunnel,
			Kinds:  []string{protocol.KindBindPersistent},
			Opens:  []string{protocol.OpenTCP},
			Params: []protocol.FieldSpec{
				{Key: "bind", Num: minion.ArgReverseBind, Type: protocol.FieldString, Label: "Listen address", Default: "0.0.0.0", MaxLength: 255, Order: 1,
					Description: "The address the server listens on: 0.0.0.0 for all of its own (as its GatewayPorts allows: else its loopback), 127.0.0.1 for itself alone."},
				{Key: "listen", Num: minion.ArgReverseListen, Type: protocol.FieldInt, Label: "Listen port", Required: true, Min: 0, Max: 65535, Order: 2,
					Description: "The port on the server: 0 for any free one. One under 1024 needs a root login."},
				{Key: "timeout", Num: minion.ArgReverseTimeout, Type: protocol.FieldDuration, Label: "Connect timeout", Default: "10s", Order: 10, Advanced: true,
					Description: "How long core tries to connect to a destination; a connection to the server waits that long, and 30 s more, for it."},
				{Key: "max_streams", Num: minion.ArgReverseMaxStreams, Type: protocol.FieldInt, Label: "Connections at once", Default: 256, Min: 1, Max: 4096,
					Order: 11, Advanced: true, Description: "How many connections the tunnel carries at once: one past it is closed."},
			},
		},
	},
}

const (
	channelModule = "ssh"
	targetServer  = "ssh"
)

// sshFactory builds descriptions of SSH builds.
type sshFactory struct{}

// The steps of a build.
var (
	stepDescribe = protocol.BuildStep{ID: "describe", Label: "Describe the build"}
	stepUpload   = protocol.BuildStep{ID: "upload", Label: "Upload the description"}
)

// Steps is every build's plan.
func (sshFactory) Steps(protocol.BuildRequest) []protocol.BuildStep {
	return []protocol.BuildStep{stepDescribe, stepUpload}
}

// description is a build's file: what it has, for the record. There is
// nothing to deploy and nothing secret in it: the channel acts as the
// minion, and core keeps the build's keys, giving them to the channel with
// each call and open.
type description struct {
	BuildID     string          `json:"build_id"`
	Module      string          `json:"module"`
	Target      string          `json:"target"`
	Commands    []string        `json:"commands"`
	Connections []describedConn `json:"connections"`
	Note        string          `json:"note"`
}

type describedConn struct {
	Place    int    `json:"place"`
	Kind     string `json:"kind"`
	Endpoint string `json:"endpoint,omitempty"`
}

func (sshFactory) Build(ctx context.Context, job *factory.Job) (factory.Result, error) {
	job.Step(stepDescribe.ID, "")
	req := job.Request
	d := description{BuildID: req.BuildID, Module: "ssh", Target: req.Target,
		Note: "Nothing to deploy: add a target to this build for each server (its host, a user, a password or key), and core reaches it through the SSH channel."}
	for _, c := range buildSchema.Commands {
		if job.HasCommand(c.ID) {
			d.Commands = append(d.Commands, c.ID)
		}
	}
	for i, c := range req.Connections {
		d.Connections = append(d.Connections, describedConn{Place: i + 1, Kind: c.ConnectionKind(), Endpoint: c.Endpoint.Name})
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return factory.Result{}, err
	}
	job.Logf("a description of build %s: %d commands, %d connections", req.BuildID, len(d.Commands), len(d.Connections))
	job.Step(stepUpload.ID, "")
	if err := job.UploadArtifact(ctx, "ssh-"+req.BuildID[:8]+".json", "application/json", bytes.NewReader(append(b, '\n'))); err != nil {
		return factory.Result{}, err
	}
	return factory.Result{}, nil
}
