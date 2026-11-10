# logos-ssh

The SSH module for Logos: an **agentless** channel and its factory (docs:
`contracts/agentless-channels`). The channel is the minion of the SSH servers
it logs in to: it takes core's messages, runs their tasks on the server (commands
in exec channels, files over SFTP) and answers as a minion would. Nothing is
installed on the server; core sees a minion behind a `bind` channel.

Two programs, one image:

- **`ssh-channel`** (module `ssh`, a channel): the connection schema below,
  both kinds `agentless`. Core calls it over the control link (`bind-call`)
  and asks it to open connections (`bind-persistent`).
- **`ssh-factory`** (module `ssh`, a factory): builds for servers reached
  this way. A build takes seconds and holds no program and no keys: its file
  describes what it has. Its suite is the AES one, as any factory's; core
  keeps the build's keys and gives them to the channel with each call and
  open, as the channel's kinds are agentless. Add a target to the build for each server.

## How it goes

- **A call** (`bind-call`): the channel reads the target's values, logs in (or
  takes the login a call before kept, for `call_reuse`), and answers core's
  message as the minion: a `rehello` with its hello, the call's tasks run in
  it one after another, walks and file transfers going on from their `ctx`
  across calls, as the Dumbo page does. A task ends within the call's
  deadline.
- **An open** (`bind-persistent`): the channel logs in, opens the
  connection's socket to core, and the minion speaks first, as a listening
  minion does: its hello, alone, under the id the open gives (the target's
  open session's, else the build's: the minion keeps no ids of its own).
  From then on it runs core's tasks as they come, up to 4 at once (tunnels
  besides: they run until stopped). The connection lives as long as
  both the socket and the SSH connection; a keepalive finds a server gone
  quiet. Its commands run inside the SSH connection and go with it: back
  over a new one, core's `reack` (which tasks it still has) gets
  `unknown_task` for each of them, and core ends them.
- **What came of it** decides the target's state: nothing reached
  (unreachable, timeout), something that is not an SSH server (what it sent,
  for a call), a host key other than the one given (failure `host_key`), a
  login refused (failure `login`).

## Connection schema (`ssh`, version 1)

| Kind | Built-in (`fields`) | Each server (`target`) |
|---|---|---|
| `bind-call` | `call_reuse` (`30s`; `0s` logs in for every call) | `host`, `port` (22), `host_key` (`SHA256:…`; empty: the first one presented, shown on the session to pin), `user` (for a credential without a username), `credentials` (required: the operation's `KEY` and `PLAINTEXT` credentials, up to 8, tried in order, a connection each, until one is taken; a password with a realm logs in as `username@realm`), `proxy` (`socks5://`, `socks5h://`, `http://`), `connect_timeout` (10s) |
| `bind-persistent` | `keepalive` (`30s`) | the same |

## Commands

`shell` (op 1: `command`, `timeout` 30s; in `/bin/sh`, a stop kills its
process group), `ls` (2), `walk` (3: depth first across calls; `one_fs` by
the server's mount table, as SFTP says no file systems), `download` (4),
`stream_download` (5), `upload` (6), `stream_upload` (7), `rm` (8), `volumes`
(9: `df -kPT`, else `df -kP`), `become` (10: shell commands from then on as
another user, through sudo or su) and `unbecome` (11), `tunnel` (12) and
`reverse_tunnel` (13), below. The hello says the server as `uname -snm` and
`id` say it, its machine id (`/etc/machine-id` over SFTP, else the SHA-256 of
its host key: source `ssh-host-key`), pid 0, and `x.ssh_server`,
`x.host_key`.

**Tunnels** (`bind-persistent` only; docs: `contracts/agentless-channels`,
Tunnels): the channel runs core's tunnel items itself, each stream over the
session's own SSH connection, as `ssh -L`, `-D` and `-R` do, so core's fronts
(SOCKS, HTTP proxy, forward, terminal, VPN) work as they do with BOB's. A
TCP stream is a `direct-tcpip` channel (TLS on top, the channel's), a unix
socket OpenSSH's `direct-streamlocal`, a terminal a session of its own (a pty
of the open's size when the server gives one, else pipes: the program, or
the login's shell; Ctrl-C written in for an interrupt, terminate and kill to
its whole session), SOCKS5 `BIND` and `reverse_tunnel` a remote forward
(`tcpip-forward`: on the server's loopback unless its `GatewayPorts` lets it
listen where asked). No UDP and no ICMP: SSH carries neither. Everything runs
as the login (a become elevates shell commands alone), within what the
server's `AllowTcpForwarding`, `PermitOpen` and `AllowStreamLocalForwarding`
allow, its refusals read as tunnel results (`denied`, `refused`, `host
unreachable`, ...). Tunnels end with the connection: core then gets
`unknown_task` for them and ends them. Windows's OpenSSH (checked against
9.5): a terminal is a ConPTY, an interrupt Ctrl-C, terminate and kill SSH's
`KILL` (the process tree ends); its terminals say exit 0 whatever the shell
exits with (pipes say the code); a port that refuses opens after about 2 s
and ends at once; a unix socket's forward fails (`open failed`).

Windows servers (Windows's OpenSSH: its version says `OpenSSH_for_Windows`,
its SFTP a drive's folders, `/C:/Users/me`) are served as BOB's minion runs on
Windows. Paths are Windows's (`C:\Users\me`: `/` read as `\`, a drive alone
its root), each SFTP call taking SFTP's `/C:/` form. Each listing also asks
cmd's `dir` for the entries' attributes (the listing's modes, hidden by
attribute) and junctions, which list as links to their targets: SFTP reads a
junction as the folder it points to, so walks would loop through one and a
removal would reach through it. `rm` removes a junction as itself and a
read-only file too. `shell` runs the line as typed in the server's default
shell (`cmd.exe /c`), and a stop is a `KILL` signal, on which Windows's
OpenSSH ends all the command started. The hello (one PowerShell script, its
values as hex of UTF-16 whatever the console's code page; cmd's when
PowerShell does not run) says `windows`, the architecture, the host, the
`DOMAIN\user`, the domain or workgroup, the integrity by the login's
mandatory label, and BOB's machine id on Windows (`smbios-uuid`, else
`win-machine-guid`). `volumes` are the drives (`Win32_LogicalDisk`; else
SFTP's root and `statvfs`). Docs: `contracts/agentless-channels.md`,
Windows servers.

## Config

The channel (`internal/config`): `CHANNEL_ID` (`ssh-local`),
`LOGOS_CORE_BASE_URL` (and, over HTTPS to a self-signed core,
`LOGOS_CORE_CA_FILE`, `LOGOS_CORE_CERT_SHA256` or `LOGOS_CORE_TLS_INSECURE`:
[How modules reach core](https://logoscore.github.io/logos-docs/core-infrastructure/#how-modules-reach-core)), `MAX_CONNECTIONS` (persistent ones, 1000),
`CALL_TIMEOUT` (2m, 1s to 10m: how long a call may take, its login and its
tasks; core's deadline, 2 minutes, wins when shorter), `LOG_FORMAT` (`json`,
`text`), `RABBITMQ_*`. The factory: `FACTORY_ID`
(`ssh-factory-local`), `LOGOS_CORE_BASE_URL` (the channel's, with the same
TLS settings: builds upload their description to core), `LOG_FORMAT`,
`RABBITMQ_*`.

## Management

The channel: `call_timeout` and `log_level` (live); `drain`, `resume`, `close_connections`
(persistent connections and kept logins); status: the control link,
connections open, logins kept, calls and opens (and failed). The factory:
`log_level`, and factory-core's builds section.

## Trust

An agentless channel is not blind: core gives it the keys of every call and
open, so it reads what it carries, and it holds the targets' credentials
(core gives them with every call and open too). Run it where you would run
an agent, its link to core private (TLS) until channel authentication is
built.

## Development

```bash
go build ./... && go vet ./... && go test -race ./...
golangci-lint run ./...
docker compose up -d --build
```

The tests log in to an SSH server in the test's own process
(`internal/sshtest`: password and key logins, `/bin/sh` commands in process
groups of their own, SFTP, forwards (`direct-tcpip`, `direct-streamlocal`,
`tcpip-forward`) and, on Linux, terminals (`pty-req`, `window-change`);
`NewWindows` answers as Windows's OpenSSH does:
its version, SFTP with `C:` at its root and a link to a folder read as a
junction, commands a test's `Exec` answers, stopped by a signal), so they
need no server and run on Unix.
