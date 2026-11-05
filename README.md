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
  From then on it runs core's tasks as they come, up to 4 at once. The connection lives as long as
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
| `bind-call` | `call_reuse` (`30s`; `0s` logs in for every call) | `host`, `port` (22), `host_key` (`SHA256:…`; empty: the first one presented, shown on the session to pin), `user`, `password`, `private_key` (OpenSSH or PEM), `passphrase`, `proxy` (`socks5://`, `socks5h://`, `http://`), `connect_timeout` (10s) |
| `bind-persistent` | `keepalive` (`30s`) | the same |

## Commands

`shell` (op 1: `command`, `timeout` 30s; in `/bin/sh`, a stop kills its
process group), `ls` (2), `walk` (3: depth first across calls; `one_fs` by
the server's mount table, as SFTP says no file systems), `download` (4),
`stream_download` (5), `upload` (6), `stream_upload` (7), `rm` (8), `volumes`
(9: `df -kPT`, else `df -kP`). The hello says the server as `uname -snm` and
`id` say it, its machine id (`/etc/machine-id` over SFTP, else the SHA-256 of
its host key: source `ssh-host-key`), pid 0, and `x.ssh_server`,
`x.host_key`.

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
`LOGOS_CORE_BASE_URL`, `MAX_CONNECTIONS` (persistent ones, 1000),
`CALL_TIMEOUT` (2m, 1s to 10m: how long a call may take, its login and its
tasks; core's deadline, 2 minutes, wins when shorter), `LOG_FORMAT` (`json`,
`text`), `RABBITMQ_*`. The factory: `FACTORY_ID`
(`ssh-factory-local`), `LOG_FORMAT`, `RABBITMQ_*`.

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
groups of their own, SFTP; `NewWindows` answers as Windows's OpenSSH does:
its version, SFTP with `C:` at its root and a link to a folder read as a
junction, commands a test's `Exec` answers, stopped by a signal), so they
need no server and run on Unix.
