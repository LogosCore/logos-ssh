# CLAUDE.md

`logos-ssh` (`github.com/logoscore/logos-ssh`): the SSH module, an agentless channel and its factory (docs `contracts/agentless-channels.md`, a draft until core and the docs land). Two programs, one image: `cmd/ssh-channel` (module `ssh`, a channel: both kinds `agentless`, the channel acting as the minion of the servers it logs in to) and `cmd/ssh-factory` (module `ssh`, a factory: builds with `crypto: none`, a JSON description each, nothing to deploy). The two share a module name, as the Dumbo pair do, with their own instance ids (`ssh-local`, `ssh-factory-local`). README.md has what they declare and how a call and an open go.

## Commands

```bash
go build ./... && go vet ./... && go test -race ./...
golangci-lint run --max-issues-per-linter 0 --max-same-issues 0 ./...
docker compose up -d --build
```

Go 1.25.7: pick module versions that do not need a newer Go (x/crypto v0.55.0 and x/net v0.58.0 are the last on 1.25). CI (`.github/workflows/ci.yml`, the same file as the other Go modules) runs the tests and golangci-lint v2.13.2 with default linters, no config: keep 0 issues. A `v*` tag publishes the image (`docker-image.yml`). The tests are Unix-only where they log in: `internal/sshtest` is an SSH server in the test's process (password and key logins, keepalives, `/bin/sh` commands each in a process group of its own as sshd's sessions are, signals, SFTP from a folder). While the protocol is unreleased, a git-excluded `go.work` (`use . ../logos-golang-protocol`) wires the checkout; drop it at release, once the protocol tag the code needs (the `none` suite, `agentless`, the `login` and `host_key` failure kinds, `ssh-host-key`) is in `go.mod`.

## Layout

- `internal/minion`: the SSH minion's own workings (minions share the protocol, never their insides): `Runner` for a persistent connection (BOB's minion's ways: tasks in the background, each message within the connection's size, a standing allowance), `Caller` for calls (the Dumbo page's ways: a call's tasks run in it, walks depth first and transfers going on from their `ctx`, the SHA-256's state carried in it), both acting on a `Host`; `ReadCore`/`Reply`/`Message` (a message has an `id`, starting an exchange, or a `re`, answering one, never both). Tests run it on the test's machine (`osHost`).
- `internal/sshhost`: the `Host` over SSH: files over SFTP (`fs.PathError`s, so `fs.ErrNotExist`/`fs.ErrPermission` show), a folder in name order, owners by name from `/etc/passwd` and `/etc/group` read once, a path's file system as the mount it is under (`/proc/self/mounts`, else `df`), `Rename` the POSIX way where the server has it, `WriteAt` a chunk a call; `Shell` runs `exec /bin/sh -c '<echo LOGOS-PID:$$; command>'`, stdout's first line kept back for the process group a stop kills (`kill -s KILL -- -pid` in a session of its own); `Volumes` from `df -kPT` (else `df -kP`); `Hello` from `uname -snm; id -un; id -u`, the machine id from `/etc/machine-id` over SFTP, else the host key's SHA-256 (`ssh-host-key`).
- `internal/sshconn`: dial (direct, SOCKS5, HTTP CONNECT), log in (key first, then password and keyboard-interactive with it), check the host key, keep the first bytes for "not an SSH server"; `Failure`/`CallFailure` map what came of it onto link failures (`login`, `host_key`, `unreachable`, `timeout`, `other`) or an excerpt. `Pool` keeps a call's login for its target's `call_reuse`, checked with a keepalive before reuse. Channel opens go through `Conn.Session`/`Conn.SFTP`, never `SSH.NewSession` directly: an open waits at most `OpenWait` (15s) and gives up with the connection, as `x/crypto/ssh` can leave one unanswered for good on a connection that went away under it; `Close` ends every wait on the connection.
- `internal/agent`: `Agent.Call` (the control link's handler: read the target, the message unsealed, a login from the pool, `Caller.Answer`, the reply under the call's id) and `Agent.Open` (log in, `connclient.Dial`, then a `session`: core speaks first, the minion answers under core's id and goes on under the session id a `hello_response` gives; replies match by `re`, the rest are pushes; a keepalive every `keepalive`; either side closing closes both).
- `internal/connection`: the connection schema and `ReadTarget`. `internal/ops`: the commands' numbers, shared by the factory's schema and the minion. `internal/management`: the channel's manifest. `internal/icon`: the icon both register with. `cmd/ssh-factory`: the build schema (its params numbered as the minion's `Arg…`), the builder (steps describe, upload; `ssh-<id8>.json`), management (`log_level`).

## Conventions

- The channel is the minion: it reads core's messages and holds targets' credentials. Never log a credential or a message's contents; logs carry the request id, the server, the outcome and the duration.
- Lifecycle, management serving and the control link's and sockets' plumbing stay in module-core and channel-core.
- Nothing may wait on a server past its context. channel-core opens the control link again only once every call returned, so one stuck call stops the whole channel: `Agent.call` closes the call's connection when its context ends (core's deadline, the link dropping), and a broken connection is never pooled.
- The tests check every item the minion sends with the protocol's own validators (`checkItems` in `internal/agent`, the hello as `ValidateAgentless`): core refuses what they refuse.
