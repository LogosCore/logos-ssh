# logos-ssh

The SSH module for Logos: an **agentless** channel and its factory, which
reach SSH servers with nothing installed on them. The channel is the minion of
the servers it logs in to: it takes core's messages, runs their tasks on the
server (commands in exec channels, files over SFTP) and answers as a minion
would. Core sees a minion behind a `bind` channel; the server sees an SSH
client. What makes a channel agentless, and what core gives one, is the docs'
[Agentless Channels](https://logoscore.github.io/logos-docs/contracts/agentless-channels/);
this README is the module's own: what it declares, how it does each command
over SSH, `become`, tunnels and Windows servers.

Two programs, one image (`ghcr.io/logoscore/logos-ssh`, published on `v*`
tags for `linux/amd64` and `linux/arm64`):

- **`ssh-channel`** (module `ssh`, a channel): the
  [connection schema](#connection-schema-ssh-version-1) below, both kinds
  `agentless`. Core calls it over the control link (`bind-call`) and asks it
  to open connections (`bind-persistent`).
- **`ssh-factory`** (module `ssh`, a factory): builds for servers reached
  this way ([Build schema](#build-schema)). A build takes seconds and holds
  no program and no keys: its file describes what it has. Add a target to the
  build for each server.

Both register as `ssh`, as the Dumbo channel and factory are both `dumbo`,
each under an instance id of its own (`ssh-local` and `ssh-factory-local` by
default): core keys registrations by instance id alone, so a channel and a
factory sharing one would replace each other.

## How it goes

- **A call** (`bind-call`): the channel reads the target's values, logs in (or
  takes the login a call before kept, for `call_reuse`), and answers core's
  message as the minion: a `rehello` with its hello, the call's tasks run in
  it one after another, walks and file transfers going on from their `ctx`
  across calls, as the Dumbo page does.
- **An open** (`bind-persistent`): the channel logs in, opens the
  connection's socket to core, and the minion speaks first, as a listening
  minion does: its hello, alone, under the id the open gives (the target's
  open session's, else the build's: the minion keeps no ids of its own).
  From then on it runs core's tasks as they come. The connection lives as
  long as both the socket and the SSH connection; a keepalive finds a server
  gone quiet. Its commands run inside the SSH connection and go with it: back
  over a new one, core's `reack` (which tasks it still has) gets
  `unknown_task` for each of them, and core ends them.
- **The keys**: the factory's suite is the AES one, as any factory's. Core
  makes each build's keys and keeps them, and with every call and open gives
  the channel the keys of the id it goes under (the build's, the session's):
  the channel opens core's message (`protocol.OpenFrame`) and seals the
  minion's answer (`protocol.SealFrame`) with them. The minion does not stage:
  a session's keys are its build's, and the build's file holds none.
- **What came of a call or an open** decides the target's state:

  | What came of it | The channel answers | Target |
  |---|---|---|
  | DNS failed, the connection refused or timed out | a failure: `unreachable` or `timeout` | unreachable, retried |
  | something that is not an SSH server | the first bytes it sent (a call) | not the minion |
  | a host key other than the one given | a failure `host_key`, with the key presented | refused |
  | every login refused | a failure `login`, saying why for each | refused |
  | logged in | its hello | connected |

### Tasks

- **In a call** 4 tasks come at most (each answer's `get_tasks`), and they
  run one after another, each in an SSH channel of its own. A call ends at
  the shorter of core's deadline (2 minutes: the channel declares no
  `max_call`) and the channel's `call_timeout`, keeping 2 seconds of it to
  answer in. A `shell` still running then is stopped and fails with its
  output so far ("stopped at the call's deadline …: a command meant to run
  longer needs a bind-persistent connection"). A task after the call's first
  waits for the next call, not acked, once the answer has used half its room
  or less than 5 seconds of the call are left: core sends it again.
- **On a persistent connection** the minion runs up to 4 tasks at once, each
  in an SSH channel of its own (tunnels besides: they run until stopped), a
  task taking as long as it takes; shell commands after a [become](#become)
  take turns in its elevated shell. The connection closing stops the tasks on
  it.
- **No `sleep` and no `exit`**: without a schedule, core calls only when it
  has something to send. A session ends when an operator archives it, and
  removing its target stops the calls.

### Nothing waits on a server for good

A call lives as long as its context: core's deadline, the channel's
`call_timeout` (`CALL_TIMEOUT`, 2 minutes by default, live in its
management) and the control link. channel-core cancels a call's context when
the link drops, and opens the link again only once every call returned, so one
stuck call would leave the whole channel without a link. Ending the context
closes the call's SSH connection, so whatever still waits on the server gives
up: an SFTP request, a command's output. A channel open (a session, the SFTP
client) waits at most 15 s, and gives up with the connection: `x/crypto/ssh`
can leave an open unanswered for good on a connection that went away under
it. A connection that broke this way is not kept for `call_reuse`.

## Connection schema (`ssh`, version 1)

Both kinds `agentless`, with the same target fields:

| Kind | Built-in (`fields`) | Each server (`target`) |
|---|---|---|
| `bind-call` | `call_reuse` (`30s`, `0s` to `10m`: how long the SSH connection stays open after a call, for the next one; `0s` logs in for every call) | `host` (required), `port` (`22`), `host_key`, `user`, `credentials` (required), `proxy`, `connect_timeout` (`10s`, `1s` to `2m`: reaching the server and logging in) |
| `bind-persistent` | `keepalive` (`30s`, `5s` to `1h`: how often the channel checks the server is still there) | the same |

Its field numbers, one numbering for the kinds' fields and the targets'
([Field numbers](https://logoscore.github.io/logos-docs/contracts/minion-connection/#field-numbers);
`TestFieldNumbers` pins them): `host` 1, `port` 2, `host_key` 3, `user` 4,
`credentials` 5, `proxy` 6, `connect_timeout` 7, `call_reuse` 8, `keepalive`
9.

- **`credentials`**: a `credential_list` of the operation's
  [credentials](https://logoscore.github.io/logos-docs/contracts/credentials/),
  `KEY` and `PLAINTEXT`, up to 8, tried in order ([Logging in](#logging-in));
  `user` is who a credential without a username logs in as.
- **`host_key`**: the server's host key's SHA-256 fingerprint (`SHA256:…`,
  as `ssh-keygen -l` prints it). Given, the server must present that key, or
  the channel answers a failure `host_key` with the key it did present.
  Empty, the channel takes the key the server presents and says it in the
  hello (`x.host_key`): the session shows it, and an operator pins it by
  filling it in on the target.
- **`proxy`**: `socks5://` or `socks5h://` (a pivot, an SSH dynamic forward),
  or `http://` (CONNECT).

### Logging in

With the target's credentials, in its order, a connection each, until one is
taken:

- a `KEY` by its key: OpenSSH or PEM, with its passphrase. A key whose line
  breaks a paste lost is made a block again; a public key or a PuTTY `.ppk`
  is refused, saying so (and how to convert the `.ppk`);
- a `PLAINTEXT` by its password, as a password and answering
  keyboard-interactive.

Each logs in as its username (a `PLAINTEXT`'s with a realm as
`username@realm`), or as the target's `user` when it has none. A refusal goes
on to the next; a failure that is not one (unreachable, another host key, not
an SSH server) ends the call or open, as the next would meet it too. Every
answer says the [logins](https://logoscore.github.io/logos-docs/contracts/credentials/#logins)
tried: core marks the credential that was taken valid, and notes each on the
target. With every one refused, the channel answers a failure `login` naming
each.

## The hello

From one exec of `uname -snm; id -un; id -u` and an SFTP read (a Windows
server's [below](#windows-servers)):

- `os` and `arch` from `uname`, in Go's names (`Linux` `linux`, `x86_64`
  `amd64`, `aarch64` `arm64`, `i686` `386`, `armv7l` `arm`); `host` the node
  name; `user` the login's; `integrity` `root` for uid 0, else `user`;
- the [machine id](https://logoscore.github.io/logos-docs/contracts/minion-messages/sessions/#machine-identity):
  `linux-machine-id` from `/etc/machine-id` (else
  `/var/lib/dbus/machine-id`), so a Linux machine BOB's minion reaches too is
  one machine in the file browser; else `ssh-host-key`, the SHA-256 of the
  server's host key in hex (core lowercases a machine id, which base64 would
  not survive);
- `pid` 0: it has no process of its own on the server; `version`
  `logos-ssh/<version>`; `max_tasks` 4;
- `x`: `ssh_server`, the version string the server sent
  (`SSH-2.0-OpenSSH_9.6p1 …`), and `host_key`.

## Build schema

Build schema version 3, its own version 1:

- **`crypto`** `aes-256-cbc-hmac-sha256`, as any factory's. No build fields,
  and none of `persisted_sessions`, `failover`, `max_tasks`, `compression`,
  `minion_config` or `error_codes`. No `max_tasks`: a minion that keeps
  nothing between calls could not keep a limit core sets; a call brings 4
  tasks at most, and a persistent connection runs 4 at once, as the hello
  says ([Max tasks](https://logoscore.github.io/logos-docs/contracts/minion-messages/tasks-and-results/#max-tasks)).
- **One target**, `ssh` ("SSH server"), format `json`, platform `any/any`.
- **One channel**, `ssh` (num 1, connection schema version 1), with
  `bind-call` and `bind-persistent`, and no connection parameters of the
  factory's.
- **Commands** with BOB's ids, params and actions, so core's actions, the
  file browser and the console work with them as they do with BOB's (the
  `op` numbers are this factory's own, `internal/ops`), and two of its own,
  `become` and `unbecome`. All are `default`; none is `required`:

| Command (`op`) | Params | Action, result | Over SSH |
|---|---|---|---|
| `shell` (1) | `command`, `timeout` (`30s`) | | The command line in `/bin/sh`, in an exec channel (as BOB's minion runs it on Unix): its output and exit status. A stop kills its process group, what it started too. After a [become](#become), in the shell it elevated |
| `ls` (2) | `path` (`.`: the login's home) | `list_dir`, `dir_listing` | An SFTP directory read |
| `walk` (3) | `path`, `depth` (5), `max_folders` (10000), `hidden` (yes), `one_fs` (yes) | `walk_dir`, `dir_walk` | SFTP directory reads, links not followed: breadth first on a persistent connection; in calls depth first, going on from its `ctx`. `one_fs` by the server's mount table (`/proc/self/mounts`, else `df`), as SFTP says no file systems |
| `download` (4) | `path` | `download_file`, `file_download` | SFTP reads, a chunk a message |
| `stream_download` (5) | `path` | `stream_file`, `file_stream` | SFTP reads, as the downloader takes them |
| `upload` (6) | `file`, `path`, `overwrite` | `upload_file`, `file_upload` | SFTP writes |
| `stream_upload` (7) | `stream`, `path`, `overwrite` | `upload_stream`, `file_upload` | SFTP writes, as the bytes come |
| `rm` (8) | `path`, `recursive` | `delete_path` | SFTP removes, as BOB's `rm`: a link as itself, never a file system's root |
| `volumes` (9) | | `list_volumes`, `volumes` | `df -kPT` (GNU's, with types), else `df -kP` |
| `become` (10) | `user` (`root`), `method` (`sudo`), `password` | | [Become](#become) |
| `unbecome` (11) | | | Shell commands run as the login again: the elevated shell closes |
| `tunnel` (12) | `timeout` (`10s`), `max_streams` (256) | `tunnel` | [Tunnels](#tunnels): SOCKS, HTTP proxy, forward, terminal and VPN (TCP) fronts |
| `reverse_tunnel` (13) | `bind` (`0.0.0.0`), `listen`, `timeout` (`10s`), `max_streams` (256) | `reverse_tunnel` | [Tunnels](#tunnels): the server listens (a remote forward), TCP only |

On a [Windows server](#windows-servers) each does as Windows's OpenSSH lets
it.

A build takes seconds: `describe`, then `upload`. Its file,
`ssh-<first 8 of the build id>.json`, says what the build has: its id, its
commands, its connections (each one's kind and endpoint). There is nothing to
deploy and nothing secret in it.

## Become

To core, `become` and `unbecome` are commands like any other: it learns who
the session runs as from the minion's
[`identity`](https://logoscore.github.io/logos-docs/contracts/minion-messages/identity/)
items. The rest is the channel's. An SSH connection stays its login's: every
channel sshd opens on it runs as the login. So a become keeps a shell
elevated on the connection, started once by sudo or su, and the minion types
shell commands into it, as a person types into the shell `sudo su` gave them.

- **The params**: `user` (`root` by default; a name, or `#uid` through sudo),
  `method`, and `password`, a `PLAINTEXT` credential given only when the
  server asks for one:

  | `method` | Starts the shell with | The password the server may ask |
  |---|---|---|
  | `sudo` (the default) | `sudo -u <user>` | sudo's: `password`, else the login's own (a key's login has none) |
  | `sudo-su` | `sudo su <user>`, for sudoers that allow only su | the same |
  | `su` | `su <user>`, in a terminal `script(1)` makes on the server (su reads a password only from one) | the user's: `password`, needed unless the login is root |

- **Elevating** runs the method in an exec channel of the login's, gives the
  password at sudo's or su's prompt, once (asked again, it was refused), and
  takes the shell's first words, `id -u` and `id -un`, as who it became.
  Sudoers that require a terminal get one of `script(1)`'s. It takes 15
  seconds at most, the prompt and the password included.
- **The task's answer** says who the shell runs as and what still runs as
  the login (`root (uid 0), through sudo: shell commands run as root until
  unbecome. File commands still run as alice.`), with what sudo said that is
  not a prompt (a warning). A become that fails says why (`become: sudo
  refused the password (the login's)`) and changes nothing.
- **The identity**: a become that worked says the session's (scope 1): `how`
  become, `user` as `id -un` says, `integrity` `root` for uid 0 (else
  `user`), `task` the become's, and `credential` its `password` when the
  server asked for it and took it (core marks it valid). An `unbecome` says
  the process's own (scope 1, no `how`), naming its task, and the elevated
  shell closes once what runs in it ends. The hello stays the login's.
- **Only `shell` becomes.** The file commands go over the login's SFTP, and
  `volumes` runs as the login. While the session runs as another user, each
  of their tasks says so: an `identity` of its own (scope 2, no `how`) before
  its ack.
- **A shell command in the elevated shell** goes in as one line: in a
  subshell in the background, in a process group of its own (`setsid`),
  stdin `/dev/null`, stderr into stdout, between markers random to the
  connection. Its output and exit status come as without a become. Shell
  commands take turns in it (one shell a connection), so a long one holds the
  next. A stop is another line to the shell: a `kill` of the command's
  process group as the user it became, which the login could not do. A
  command that outlives the kill by 5 seconds takes the shell with it.
- **A become while elevated** goes on inside the shell: sudo or su started
  from it, so su from root asks nothing. One that fails leaves the shell as
  it was. The shell it started from waits under the new one: should the new
  one end (killed, say), that one takes no command as its own user, but
  exits, and the next command goes to a shell elevated again. When the become
  in effect does not elevate on the connection, a new one goes from the
  login, as with none in effect.
- **In order.** In a call the tasks run one after another, so a shell after a
  become runs as its user. On a persistent connection the minion runs its
  tasks at once, but a shell waits for the becomes and unbecomes before it,
  and a become for the shells before it to have what they run in. The minion
  acks in the order it took the tasks, the identity between
  ([Message order](https://logoscore.github.io/logos-docs/contracts/minion-messages/identity/#message-order)),
  and a shell acked before a become it waited for says who it ran as (scope
  2).
- **Each connection elevates again.** The elevated shell lives as long as its
  connection: a call's, kept for `call_reuse`, or a persistent one. A new
  connection takes up core's
  [acting task](https://logoscore.github.io/logos-docs/contracts/agentless-channels/#the-acting-task):
  a become, elevated as it says at the first shell command, or none, and
  shell commands run as the login. A call that reuses a connection keeps its
  shell.
- **Elevating again can fail.** Core gives the last become alone, so one made
  from another (su from root, which asked nothing) is made again from the
  login; a password that worked may no longer. Shell commands then fail
  rather than run as the login, and the minion tells its operators, once a
  connection: a [feedback](https://logoscore.github.io/logos-docs/contracts/minion-messages/sessions/#feedback)
  error, `become_failed`. A become (from the login, as above) or an
  `unbecome` gets the session past it.
- **Unix servers only**: a [Windows server](#windows-servers) has no sudo or
  su, and a become fails saying so.

## Tunnels

The channel runs core's
[tunnel items](https://logoscore.github.io/logos-docs/contracts/minion-messages/tunnels/)
itself (its own copy of BOB's minion's engine: minions share the protocol, not
their insides), and each stream goes over the session's own SSH connection,
as `ssh -L`, `-D` and `-R` do. Core's fronts (SOCKS, HTTP proxy, forward,
terminal, VPN) work as they do with BOB's minion.

- **Over `bind-persistent` only** (the commands' `kinds`): a tunnel lives as
  long as the connection it goes over, and a call's connection lives a call.
  A tunnel task in a call fails, saying so.
- **One connection**: every stream is a channel on the session's SSH
  connection, so nothing else logs in. The tunnel tasks run beside the
  others, not counted against the 4 at once.
- **As the login**: a [become](#become) elevates shell tasks only. A
  terminal is the login's shell, and a forward is sshd's, as its
  `AllowTcpForwarding`, `PermitOpen` and `GatewayPorts` allow.
- **Side messages**: the session sends its own messages one at a time, each
  waiting for core's reply, but meanwhile the streams' items go in side
  messages of their own, as many as there is to send (the streams' windows
  bound the bytes), gathering what comes over 5 ms: a server's bytes never
  wait for a reply to another message, which a channel far from core would
  feel. They go once core answered the hello, under the session's id, and
  carry no ack, result or `get_tasks`; one whose reply never comes needs
  nothing back, as the streams send again from their acks.
- **They end with the connection**: when the channel's connection to core
  drops, or the SSH connection does, every stream and listener closes. Core
  then gets `unknown_task` for the tunnel tasks, as it does for any task that
  ran in a connection that went, and ends them.
- **The params**: `timeout` (More options) is how long the server tries to
  connect to a destination, with every front but `terminal`, which connects
  to nothing; `max_streams` (1 to 4096) how many connections the tunnel
  carries at once. A `reverse_tunnel`'s `bind` and `listen` (0 for any free
  port; one under 1024 needs a root login) say where the server listens. It
  opens TCP alone, so it has no `udp` param.

What each open is over SSH (the `tunnel` command's `opens`: `tcp`, `unix`,
`tls`, `process`, `accept`; the `reverse_tunnel` command's: `tcp`):

| Open | Over SSH |
|---|---|
| TCP (SOCKS, HTTP proxy, forward, the VPN front's TCP) | A `direct-tcpip` channel: the server connects; TLS on top is the channel's, as BOB's minion's is its own |
| Unix socket | OpenSSH's `direct-streamlocal@openssh.com` (its `AllowStreamLocalForwarding`); a socket it cannot open is `failed`, OpenSSH saying no more than "open failed" |
| Process (the terminal front) | A session of its own: a pty of the open's size (`pty-req`, `window-change`) when the server gives one, else pipes; the program and args, or the login's shell (`$SHELL -l`); its exit status, as a `tunnel_ctl` |
| Accept (SOCKS5 `BIND`) | A remote forward (`tcpip-forward`) for one connection |
| Reverse tunnel | A remote forward (`tcpip-forward`); each connection, a `forwarded-tcpip` channel. On the server's loopback unless its `GatewayPorts` allows the bind address |
| UDP, ICMP, a named pipe, a source address | `unsupported`: SSH carries none of them; the commands do not say they open them, so core does not send them |

A stream's `eof` and `tunnel_close` are SSH's EOF and close on its channel.

A terminal's signals: `interrupt` is Ctrl-C (`0x03`) written into the pty, as
a key pressed (on pipes, `SIGINT` to the session). `terminate` and `kill` go
to the whole session through a session of their own (`pkill -s`, else the
process group, as a shell task's stop), and `kill` ends the channel too.

What a server refuses comes back as the result its words say: `denied` for
"administratively prohibited" (forwarding off, `PermitOpen`) and for a
refused remote forward, `unsupported` for an unknown channel type, and for a
connect that failed OpenSSH's words: `refused`, `net unreachable`, `host
unreachable` (for a name it does not find, or a host that does not answer),
`timed out`, `not found` (no such file), `denied` (permission denied).
Anything else is `failed`, with the server's words. A connect that takes
longer than the task's `timeout` is `timed out` on the channel's side.

## Windows servers

Windows's OpenSSH (Win32-OpenSSH) is served as BOB's minion runs on Windows:
the same commands, with the paths, results and stops it gives there.

- **Telling one**: the server's version says so (`OpenSSH_for_Windows`), or
  its SFTP says a drive's folders (`/C:/Users/me`). Paths follow what SFTP
  says; the shell, the hello and the volumes follow the server.
- **Paths** are Windows's (`C:\Users\me`, `\\server\share\x`), which core's
  file browser tells apart whatever their case: `/` read as `\`, a drive
  alone its root (`C:` is `C:\`), `\x` on the login's drive, and the rest
  from the login's folder. Each SFTP call takes its path in SFTP's form
  (`/C:/Users/me`). The drive letter is upper case; the rest is kept as
  typed.
- **Listings**: Windows's SFTP says no owners, modes of its own making, and a
  junction (`Application Data`, `Documents and Settings`) as the folder it
  points to, which it follows. Each listing therefore also asks cmd's `dir`
  of the folder, in UTF-8 (`chcp 65001`), beside the SFTP read. The entries'
  modes are their attributes (read-only, hidden, system, archive, reparse
  point), as BOB's minion sends them and core shows them (`-a-h--`). A hidden
  attribute makes an entry hidden, as a leading dot does. A junction is a
  link to its target, which walks do not enter. A folder whose path names a
  variable (`%TEMP%`, which cmd would expand) lists without them. `one_fs`
  walks keep to a drive.
- **Removing** goes as Go's `os.RemoveAll` on Windows: a junction or a link
  as itself, never what it points to; a read-only file's attribute cleared
  first. A folder whose junctions cmd cannot tell apart is not removed
  through.
- **`shell`**: the line as typed, in the server's default shell. Windows's
  OpenSSH runs `cmd.exe /c "<line>"`, which reads a line as BOB's minion's
  `cmd.exe /d /s /c` does, unless its `DefaultShell` names another. The
  output is as the console's code page writes it. A stop is a `KILL` signal,
  on which Windows's OpenSSH ends the command and all it started; closing the
  channel alone would leave them running, past the connection too.
- **The hello**, from one PowerShell script (`-EncodedCommand`, within what
  constrained language mode allows, each value said as hex of its UTF-16,
  whatever the console's code page): `os` `windows`; `arch` the machine's
  (`AMD64` `amd64`, `ARM64` `arm64`, `x86` `386`); `host` its host name;
  `user` `DOMAIN\user`; `domain` the domain it is joined to (its DNS name) or
  its workgroup; `integrity` from the login's mandatory label
  (`whoami /groups`), as BOB's minion reads its token's: `low`, `medium`,
  `high`, `system`. The machine id is BOB's minion's on Windows:
  `smbios-uuid` (`Win32_ComputerSystemProduct`), else `win-machine-guid` (the
  registry's `MachineGuid`), else `ssh-host-key`. Where PowerShell does not
  run, cmd says what it can: the host, the architecture, `whoami`, the
  `MachineGuid`, the label.
- **`volumes`** are the drives (`Win32_LogicalDisk`): each one's kind by its
  drive type, label, file system, size and free space, a network drive's
  share, and an empty drive (a DVD drive with nothing in it) with no media.
  Where PowerShell does not run, they are the drives SFTP's root lists, with
  the space `statvfs@openssh.com` says.
- **Tunnels** (checked against Windows's OpenSSH 9.5): a terminal is a ConPTY
  (`cmd.exe`, or the server's default shell), `interrupt` a Ctrl-C written
  into it (on pipes there is none); `terminate` and `kill` are SSH's `KILL`
  signal, which ends the process tree. Its terminals say exit 0 whatever
  their shell exits with (on pipes the code comes through). A port that
  refuses the connection opens after about 2 s and ends at once (Windows
  retries the connect), and a unix socket's forward fails.
- **No `become`**: see [Become](#become).

## Config

The channel (`internal/config`): `CHANNEL_ID` (`ssh-local`),
`LOGOS_CORE_BASE_URL` (`http://localhost:8002`; and, over HTTPS to a
self-signed core, `LOGOS_CORE_CA_FILE`, `LOGOS_CORE_CERT_SHA256` or
`LOGOS_CORE_TLS_INSECURE`:
[How modules reach core](https://logoscore.github.io/logos-docs/core-infrastructure/#how-modules-reach-core)), `MAX_CONNECTIONS` (persistent ones, 1000),
`CALL_TIMEOUT` (2m, 1s to 10m: how long a call may take, its login and its
tasks; core's deadline, 2 minutes, wins when shorter), `LOG_FORMAT` (`json`,
`text`), `RABBITMQ_*` (`RABBITMQ_HOST` `localhost`, `RABBITMQ_PORT` `5672`,
`RABBITMQ_USER` `logos`, `RABBITMQ_VHOST` `/`; `RABBITMQ_PASSWORD`, logos-core's
`RABBITMQ_DEFAULT_PASS`, has no default and is required). The factory: `FACTORY_ID`
(`ssh-factory-local`), `LOGOS_CORE_BASE_URL` (the channel's, with the same
TLS settings: builds upload their description to core), `LOG_FORMAT`,
`RABBITMQ_*` (the channel's defaults, the password required).

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

It logs no credential and nothing of a message's contents: a call's line says
its request id, the server, the outcome and how long it took, and what the
minion does with each task (its id, its command's number, sizes) is logged at
`debug`.

## Development

```bash
go build ./... && go vet ./... && go test -race ./...
golangci-lint run ./...
docker compose up -d --build
```

- **The dev stack**: `docker-compose.yml` runs both programs from one image on
  logos-core's network (`logos-core_logos`), reaching core at
  `http://logos-core-dev:8002` and RabbitMQ at `logos-rabbitmq`: start
  logos-core first (`make services` there), and set `RABBITMQ_PASSWORD`
  (core's `RABBITMQ_DEFAULT_PASS`) in `.env`. An SSH server on this machine
  is reached as `host.docker.internal`: add a target with that host.
- **Go 1.25.7**: dependencies stay on versions that build with Go 1.25
  (`x/crypto` v0.55.0 and `x/net` v0.58.0 are the last that do).
- **The tests** log in to an SSH server in the test's own process
  (`internal/sshtest`: password and key logins, `/bin/sh` commands in process
  groups of their own, SFTP, forwards (`direct-tcpip`, `direct-streamlocal`,
  `tcpip-forward`) and, on Linux, terminals (`pty-req`, `window-change`);
  `NewWindows` answers as Windows's OpenSSH does: its version, SFTP with `C:`
  at its root and a link to a folder read as a junction, commands a test's
  `Exec` answers, stopped by a signal), so they need no server and run on
  Unix. Nothing here runs a real Windows server: check Windows changes
  against one by hand. The tests also check every item the minion sends with
  the protocol's own validators, the ones core checks with (`checkItems` in
  `internal/agent`): core refuses what they refuse.
- **CI** (`.github/workflows/ci.yml`) runs the tests and golangci-lint
  v2.13.2 (its default linters, no configuration, kept at 0 issues) on pushes
  to `main`, `v*` tags and pull requests; a `v*` tag publishes the image
  (`docker-image.yml`).
- **An unreleased protocol or channel-core**: the image builds from the
  tagged modules alone (`.dockerignore` keeps a workspace out), so until they
  are tagged a git-excluded `go.work` wires the checkouts, side by side:

  ```
  go 1.25.7

  use (
  	.
  	../logos-golang-protocol
  	../logos-golang-channel-core
  )
  ```

  and the dev stack runs binaries built on the host,

  ```bash
  CGO_ENABLED=0 GOOS=linux go build -o .dev-bin/ssh-channel ./cmd/ssh-channel
  CGO_ENABLED=0 GOOS=linux go build -o .dev-bin/ssh-factory ./cmd/ssh-factory
  ```

  which a git-excluded `docker-compose.override.yml` mounts as the image's
  programs (`/app/ssh-channel`, `/app/ssh-factory`). Then
  `docker compose up -d`, without `--build`; after each change, build again
  and `docker compose restart`. Drop all three at release, once the tags are
  in `go.mod`.

## Open questions

- **A schedule** for SSH targets: periodic logins that show a server is still
  there.
- **Jump hosts**: a target reached through another.

## Design notes

Why the channel acts as the minion, why keys rather than a suite of no
crypto, and why it still has a factory are the docs'
[Agentless Channels, Design notes](https://logoscore.github.io/logos-docs/contracts/agentless-channels/#design-notes).

- **Why the SSH minion is its own.** Minions share the protocol and its
  contracts (`logos-golang-protocol`), not their workings: BOB's minion, the
  Dumbo page and this channel's minion each run their tasks their own way,
  and none waits on another's changes. The SSH minion takes its ways from
  BOB's (a persistent connection: `Runner`) and the Dumbo page's (calls:
  `Caller`), and keeps them here, in `internal/minion`.
- **Why ask cmd of a Windows listing.** SFTP says a junction as the folder it
  points to, and follows it: a walk would loop through one that points above
  it (`AppData\Local\Application Data` is `AppData\Local`), and a removal
  would reach through one into what it points to. Only Windows itself says
  which entries are junctions, with the attributes beside them. `dir` says
  both in one exec, beside the SFTP read: a few tens of milliseconds a
  folder. PowerShell would say them too, but it takes ten times that to
  start.
- **Why the host key as a machine id.** An SSH server's host key is what
  identifies it before any login, and reading it runs nothing. The machine
  id file comes first, so that a machine reached both by a minion and over
  SSH is one machine in the file browser.
