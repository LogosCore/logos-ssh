package minion

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// Becoming another user (docs: contracts/agentless-channels/, SSH: become):
// a host whose shell commands can run as another user, through sudo or su,
// in shells it keeps elevated on its connection (sshhost, on a Unix
// server). The become command elevates the session: shell commands from
// then on run as the user, until unbecome. The other commands (files,
// volumes) still run as the login, and each such task says so (an identity
// of its own, the process's). The minion says each change of the session's
// as an identity (protocol.IdentityItem, scope session), naming the task
// that made it; core hands that task back with every call and open
// (protocol.LinkActing), so a connection that comes later elevates again.
//
// Core takes a task to run as the session's identity when it is acked, in
// message order, so the minion acks the tasks before a change ahead of it.
// Its tasks run at once, but a shell task waits for the becomes before it
// (the Runner's lane), and a become for the shells before it to hold what
// they run in; a shell that ran as another than its ack said (a become
// before it ended after the ack) says who, as an identity of its own.

// Become is how to elevate: who to become, how, and the password to give.
type Become struct {
	// Task is the become task that asked for it.
	Task []byte
	// User is who to become: a name, or #uid through sudo.
	User string
	// Method is BecomeSudo, BecomeSudoSu or BecomeSu.
	Method string
	// Password is the password to give when the server asks: sudo's (the
	// login's own, unless the task gives one), su's (the user's).
	// Credential is the id of the task's credential it came from: "" when
	// the task gave none.
	Password   string
	Credential string
}

// The ways to become another user.
const (
	// BecomeSudo: sudo runs the user's shell (sudo -u user).
	BecomeSudo = "sudo"
	// BecomeSudoSu: sudo runs su to the user, for sudoers that allow only
	// su.
	BecomeSudoSu = "sudo-su"
	// BecomeSu: su, with the user's password, in a terminal of its own.
	BecomeSu = "su"
)

// Same reports whether o elevates as b does: the same task's, user, way and
// password.
func (b Become) Same(o Become) bool {
	return string(b.Task) == string(o.Task) && b.User == o.User && b.Method == o.Method && b.Password == o.Password &&
		b.Credential == o.Credential
}

// MethodLabel is how the method reads to people: "sudo", "sudo su", "su".
func (b Become) MethodLabel() string { return strings.ReplaceAll(b.Method, "-", " ") }

// Became is what an elevation came to.
type Became struct {
	// User is who the shell runs as, as id -un says; UID its uid.
	User string
	UID  int64
	// PasswordUsed: the server asked for the password and took it.
	PasswordUsed bool
	// Notes are what sudo or su said on the way that is not a prompt (a
	// warning).
	Notes string
}

// Ran is who a command ran as through a become: the become task that made
// the shell it ran in, and the user, as id says.
type Ran struct {
	Task []byte
	User string
	UID  int64
}

// Becomer is a host whose shell commands can run as another user.
type Becomer interface {
	// Become elevates now, on the host's connection: shell commands after
	// it run as b.User, until Unbecome or another Become. One that fails
	// leaves the session as it was.
	Become(ctx context.Context, b Become) (Became, error)
	// Unbecome: shell commands run as the login again.
	Unbecome()
	// Acting is the become in effect; nil for none.
	Acting() *Become
	// Login is who the host logged in as: whom the commands that do not
	// become run as.
	Login() string
	// BecomeFailure is why shell commands cannot run as the acting user on
	// this connection (the become worked once, and elevating again failed),
	// and whether this is the first time it is asked: the minion tells its
	// operators once.
	BecomeFailure() (string, bool)
}

// ErrBecome is what a host's Shell error wraps when the command could not
// run as the acting user: its message says why ("become: sudo refused the
// password").
var ErrBecome = errors.New("become")

// Become's params, by number (num).
const (
	ArgBecomeUser     = 1
	ArgBecomeMethod   = 2
	ArgBecomePassword = 3
)

// becomeUser is a user name a become takes: POSIX's portable characters,
// not starting with "-"; or #uid, through sudo.
var (
	becomeUser = regexp.MustCompile(`^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,31}\$?$`)
	becomeUID  = regexp.MustCompile(`^#[0-9]{1,10}$`)
)

// BecomeArgs reads a become task's args: the user (root unless they say),
// the method (sudo unless they say) and the password's credential, if any.
func BecomeArgs(task []byte, args protocol.Args) (Become, error) {
	b := Become{Task: task, User: "root", Method: BecomeSudo}
	if u, ok := protocol.ArgString(args, ArgBecomeUser); ok && u != "" {
		b.User = u
	}
	if m, ok := protocol.ArgString(args, ArgBecomeMethod); ok && m != "" {
		b.Method = m
	}
	switch b.Method {
	case BecomeSudo, BecomeSudoSu, BecomeSu:
	default:
		return Become{}, fmt.Errorf("become: no method %q: sudo, sudo-su or su", b.Method)
	}
	switch {
	case becomeUID.MatchString(b.User) && b.Method != BecomeSudo:
		return Become{}, fmt.Errorf("become: %s takes a user's name, not a uid", b.MethodLabel())
	case !becomeUser.MatchString(b.User) && !becomeUID.MatchString(b.User):
		return Become{}, fmt.Errorf("become: %q is not a user name", b.User)
	}
	c, err := protocol.ArgCredential(args, ArgBecomePassword)
	if err != nil {
		return Become{}, fmt.Errorf("become: the password: %w", err)
	}
	if c != nil {
		b.Password, b.Credential = c.Password, c.ID
	}
	return b, nil
}

// integrityOfUID is the integrity a Unix uid runs at: root, or a user.
func integrityOfUID(uid int64) int {
	if uid == 0 {
		return protocol.IntegrityRoot
	}
	return protocol.IntegrityUser
}

// becameIdentity is the session's identity after an elevation: the user it
// runs as, how, and the credential when its password was asked for and
// taken.
func becameIdentity(b Become, got Became) protocol.IdentityItem {
	it := protocol.IdentityItem{T: protocol.ItemIdentity, Scope: protocol.IdentitySession, Task: b.Task, User: got.User,
		Integrity: integrityOfUID(got.UID), How: protocol.IdentityBecome}
	if got.PasswordUsed && b.Credential != "" {
		it.Credential = b.Credential
	}
	return it
}

// ownIdentity says the process's own: for the session (an unbecome, the
// task that made it), or for one task (a command that does not become).
func ownIdentity(scope int, task []byte) protocol.IdentityItem {
	return protocol.IdentityItem{T: protocol.ItemIdentity, Scope: scope, Task: task}
}

// ranIdentity is one task's identity: who its command ran as (nil: the
// process's own).
func ranIdentity(task []byte, as *Ran) protocol.IdentityItem {
	if as == nil {
		return ownIdentity(protocol.IdentityTask, task)
	}
	return protocol.IdentityItem{T: protocol.ItemIdentity, Scope: protocol.IdentityTask, Task: task, User: as.User,
		Integrity: integrityOfUID(as.UID), How: protocol.IdentityBecome}
}

// ranAsSaid reports whether a command that ran as as (nil: the login) ran
// as core takes it to: as the session's identity said when its task was
// acked (said: the task that made it, nil the process's own).
func ranAsSaid(as *Ran, said []byte) bool {
	if as == nil {
		return said == nil
	}
	return said != nil && bytes.Equal(as.Task, said)
}

// ActingTask is the task that made the session's acting identity, as core
// gives it with a call or an open (nil: none).
func ActingTask(a *protocol.LinkActing) []byte {
	if a == nil {
		return nil
	}
	return a.Task
}

// becameText is what a become task answers: who it is now, how, and what
// still runs as the login.
func becameText(b Become, got Became, login string) string {
	s := fmt.Sprintf("%s (uid %d), through %s: shell commands run as %s until unbecome. File commands still run as %s.\n",
		got.User, got.UID, b.MethodLabel(), got.User, login)
	if got.Notes != "" {
		s += "\n" + got.Notes + "\n"
	}
	return s
}

// becomes reports whether a command runs as the acting user when one is in
// effect: only the shell does (the rest go over the login's SFTP).
func becomes(c Command) bool { return c == CmdShell }
