// Package minion is the SSH channel's minion: what it does with core's
// messages for each server it acts as (docs: contracts/agentless-channels/).
// It is the SSH minion's own, as BOB's minion and the Dumbo page have their
// own: minions share the protocol (logos-golang-protocol), not their inner
// workings.
//
// A Runner serves a bind-persistent connection, the way a listening minion
// does: it takes core's items (tasks, cancels, chunks, acks, a rehello),
// runs each task once, on a goroutine of its own, and forms the next message
// within the connection's size. A Caller answers a bind-call connection's
// calls, the way the Dumbo page does: each call's tasks run in it, and what a
// walk or a file transfer needs to go on travels in its ctx, which core
// echoes.
//
// Both act on a Host: the server, over SSH and SFTP, or in tests the test's
// own machine.
package minion
