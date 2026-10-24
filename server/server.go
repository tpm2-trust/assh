// Package server is an SSH server split in two: this side holds the host
// key and gets each login's interactive session; the side that speaks SSH
// runs without privileges and holds neither (child.go).
//
// A program that uses it starts the server with Start and, when it is
// started again as Options.Command says, runs ChildMain: one program, two
// processes.
package server

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// nobody is who the unprivileged half runs as by default: owning no file.
const nobody = 65534

// namespaces are the namespaces the unprivileged half gets of its own: no
// network but the socket it is handed, no other process to see.
const namespaces = syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWPID |
	syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS

// Options are a server's settings.
type Options struct {
	// Listener is the port, taken over: the server keeps no copy, so the
	// port closes when the unprivileged half ends.
	Listener *net.TCPListener
	// HostKey signs the key exchanges. It stays in this process.
	HostKey ssh.Signer
	// AuthorizedKeys are the keys that may log in, one authorized_keys
	// line each (ParseAuthorizedKeys).
	AuthorizedKeys []string
	// Command is the unprivileged half: this program, started so that it
	// runs ChildMain. Without an environment it gets PATH=/usr/bin alone.
	Command func() *exec.Cmd
	// Session gets each login's shell. It is called in the order the
	// logins come, from the server's own goroutine: hand the session on
	// and return.
	Session func(*Session)
	// Log gets what the server and its unprivileged half report.
	Log func(string)
	// Version is the server's SSH version string; default "SSH-2.0-assh".
	Version string
	// Name and Notice are what a client is told that asks for a command:
	// "Name: Notice". Defaults: "assh", "only an interactive session is
	// served here (ssh without a command)".
	Name   string
	Notice string
	// UID runs the unprivileged half when the server runs as root;
	// default 65534 (nobody).
	UID uint32
}

// Session is a login's interactive session: what is typed comes in, what
// is written goes to the client's terminal. Closing it ends the session.
type Session struct {
	net.Conn
	User   string // the login name the client gave
	Key    string // the SHA256 fingerprint of the key it logged in with
	Remote string // its address
	Term   string // the terminal's TERM, "" when the client asked for none
	Cols   int
	Rows   int

	resize chan [2]int
}

// String is who logged in, for a log.
func (s *Session) String() string {
	return fmt.Sprintf("%s from %s, key %s", s.User, s.Remote, s.Key)
}

// Resized gives the terminal's new size, columns and rows, each time the
// client's window changes; only the latest is kept.
func (s *Session) Resized() <-chan [2]int { return s.resize }

// Server is a running server.
type Server struct {
	cmd    *exec.Cmd
	ctl    *conn
	exited chan struct{}
	signer ssh.Signer
	opts   Options

	mu       sync.Mutex
	sessions map[uint64]*Session

	// How is what the unprivileged half runs with, for the log.
	How string
}

// Pid is the unprivileged half's process.
func (s *Server) Pid() int { return s.cmd.Process.Pid }

// Exited is closed when the unprivileged half has ended.
func (s *Server) Exited() <-chan struct{} { return s.exited }

// ParseAuthorizedKeys are the keys of an authorized_keys file that may
// log in, one per line as the file has them, and how many lines were left
// out: a line with options in front of the key (from="...",
// command="...") is not honoured by this server, so it does not let
// anyone in either.
func ParseAuthorizedKeys(data []byte) ([]string, int) {
	var out []string
	skipped := 0
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		_, _, opts, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err != nil || len(opts) > 0 {
			skipped++
			continue
		}
		out = append(out, l)
	}
	return out, skipped
}

// Start starts the unprivileged half on the listener. As root it runs as
// Options.UID in namespaces of its own (without them where the kernel
// cannot); run as another user it runs as that user. Start returns when
// it is ready.
func Start(o Options) (*Server, error) {
	if o.Listener == nil || o.HostKey == nil || o.Command == nil || o.Session == nil {
		return nil, errors.New("a server needs a listener, a host key, a command and a session handler")
	}
	if o.Log == nil {
		o.Log = func(string) {}
	}
	if o.Version == "" {
		o.Version = "SSH-2.0-assh"
	}
	if o.Name == "" {
		o.Name = "assh"
	}
	if o.Notice == "" {
		o.Notice = "only an interactive session is served here (ssh without a command)"
	}
	if o.UID == 0 {
		o.UID = nobody
	}
	lf, err := o.Listener.File()
	o.Listener.Close()
	if err != nil {
		return nil, err
	}
	defer lf.Close()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	mine, theirs := os.NewFile(uintptr(fds[0]), "control"), os.NewFile(uintptr(fds[1]), "control")
	defer theirs.Close()
	c, err := net.FileConn(mine)
	mine.Close()
	if err != nil {
		return nil, err
	}
	ctl := &conn{c: c.(*net.UnixConn)}

	build := func(ns bool) *exec.Cmd {
		cmd := o.Command()
		if cmd.Env == nil {
			cmd.Env = []string{"PATH=/usr/bin"}
		}
		if cmd.Stderr == nil {
			cmd.Stderr = os.Stderr // a panic, for the log
		}
		cmd.ExtraFiles = []*os.File{lf, theirs} // childListenFD, childControlFD
		attr := &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGKILL}
		if os.Geteuid() == 0 {
			attr.Credential = &syscall.Credential{Uid: o.UID, Gid: o.UID, Groups: []uint32{}}
			if ns {
				attr.Cloneflags = namespaces
			}
		}
		cmd.SysProcAttr = attr
		return cmd
	}
	cmd := build(true)
	if err := cmd.Start(); err != nil && os.Geteuid() == 0 {
		// A kernel without one of the namespaces: the other user and
		// Landlock still hold.
		o.Log("the unprivileged half runs without namespaces of its own: " + err.Error())
		cmd = build(false)
		if err := cmd.Start(); err != nil {
			c.Close()
			return nil, err
		}
	} else if err != nil {
		c.Close()
		return nil, err
	}
	s := &Server{cmd: cmd, ctl: ctl, exited: make(chan struct{}), signer: o.HostKey, opts: o,
		sessions: map[uint64]*Session{}}
	go func() {
		cmd.Wait()
		close(s.exited)
	}()

	ready := make(chan string, 1)
	go s.serve(ready)
	init := msg{T: "init", HostKey: o.HostKey.PublicKey().Marshal(), AuthorizedKeys: o.AuthorizedKeys,
		Version: o.Version, Name: o.Name, Notice: o.Notice}
	if ms, ok := o.HostKey.(ssh.MultiAlgorithmSigner); ok {
		init.Algorithms = ms.Algorithms()
	} else {
		init.Algorithms = []string{o.HostKey.PublicKey().Type()}
	}
	if err := ctl.send(init, -1); err != nil {
		s.Stop()
		return nil, err
	}
	select {
	case s.How = <-ready:
		return s, nil
	case <-s.exited:
		c.Close()
		return nil, errors.New("the unprivileged half ended at its start")
	case <-time.After(10 * time.Second):
		s.Stop()
		return nil, errors.New("the unprivileged half did not start")
	}
}

// serve answers the unprivileged half: signatures, sessions, its lines for
// the log. The host key signs only while it runs.
func (s *Server) serve(ready chan<- string) {
	for {
		m, fd, err := s.ctl.recv()
		if err != nil {
			if fd >= 0 {
				unix.Close(fd)
			}
			return
		}
		switch m.T {
		case "ready":
			ready <- m.Text
		case "log":
			s.opts.Log(m.Text)
		case "sign":
			s.ctl.send(s.sign(m), -1)
		case "session":
			if fd < 0 {
				continue
			}
			f := os.NewFile(uintptr(fd), "session")
			c, err := net.FileConn(f)
			f.Close()
			fd = -1
			if err != nil {
				continue
			}
			sess := &Session{Conn: c, User: m.User, Key: m.Key, Remote: m.Remote, Term: m.Term,
				Cols: m.Cols, Rows: m.Rows, resize: make(chan [2]int, 1)}
			s.mu.Lock()
			s.sessions[m.ID] = sess
			s.mu.Unlock()
			s.opts.Session(sess)
		case "resize":
			s.mu.Lock()
			sess := s.sessions[m.ID]
			s.mu.Unlock()
			if sess != nil {
				select {
				case <-sess.resize: // only the latest
				default:
				}
				sess.resize <- [2]int{m.Cols, m.Rows}
			}
		case "ended":
			s.mu.Lock()
			delete(s.sessions, m.ID)
			s.mu.Unlock()
		}
		if fd >= 0 {
			unix.Close(fd)
		}
	}
}

// sign signs a key exchange in the algorithm negotiated.
func (s *Server) sign(m msg) msg {
	reply := msg{T: "signed", ID: m.ID}
	var sig *ssh.Signature
	var err error
	if as, ok := s.signer.(ssh.AlgorithmSigner); ok && m.Algorithm != "" {
		sig, err = as.SignWithAlgorithm(rand.Reader, m.Data, m.Algorithm)
	} else {
		sig, err = s.signer.Sign(rand.Reader, m.Data)
	}
	if err != nil {
		s.opts.Log("signing the key exchange: " + err.Error())
		reply.Err = err.Error()
	} else {
		reply.Format, reply.Data = sig.Format, sig.Blob
	}
	return reply
}

// Stop closes the control socket - the unprivileged half then stops
// accepting, lets its relays end and exits - and kills it if it has not
// ended in time.
func (s *Server) Stop() {
	s.ctl.c.Close()
	select {
	case <-s.exited:
	case <-time.After(3 * time.Second):
		s.cmd.Process.Kill()
		<-s.exited
	}
}
