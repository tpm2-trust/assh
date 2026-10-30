package server

// The unprivileged half: the process that speaks SSH.
//
// The server holds the host key (or the means to sign with it) and what a
// login leads to; it must not parse what arrives from the network before a
// login. So it opens the port and starts its own program again - led to
// ChildMain - handing it the listening socket and one end of a control
// socket. This process then gives up everything it does not need - it runs
// as a uid nobody else uses (or nobody), in network, IPC, PID, mount and
// UTS namespaces of its own, and takes from itself what package sandbox
// takes, on every thread: new privileges, being traced, executable memory,
// every file (Landlock), the system calls that administer the machine and
// make namespaces (seccomp) - and only then speaks SSH
// (golang.org/x/crypto/ssh).
//
// It holds no host key: the key exchange is signed by the server, asked
// over the control socket. It runs nothing: a login's shell becomes a
// session - one end of a socket pair, handed to the server with
// SCM_RIGHTS - and this process relays bytes between it and the SSH
// channel. A compromise of the SSH code here gets what a login gets, and
// no key.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/tpm2-trust/assh/sandbox"
)

// Limits of the unprivileged half: connections that have not logged in
// yet, how long they get for it, and sessions at once.
const (
	preAuthMax   = 8
	preAuthLimit = 30 * time.Second
	sessionMax   = 8
)

// ChildMain is the unprivileged half. The program that uses this package
// calls it when it is started as Options.Command starts it, and exits
// with what it returns.
func ChildMain() error {
	if os.Geteuid() == 0 {
		return errors.New("the SSH server's unprivileged half refuses to run as root")
	}
	f := os.NewFile(childControlFD, "control")
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("no control socket (the unprivileged half is started by the SSH server): %w", err)
	}
	ctl := &conn{c: c.(*net.UnixConn)}
	lf := os.NewFile(childListenFD, "listen")
	ln, err := net.FileListener(lf)
	lf.Close()
	if err != nil {
		return fmt.Errorf("no listening socket: %w", err)
	}
	confined, err := sandboxSelf()
	if err != nil {
		return fmt.Errorf("the unprivileged half cannot confine itself: %w", err)
	}

	init, fd, err := ctl.recv()
	if fd >= 0 {
		unix.Close(fd)
	}
	if err != nil || init.T != "init" {
		return fmt.Errorf("no init from the server: %v", err)
	}
	s, err := newChild(ctl, init)
	if err != nil {
		return err
	}
	ctl.send(msg{T: "ready", Text: confined}, -1)
	go s.control()
	s.accept(ln)
	return nil
}

// sandboxSelf takes what is left to take from this process (sandbox: no
// new privileges, no file, none of the administering system calls, on
// every thread) and describes what it runs with, for the log.
func sandboxSelf() (string, error) {
	desc := fmt.Sprintf("uid %d", os.Geteuid())
	if os.Getpid() == 1 {
		// The first process of its own PID namespace: the server asked
		// for network, IPC, PID, mount and UTS namespaces at once.
		desc += ", namespaces of its own"
	}
	confined, err := sandbox.Apply(sandbox.Policy{})
	if err != nil {
		return "", err
	}
	return desc + ", " + confined, nil
}

// child is the SSH side of the unprivileged half.
type child struct {
	ctl     *conn
	config  *ssh.ServerConfig
	name    string
	notice  string
	preAuth chan struct{} // a slot per connection that has not logged in
	slots   chan struct{} // a slot per session

	mu       sync.Mutex
	nextID   uint64
	pending  map[uint64]chan msg // sign requests waiting for the server
	sessions uint64              // the last session's ID
	relays   sync.WaitGroup
	closing  atomic.Bool
}

func newChild(ctl *conn, init msg) (*child, error) {
	pub, err := ssh.ParsePublicKey(init.HostKey)
	if err != nil {
		return nil, fmt.Errorf("host key from the server: %w", err)
	}
	allowed := map[string]bool{}
	for _, l := range init.AuthorizedKeys {
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err == nil {
			allowed[string(k.Marshal())] = true
		}
	}
	s := &child{ctl: ctl, name: init.Name, notice: init.Notice, pending: map[uint64]chan msg{},
		preAuth: make(chan struct{}, preAuthMax), slots: make(chan struct{}, sessionMax)}
	s.config = &ssh.ServerConfig{
		ServerVersion: init.Version,
		MaxAuthTries:  6,
		// The key the client proved it holds is the one passed here; the
		// login's Permissions carry its fingerprint, never a key kept from
		// an earlier call (CVE-2024-45337).
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !allowed[string(key.Marshal())] {
				return nil, errors.New("not an authorized key")
			}
			return &ssh.Permissions{Extensions: map[string]string{"key": ssh.FingerprintSHA256(key)}}, nil
		},
		AuthLogCallback: func(meta ssh.ConnMetadata, method string, err error) {
			if err != nil && method != "none" {
				s.log(fmt.Sprintf("refused %s login of %s from %s", method, meta.User(), meta.RemoteAddr()))
			}
		},
	}
	s.config.AddHostKey(&remoteSigner{s: s, pub: pub, algorithms: init.Algorithms})
	return s, nil
}

func (s *child) log(text string) { s.ctl.send(msg{T: "log", Text: text}, -1) }

// control reads the server's answers. When the server closes the socket
// this half stops: no new connection, the sessions' relays finish (the
// server has closed their ends), and the process ends.
func (s *child) control() {
	for {
		m, fd, err := s.ctl.recv()
		if fd >= 0 {
			unix.Close(fd)
		}
		if err != nil {
			s.closing.Store(true)
			done := make(chan struct{})
			go func() { s.relays.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
			}
			os.Exit(0)
		}
		if m.T != "signed" {
			continue
		}
		s.mu.Lock()
		ch := s.pending[m.ID]
		delete(s.pending, m.ID)
		s.mu.Unlock()
		if ch != nil {
			ch <- m
		}
	}
}

// remoteSigner signs the key exchange with the host key the server holds,
// in the algorithms the server offers.
type remoteSigner struct {
	s          *child
	pub        ssh.PublicKey
	algorithms []string
}

func (r *remoteSigner) PublicKey() ssh.PublicKey { return r.pub }

func (r *remoteSigner) Algorithms() []string { return r.algorithms }

func (r *remoteSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return r.SignWithAlgorithm(rand, data, "")
}

func (r *remoteSigner) SignWithAlgorithm(_ io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	s := r.s
	ch := make(chan msg, 1)
	s.mu.Lock()
	s.nextID++
	id := s.nextID
	s.pending[id] = ch
	s.mu.Unlock()
	if err := s.ctl.send(msg{T: "sign", ID: id, Data: data, Algorithm: algorithm}, -1); err != nil {
		return nil, err
	}
	select {
	case m := <-ch:
		if m.Err != "" {
			return nil, errors.New(m.Err)
		}
		return &ssh.Signature{Format: m.Format, Blob: m.Data}, nil
	case <-time.After(10 * time.Second):
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return nil, errors.New("the server did not sign")
	}
}

// accept takes the connections, as many at once as have a pre-login slot.
func (s *child) accept(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if s.closing.Load() {
			c.Close()
			continue
		}
		select {
		case s.preAuth <- struct{}{}:
		default:
			c.Close() // too many at once that have not logged in
			continue
		}
		go s.serve(c)
	}
}

// login is who logged in, for the server.
type login struct {
	user, key, remote string
}

func (l login) String() string {
	return fmt.Sprintf("%s from %s, key %s", l.user, l.remote, l.key)
}

// serve is one connection: the login, then its channels.
func (s *child) serve(c net.Conn) {
	s.log(fmt.Sprintf("connection from %s", c.RemoteAddr()))
	c.SetDeadline(time.Now().Add(preAuthLimit))
	sc, chans, reqs, err := ssh.NewServerConn(c, s.config)
	<-s.preAuth
	if err != nil {
		c.Close()
		return
	}
	c.SetDeadline(time.Time{})
	defer sc.Close()
	who := login{user: sc.User(), key: sc.Permissions.Extensions["key"], remote: sc.RemoteAddr().String()}
	s.log("login of " + who.String())
	go ssh.DiscardRequests(reqs) // no forwarding, no keepalive answers needed
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.Prohibited, "only an interactive session is served")
			s.log(fmt.Sprintf("refused the %s channel of %s", nc.ChannelType(), who))
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go s.session(ch, creqs, who)
	}
}

// ptyReq is the payload of a "pty-req" (RFC 4254 6.2), windowChange of a
// "window-change" (6.7).
type ptyReq struct {
	Term          string
	Cols, Rows    uint32
	Width, Height uint32
	Modes         string
}

type windowChange struct {
	Cols, Rows    uint32
	Width, Height uint32
}

// session waits for the shell request - the only one served besides the
// terminal's - and relays the channel to a session of the server.
func (s *child) session(ch ssh.Channel, reqs <-chan *ssh.Request, who login) {
	defer ch.Close()
	var term string
	var cols, rows int
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			var p ptyReq
			if ssh.Unmarshal(req.Payload, &p) == nil {
				term, cols, rows = p.Term, int(p.Cols), int(p.Rows)
			}
			req.Reply(true, nil)
		case "env", "window-change":
			req.Reply(true, nil)
		case "shell":
			req.Reply(true, nil)
			s.relay(ch, reqs, who, term, cols, rows)
			return
		case "exec", "subsystem":
			// Accepted only to say why nothing runs: a refused request
			// leaves the client with "request failed" and no reason.
			req.Reply(true, nil)
			s.log(fmt.Sprintf("refused the %s request of %s", req.Type, who))
			fmt.Fprintf(ch.Stderr(), "%s: %s\r\n", s.name, s.notice)
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
			return
		default:
			req.Reply(false, nil)
			s.log(fmt.Sprintf("refused the %s request of %s", req.Type, who))
		}
	}
}

// relay hands a socket pair's end to the server as a session and copies
// between it and the channel until either side ends; the terminal's new
// sizes go to the server as they come.
func (s *child) relay(ch ssh.Channel, reqs <-chan *ssh.Request, who login, term string, cols, rows int) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		fmt.Fprintf(ch, "%s: too many sessions at once\r\n", s.name)
		go ssh.DiscardRequests(reqs)
		return
	}
	if s.closing.Load() {
		go ssh.DiscardRequests(reqs)
		return
	}
	s.relays.Add(1)
	defer s.relays.Done()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		go ssh.DiscardRequests(reqs)
		return
	}
	s.mu.Lock()
	s.sessions++
	id := s.sessions
	s.mu.Unlock()
	err = s.ctl.send(msg{T: "session", ID: id, User: who.user, Key: who.key, Remote: who.remote,
		Term: term, Cols: cols, Rows: rows}, fds[1])
	unix.Close(fds[1])
	f := os.NewFile(uintptr(fds[0]), "session")
	c, cerr := net.FileConn(f)
	f.Close()
	if err != nil || cerr != nil {
		go ssh.DiscardRequests(reqs)
		return
	}
	defer c.Close()
	defer s.ctl.send(msg{T: "ended", ID: id}, -1)
	go func() {
		for req := range reqs {
			var w windowChange
			if req.Type == "window-change" && ssh.Unmarshal(req.Payload, &w) == nil {
				s.ctl.send(msg{T: "resize", ID: id, Cols: int(w.Cols), Rows: int(w.Rows)}, -1)
			}
			if req.WantReply {
				req.Reply(req.Type == "window-change", nil)
			}
		}
	}()
	done := make(chan struct{})
	go func() {
		io.Copy(c, ch) // what is typed
		c.(*net.UnixConn).CloseWrite()
		close(done)
	}()
	io.Copy(ch, c) // the screen; ends when the server closes the session
	ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
	ch.Close()
	<-done
}
