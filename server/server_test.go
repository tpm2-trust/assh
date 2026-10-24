package server

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestMain is also the unprivileged half, when a test's server starts this
// binary again.
func TestMain(m *testing.M) {
	if os.Getenv("ASSH_TEST_CHILD") == "1" {
		if err := ChildMain(); err != nil {
			os.Stderr.WriteString("child: " + err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func childCommand() *exec.Cmd {
	c := exec.Command(os.Args[0])
	c.Env = []string{"ASSH_TEST_CHILD=1"}
	return c
}

type testLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *testLog) add(s string) { l.mu.Lock(); l.lines = append(l.lines, s); l.mu.Unlock() }

func (l *testLog) wait(t *testing.T, want string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		l.mu.Lock()
		all := strings.Join(l.lines, "\n")
		l.mu.Unlock()
		if strings.Contains(all, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("never logged %q:\n%s", want, all)
		}
	}
}

type testServer struct {
	*Server
	port     int
	hostKey  ssh.PublicKey
	client   ssh.Signer
	log      *testLog
	sessions chan *Session
}

// start runs a server on a free port with a software host key and one
// key that may log in; handle gets the sessions (nil: the test reads
// them from sessions).
func start(t *testing.T, handle func(*Session)) *testServer {
	t.Helper()
	hk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	host, _ := ssh.NewSignerFromSigner(hk)
	ck, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, _ := ssh.NewSignerFromSigner(ck)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ts := &testServer{port: port, hostKey: host.PublicKey(), client: client, log: &testLog{}, sessions: make(chan *Session, 4)}
	if handle == nil {
		handle = func(s *Session) { ts.sessions <- s }
	}
	srv, err := Start(Options{
		Listener:       ln.(*net.TCPListener),
		HostKey:        host,
		AuthorizedKeys: []string{string(ssh.MarshalAuthorizedKey(client.PublicKey()))},
		Command:        childCommand,
		Session:        handle,
		Log:            ts.log.add,
		Name:           "test",
		Notice:         "nothing runs here",
	})
	if err != nil {
		t.Fatal(err)
	}
	ts.Server = srv
	t.Cleanup(srv.Stop)
	return ts
}

func (ts *testServer) dial(t *testing.T, key ssh.Signer) (*ssh.Client, error) {
	return ssh.Dial("tcp", "127.0.0.1:"+strconv.Itoa(ts.port), &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.FixedHostKey(ts.hostKey),
		Timeout:         10 * time.Second,
	})
}

func shell(t *testing.T, c *ssh.Client, pty bool) (io.Writer, *bufio.Reader, *ssh.Session) {
	t.Helper()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if pty {
		if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
			t.Fatal(err)
		}
	}
	in, _ := sess.StdinPipe()
	out, _ := sess.StdoutPipe()
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	return in, bufio.NewReader(out), sess
}

func until(t *testing.T, r *bufio.Reader, want string) string {
	t.Helper()
	got := make(chan string, 1)
	go func() {
		var b []byte
		for !bytes.Contains(b, []byte(want)) {
			c, err := r.ReadByte()
			if err != nil {
				got <- "EOF before it: " + string(b)
				return
			}
			b = append(b, c)
		}
		got <- string(b)
	}()
	select {
	case s := <-got:
		if strings.HasPrefix(s, "EOF before it: ") {
			t.Fatalf("waiting for %q: %s", want, s)
		}
		return s
	case <-time.After(10 * time.Second):
		t.Fatalf("waiting for %q: nothing", want)
		return ""
	}
}

// A login's shell becomes a session of the server - who, the terminal,
// its new sizes - while the unprivileged half runs sandboxed and signs
// nothing itself.
func TestLoginBecomesSession(t *testing.T) {
	ts := start(t, nil)
	if !strings.Contains(ts.How, "no new privileges") {
		t.Fatalf("runs with %q", ts.How)
	}
	c, err := ts.dial(t, ts.client)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in, out, sess := shell(t, c, true)
	s := <-ts.sessions
	if s.User != "root" || s.Key != ssh.FingerprintSHA256(ts.client.PublicKey()) || s.Term != "xterm" || s.Cols != 80 || s.Rows != 24 {
		t.Fatalf("session %+v", s)
	}
	if !strings.Contains(s.String(), "root from 127.0.0.1:") {
		t.Fatal(s.String())
	}
	io.WriteString(s, "hello\r\n")
	until(t, out, "hello")
	io.WriteString(in, "typed")
	buf := make([]byte, 5)
	if _, err := io.ReadFull(s, buf); err != nil || string(buf) != "typed" {
		t.Fatalf("%q %v", buf, err)
	}
	if err := sess.WindowChange(40, 100); err != nil {
		t.Fatal(err)
	}
	select {
	case size := <-s.Resized():
		if size != [2]int{100, 40} {
			t.Fatalf("size %v", size)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no resize")
	}
	s.Close()
	if err := sess.Wait(); err != nil {
		t.Fatalf("session end: %v", err)
	}
	ts.log.wait(t, "login of root from 127.0.0.1")
}

// A key that may not log in is refused; a command is answered with the
// notice; another channel than a session is refused.
func TestRefuses(t *testing.T) {
	ts := start(t, nil)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	os, _ := ssh.NewSignerFromSigner(other)
	if _, err := ts.dial(t, os); err == nil {
		t.Fatal("another key logged in")
	}
	ts.log.wait(t, "refused publickey login of root")
	c, err := ts.dial(t, ts.client)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, _ := c.NewSession()
	out, err := sess.CombinedOutput("id")
	if err == nil || !strings.Contains(string(out), "test: nothing runs here") {
		t.Fatalf("exec: %v %q", err, out)
	}
	if _, err := c.Dial("tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("a forwarding was opened")
	}
}

// The unprivileged half refuses to run without the server's descriptors
// (and as root).
func TestChildAlone(t *testing.T) {
	if out, err := childCommand().CombinedOutput(); err == nil || !strings.Contains(string(out), "no control socket") {
		if !strings.Contains(string(out), "refuses to run as root") {
			t.Fatalf("alone: %v %s", err, out)
		}
	}
}

// RunCommand runs a command in a pseudo-terminal for the session, and on
// pipes without one.
func TestRunCommand(t *testing.T) {
	ts := start(t, func(s *Session) {
		go RunCommand(s, []string{"/bin/sh", "-c", `echo "user $ASSH_USER term $TERM"; read x; echo "got $x"`}, nil, []string{"PATH=/usr/bin:/bin"})
	})
	c, err := ts.dial(t, ts.client)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in, out, sess := shell(t, c, true)
	until(t, out, "user root term xterm")
	io.WriteString(in, "abc\r")
	until(t, out, "got abc")
	if err := sess.Wait(); err != nil {
		t.Fatal(err)
	}

	in, out, sess = shell(t, c, false)
	until(t, out, "user root term")
	io.WriteString(in, "def\n")
	until(t, out, "got def")
	sess.Wait()
}

func TestParseAuthorizedKeys(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, _ := ssh.NewSignerFromSigner(k)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
	keys, skipped := ParseAuthorizedKeys([]byte("# comment\n\n" + line + " me@host\ncommand=\"x\" " + line + "\nnot a key\n"))
	if len(keys) != 1 || skipped != 2 || keys[0] != line+" me@host" {
		t.Fatalf("%q %d", keys, skipped)
	}
}
