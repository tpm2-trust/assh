package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/crypto/ssh"

	"github.com/tpm2-trust/assh/agent"
	"github.com/tpm2-trust/assh/hostkey"
	"github.com/tpm2-trust/assh/server"
)

// childArg starts this binary as the server's unprivileged half.
const childArg = "unprivileged-half"

func childMain() error { return server.ChildMain() }

func childCommand() *exec.Cmd {
	self, err := os.Executable()
	if err != nil {
		self = os.Args[0]
	}
	return exec.Command(self, childArg)
}

// Header is the first line 'serve --socket' writes to the program behind
// the socket, as JSON, before the session's bytes.
type Header struct {
	User   string `json:"user"`
	Key    string `json:"key"`
	Remote string `json:"remote"`
	Term   string `json:"term,omitempty"`
	Cols   int    `json:"cols,omitempty"`
	Rows   int    `json:"rows,omitempty"`
}

func serveCommand(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var h hostKeyFlags
	h.add(fs, "/run/assh/serve.pcrs.json")
	listen := fs.String("listen", ":22", "the address to listen on")
	authPath := fs.String("authorized-keys", "", "the keys that may log in (authorized_keys; lines with options are left out)")
	socket := fs.String("socket", "", "hand each session to the program listening on this Unix socket")
	userName := fs.String("user", "", "run the command as this user (default: as assh runs)")
	fs.Parse(args)
	command := fs.Args()
	if (*socket == "") == (len(command) == 0) {
		return errors.New("serve needs a command (after --) or --socket, one of them")
	}
	data, err := os.ReadFile(*authPath)
	if err != nil {
		return fmt.Errorf("the keys that may log in: %w", err)
	}
	keys, skipped := server.ParseAuthorizedKeys(data)
	if skipped > 0 {
		logger(fmt.Sprintf("%d line(s) of %s left out: options are not honoured", skipped, *authPath))
	}
	if len(keys) == 0 {
		return fmt.Errorf("%s holds no key: nobody could log in", *authPath)
	}
	var cred *syscall.Credential
	if *userName != "" {
		u, err := user.Lookup(*userName)
		if err != nil {
			return err
		}
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		cred = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	}
	if h.state != "" {
		os.MkdirAll(filepath.Dir(h.state), 0o755)
	}
	hk, err := h.issue(logger)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	session := func(s *server.Session) {
		logger("session of " + s.String())
		if *socket != "" {
			go forward(s, *socket)
			return
		}
		go func() {
			if err := server.RunCommand(s, command, cred, []string{"PATH=/usr/local/bin:/usr/bin:/bin"}); err != nil {
				logger(fmt.Sprintf("the command of %s: %v", s, err))
			}
		}()
	}
	srv, err := server.Start(server.Options{
		Listener:       ln.(*net.TCPListener),
		HostKey:        hk.SSH(),
		AuthorizedKeys: keys,
		Command:        childCommand,
		Session:        session,
		Log:            logger,
	})
	if err != nil {
		return err
	}
	logger(fmt.Sprintf("listening on %s; the unprivileged half (pid %d) runs with %s", *listen, srv.Pid(), srv.How))
	select {
	case <-srv.Exited():
		return errors.New("the unprivileged half ended")
	case <-signalled():
		srv.Stop()
		return nil
	}
}

func signalled() <-chan struct{} {
	ch := make(chan struct{})
	go func() { waitForSignal(); close(ch) }()
	return ch
}

// forward hands a session to the program behind the socket: a header
// line, then the bytes both ways.
func forward(s *server.Session, path string) {
	defer s.Close()
	c, err := net.Dial("unix", path)
	if err != nil {
		logger(fmt.Sprintf("the session of %s: %v", s, err))
		fmt.Fprint(s, "assh: nothing answers for this session\r\n")
		return
	}
	defer c.Close()
	b, _ := json.Marshal(Header{User: s.User, Key: s.Key, Remote: s.Remote, Term: s.Term, Cols: s.Cols, Rows: s.Rows})
	if _, err := c.Write(append(b, '\n')); err != nil {
		return
	}
	go func() {
		io.Copy(c, s)
		c.(*net.UnixConn).CloseWrite()
	}()
	io.Copy(s, c)
}

func agentCommand(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	var h hostKeyFlags
	h.add(fs, "")
	dir := fs.String("dir", "/run/assh", "where the socket, the public key and the certificate go")
	uid := fs.Int("uid", 0, "the only user answered (sshd: root)")
	fs.Parse(args)
	if h.state == "" {
		h.state = filepath.Join(*dir, "agent.pcrs.json")
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return err
	}
	hk, err := h.issue(logger)
	if err != nil {
		return err
	}
	pub := filepath.Join(*dir, "host.pub")
	if err := os.WriteFile(pub, sshAuthorizedKey(hk.Cert.Key), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*dir, "host-cert.pub"), sshAuthorizedKey(hk.Cert), 0o644); err != nil {
		return err
	}
	signer, err := plainSigner(hk)
	if err != nil {
		return err
	}
	sock := filepath.Join(*dir, "agent.sock")
	ln, err := agent.Listen(sock)
	if err != nil {
		return err
	}
	logger(fmt.Sprintf("agent at %s: HostKey %s, HostCertificate %s/host-cert.pub, HostKeyAgent %s", sock, pub, *dir, sock))
	go agent.New(signer, hk.Cert, logger).Serve(ln, *uid)
	notifyReady()
	<-signalled()
	ln.Close()
	return nil
}

func sshAuthorizedKey(k ssh.PublicKey) []byte { return ssh.MarshalAuthorizedKey(k) }

// plainSigner is the host key for sshd: every algorithm the TPM signs in,
// rsa-sha2-512 too where it has SHA-512 (the agent refuses SHA-1).
func plainSigner(hk *hostkey.HostKey) (ssh.Signer, error) {
	return ssh.NewSignerFromSigner(hk.Signer)
}

// notifyReady tells systemd the agent is up (Type=notify), so sshd starts
// after it.
func notifyReady() {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return
	}
	defer c.Close()
	c.Write([]byte("READY=1"))
}
