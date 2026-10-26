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
	"strings"
	"syscall"

	"github.com/google/go-tpm/tpm2"
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
	cfg, err := commandConfig(fs, args)
	if err != nil {
		return err
	}
	var h hostKeyFlags
	h.add(fs, cfg, "/run/assh/serve.pcrs.json")
	listen := fs.String("listen", cfg.Listen, "the address to listen on")
	authPath := fs.String("authorized-keys", cfg.AuthorizedKeys, "the keys that may log in (authorized_keys; lines with options are left out)")
	socket := fs.String("socket", cfg.Socket, "hand each session to the program listening on this Unix socket")
	userName := fs.String("user", cfg.User, "run the command as this user (default: as assh runs)")
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
	cfg, err := commandConfig(fs, args)
	if err != nil {
		return err
	}
	var h hostKeyFlags
	h.add(fs, cfg, "")
	dir := fs.String("dir", cfg.AgentDir, "where the socket, the public key and the certificate go")
	uid := fs.Int("uid", cfg.AgentUID, "the only user answered (sshd: root)")
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
	if err := os.WriteFile(pub, sshAuthorizedKey(hk.PublicKey()), 0o644); err != nil {
		return err
	}
	certPath := filepath.Join(*dir, "host-cert.pub")
	if hk.Cert != nil {
		if err := os.WriteFile(certPath, sshAuthorizedKey(hk.Cert), 0o644); err != nil {
			return err
		}
	} else if err := os.Remove(certPath); err != nil && !os.IsNotExist(err) {
		// A temporary key has no certificate: none of another boot stays.
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
	algs, err := hostKeyAlgorithms(hk, h.tpm)
	if err != nil {
		return err
	}
	conf := fmt.Sprintf("HostKey %s\n", pub)
	if hk.Cert != nil {
		conf += fmt.Sprintf("HostCertificate %s\n", certPath)
	}
	conf += fmt.Sprintf("HostKeyAgent %s\nHostKeyAlgorithms %s\n", sock, strings.Join(algs, ","))
	if err := os.WriteFile(filepath.Join(*dir, "sshd.conf"), []byte(conf), 0o644); err != nil {
		return err
	}
	if hk.Cert != nil {
		logger(fmt.Sprintf("agent at %s: HostKey %s, HostCertificate %s, HostKeyAgent %s (sshd: %s)", sock, pub, certPath, sock, filepath.Join(*dir, "sshd.conf")))
	} else {
		logger(fmt.Sprintf("agent at %s: HostKey %s (temporary, no certificate), HostKeyAgent %s (sshd: %s)", sock, pub, sock, filepath.Join(*dir, "sshd.conf")))
	}
	go agent.New(signer, hk.Cert, logger).Serve(ln, *uid)
	notifyReady()
	<-signalled()
	ln.Close()
	return nil
}

func sshAuthorizedKey(k ssh.PublicKey) []byte { return ssh.MarshalAuthorizedKey(k) }

// hostKeyAlgorithms are the algorithms sshd may offer for hk: what the
// TPM signs in (RSA: rsa-sha2-512 only where it has SHA-512, never SHA-1's
// ssh-rsa), the certificate's first when there is one. sshd asks the agent
// for the one a client picks: one the TPM cannot make drops the connection.
func hostKeyAlgorithms(hk *hostkey.HostKey, tpmPath string) ([]string, error) {
	var plain []string
	switch hk.PublicKey().Type() {
	case ssh.KeyAlgoRSA:
		tpm, err := openTPM(tpmPath)()
		if err != nil {
			return nil, err
		}
		defer tpm.Close()
		rsp, err := tpm2.GetCapability{Capability: tpm2.TPMCapAlgs, Property: uint32(tpm2.TPMAlgSHA512), PropertyCount: 1}.Execute(tpm)
		if err != nil {
			return nil, fmt.Errorf("asking the TPM for SHA-512: %w", err)
		}
		algs, err := rsp.CapabilityData.Data.Algorithms()
		if err != nil {
			return nil, err
		}
		if len(algs.AlgProperties) > 0 && algs.AlgProperties[0].Alg == tpm2.TPMAlgSHA512 {
			plain = append(plain, ssh.KeyAlgoRSASHA512)
		}
		plain = append(plain, ssh.KeyAlgoRSASHA256)
	default:
		plain = []string{hk.PublicKey().Type()}
	}
	var out []string
	if hk.Cert != nil {
		for _, a := range plain {
			out = append(out, certAlgorithm(a))
		}
	}
	return append(out, plain...), nil
}

// certAlgorithm is the certificate algorithm of a key algorithm.
func certAlgorithm(a string) string {
	switch a {
	case ssh.KeyAlgoRSASHA512:
		return ssh.CertAlgoRSASHA512v01
	case ssh.KeyAlgoRSASHA256:
		return ssh.CertAlgoRSASHA256v01
	case ssh.KeyAlgoECDSA256:
		return ssh.CertAlgoECDSA256v01
	}
	return a + "-cert-v01@openssh.com"
}

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
