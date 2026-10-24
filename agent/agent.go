// Package agent lends a host key to OpenSSH's sshd without handing it
// over: sshd asks for each signature over the ssh-agent protocol
// (sshd_config's HostKeyAgent), and the key stays where it is - for assh,
// in the TPM.
//
// sshd is configured with the public key and the certificate as files,
// and the agent's socket:
//
//	HostKey         /run/assh/host.pub
//	HostCertificate /run/assh/host-cert.pub
//	HostKeyAgent    /run/assh/agent.sock
package agent

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/unix"
)

// Agent answers for one host key and its certificate.
type Agent struct {
	signer ssh.Signer       // the key itself
	cert   *ssh.Certificate // nil without one
	log    func(string)
}

// New is an agent for signer; cert, when not nil, is its certificate and
// is listed beside it. log gets every refusal.
func New(signer ssh.Signer, cert *ssh.Certificate, log func(string)) *Agent {
	if log == nil {
		log = func(string) {}
	}
	return &Agent{signer: signer, cert: cert, log: log}
}

// Listen makes the agent's socket at path: a directory for it if there is
// none, readable by root alone.
func Listen(path string) (*net.UnixListener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	os.Remove(path)
	old := unix.Umask(0o177)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	unix.Umask(old)
	if err != nil {
		return nil, err
	}
	return ln, nil
}

// Serve answers the connections on ln until it is closed. Only a peer
// running as uid (sshd: 0) is answered.
func (a *Agent) Serve(ln *net.UnixListener, uid int) error {
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			return err
		}
		if peer, err := peerUID(c); err != nil || peer != uid {
			a.log(fmt.Sprintf("refused a connection of uid %d", peer))
			c.Close()
			continue
		}
		go func() {
			defer c.Close()
			agent.ServeAgent(a, c)
		}()
	}
}

func peerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *unix.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if serr != nil {
		return -1, serr
	}
	return int(cred.Uid), nil
}

var errRefused = errors.New("this agent only signs")

// List gives the key and its certificate.
func (a *Agent) List() ([]*agent.Key, error) {
	keys := []*agent.Key{{Format: a.signer.PublicKey().Type(), Blob: a.signer.PublicKey().Marshal(), Comment: "assh host key"}}
	if a.cert != nil {
		keys = append(keys, &agent.Key{Format: a.cert.Type(), Blob: a.cert.Marshal(), Comment: "assh host certificate"})
	}
	return keys, nil
}

// Sign signs with the key, asked for by itself or by its certificate.
func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

// SignWithFlags signs in the algorithm the flags ask for: for RSA
// rsa-sha2-256 or rsa-sha2-512 (where the TPM has SHA-512), never SHA-1's
// ssh-rsa.
func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	blob := string(key.Marshal())
	if blob != string(a.signer.PublicKey().Marshal()) && (a.cert == nil || blob != string(a.cert.Marshal())) {
		return nil, errors.New("not this agent's key")
	}
	algorithm := ""
	switch {
	case flags&agent.SignatureFlagRsaSha256 != 0:
		algorithm = ssh.KeyAlgoRSASHA256
	case flags&agent.SignatureFlagRsaSha512 != 0:
		algorithm = ssh.KeyAlgoRSASHA512
	}
	if algorithm == "" {
		if a.signer.PublicKey().Type() == ssh.KeyAlgoRSA {
			return nil, errors.New("ssh-rsa (SHA-1) is not offered")
		}
		return a.signer.Sign(rand.Reader, data)
	}
	as, ok := a.signer.(ssh.AlgorithmSigner)
	if !ok {
		return nil, fmt.Errorf("no %s signature", algorithm)
	}
	sig, err := as.SignWithAlgorithm(rand.Reader, data, algorithm)
	if err != nil {
		a.log(fmt.Sprintf("a %s signature: %v", algorithm, err))
	}
	return sig, err
}

func (a *Agent) Add(agent.AddedKey) error                 { return errRefused }
func (a *Agent) Remove(ssh.PublicKey) error               { return errRefused }
func (a *Agent) RemoveAll() error                         { return errRefused }
func (a *Agent) Lock([]byte) error                        { return errRefused }
func (a *Agent) Unlock([]byte) error                      { return errRefused }
func (a *Agent) Signers() ([]ssh.Signer, error)           { return nil, errRefused }
func (a *Agent) Extension(string, []byte) ([]byte, error) { return nil, agent.ErrExtensionUnsupported }
