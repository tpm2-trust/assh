package agent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func serve(t *testing.T, key crypto.Signer, withCert bool) (agent.ExtendedAgent, ssh.Signer, *ssh.Certificate) {
	t.Helper()
	signer, err := ssh.NewSignerFromSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	var cert *ssh.Certificate
	if withCert {
		caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ca, _ := ssh.NewSignerFromSigner(caKey)
		cert = &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.HostCert, ValidBefore: ssh.CertTimeInfinity}
		if err := cert.SignCert(rand.Reader, ca); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "run", "agent.sock")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket %v %v", fi.Mode(), err)
	}
	go New(signer, cert, nil).Serve(ln, os.Getuid())
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return agent.NewClient(c), signer, cert
}

// sshd's questions: the keys, and a signature with the key or the
// certificate, in the algorithm it asks for.
func TestAgentSigns(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a, signer, cert := serve(t, k, true)
	keys, err := a.List()
	if err != nil || len(keys) != 2 {
		t.Fatalf("%v %v", keys, err)
	}
	for _, pub := range []ssh.PublicKey{signer.PublicKey(), cert} {
		sig, err := a.Sign(pub, []byte("data"))
		if err != nil {
			t.Fatal(err)
		}
		if err := signer.PublicKey().Verify([]byte("data"), sig); err != nil {
			t.Fatal(err)
		}
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	os, _ := ssh.NewSignerFromSigner(other)
	if _, err := a.Sign(os.PublicKey(), []byte("data")); err == nil {
		t.Fatal("signed for another key")
	}
	if err := a.RemoveAll(); err == nil {
		t.Fatal("removed keys")
	}

	r, _ := rsa.GenerateKey(rand.Reader, 2048)
	a, signer, _ = serve(t, r, false)
	if _, err := a.Sign(signer.PublicKey(), []byte("data")); err == nil {
		t.Fatal("signed with ssh-rsa")
	}
	sig, err := a.SignWithFlags(signer.PublicKey(), []byte("data"), agent.SignatureFlagRsaSha256)
	if err != nil || sig.Format != ssh.KeyAlgoRSASHA256 {
		t.Fatalf("%v %v", sig, err)
	}
	if err := signer.PublicKey().Verify([]byte("data"), sig); err != nil {
		t.Fatal(err)
	}
}

// A peer of another user gets no answer.
func TestAgentRefusesOtherUsers(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := ssh.NewSignerFromSigner(k)
	path := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go New(signer, nil, nil).Serve(ln, os.Getuid()+1)
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := agent.NewClient(c).List(); err == nil {
		t.Fatal("answered another user")
	}
}
