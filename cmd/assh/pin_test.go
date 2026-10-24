package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/tpm2-trust/assh/internal/swtpmtest"
)

// secrets runs assh with each secret on a file descriptor from 3 on, and
// gives its output; every output is kept for the check that no secret is
// in one.
type secrets struct {
	t   *testing.T
	out bytes.Buffer
}

func (s *secrets) cmd(fds [][]byte, args ...string) *exec.Cmd {
	s.t.Helper()
	c := assh(args...)
	for _, b := range fds {
		r, w, err := os.Pipe()
		if err != nil {
			s.t.Fatal(err)
		}
		go func() { w.Write(b); w.Close() }()
		c.ExtraFiles = append(c.ExtraFiles, r)
		s.t.Cleanup(func() { r.Close() })
	}
	return c
}

func (s *secrets) run(fds [][]byte, args ...string) (string, error) {
	s.t.Helper()
	out, err := s.cmd(fds, args...).CombinedOutput()
	s.out.Write(out)
	return string(out), err
}

func (s *secrets) must(fds [][]byte, args ...string) string {
	s.t.Helper()
	out, err := s.run(fds, args...)
	if err != nil {
		s.t.Fatalf("assh %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// extend moves a PCR on, as booting another combination does.
func extend(t *testing.T, sw *swtpmtest.SWTPM, pcr int, event string) {
	t.Helper()
	c, err := transport.OpenTPM(sw.Sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := (tpm2.PCREvent{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(pcr), Auth: tpm2.PasswordAuth(nil)},
		EventData: tpm2.TPM2BEvent{Buffer: []byte(event)},
	}).Execute(c); err != nil {
		t.Fatal(err)
	}
}

// agentSigns runs the agent and has it sign as sshd would, with the CA's
// certificate; it gives what the agent said.
func agentSigns(t *testing.T, s *secrets, sw *swtpmtest.SWTPM, ca, runDir string) string {
	t.Helper()
	ag := start(t, "agent", "--tpm="+sw.Sock, "--ca", ca, "--dir", runDir, "--uid", fmt.Sprint(os.Getuid()))
	ag.wait(t, "agent at")
	defer func() { ag.stop(); s.out.WriteString(ag.String()) }()
	c, err := net.Dial("unix", filepath.Join(runDir, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	certLine, _ := os.ReadFile(filepath.Join(runDir, "host-cert.pub"))
	certKey, _, _, _, err := ssh.ParseAuthorizedKey(certLine)
	if err != nil {
		t.Fatal(err)
	}
	cert := certKey.(*ssh.Certificate)
	caPub, _ := os.ReadFile(ca + ".pub")
	caKey, _, _, _, _ := ssh.ParseAuthorizedKey(caPub)
	if !bytes.Equal(cert.SignatureKey.Marshal(), caKey.Marshal()) {
		t.Fatal("the host key is not certified by the CA")
	}
	sig, err := sshagent.NewClient(c).Sign(cert.Key, []byte("exchange hash"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.Key.Verify([]byte("exchange hash"), sig); err != nil {
		t.Fatal(err)
	}
	return ag.String()
}

// agentTemporary runs the agent where no slot is approved: it serves a
// temporary key, with no certificate; it gives what the agent said.
func agentTemporary(t *testing.T, s *secrets, sw *swtpmtest.SWTPM, ca, runDir string) string {
	t.Helper()
	ag := start(t, "agent", "--tpm="+sw.Sock, "--ca", ca, "--dir", runDir, "--uid", fmt.Sprint(os.Getuid()))
	ag.wait(t, "agent at")
	defer func() { ag.stop(); s.out.WriteString(ag.String()) }()
	if !strings.Contains(ag.String(), "is TEMPORARY") || !strings.Contains(ag.String(), "(temporary, no certificate)") {
		t.Fatalf("agent:\n%s", ag.String())
	}
	if _, err := os.Stat(filepath.Join(runDir, "host-cert.pub")); !os.IsNotExist(err) {
		t.Fatalf("a certificate beside a temporary key: %v", err)
	}
	c, err := net.Dial("unix", filepath.Join(runDir, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	line, _ := os.ReadFile(filepath.Join(runDir, "host.pub"))
	key, _, _, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ag.String(), "host key "+ssh.FingerprintSHA256(key)+" is TEMPORARY") {
		t.Fatalf("host.pub is not the key logged:\n%s", ag.String())
	}
	sig, err := sshagent.NewClient(c).Sign(key, []byte("exchange hash"))
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Verify([]byte("exchange hash"), sig); err != nil {
		t.Fatal(err)
	}
	return ag.String()
}

// A CA with its authority in the TPM, as safespace runs it: the lockout
// authorization first; the PIN on a file descriptor; two slots with the
// window PCR 15, slot 0 also reading PCR 14 (the OS); an OpenSSH login; a
// move to another combination revokes the approval of the old one, and
// until it is approved the agent serves a temporary key; with the OS
// changed, slot 1 certifies; a PIN change; and the PIN in no file, output,
// argv or environment.
func TestPINCommand(t *testing.T) {
	for _, tool := range []string{"ssh", "ssh-keygen"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	sw := swtpmtest.Start(t)
	dir := t.TempDir()
	s := &secrets{t: t}
	tpm := "--tpm=" + sw.Sock
	ca := filepath.Join(dir, "ca.json")
	pin, newPIN, lockout := []byte("pin-7GQ2xw"), []byte("pin-new-4Rt8"), []byte("lockout-Zq93nB")

	if out, err := s.run([][]byte{pin}, "ca", "create", tpm, "--out", ca, "--authority-tpm", "--pin-fd", "3", "--pcrs", "7,14,15", "--window", "15"); err == nil || !strings.Contains(out, "no lockout authorization") {
		t.Fatalf("created without a lockout authorization: %v\n%s", err, out)
	}
	out := s.must([][]byte{lockout}, "tpm", "da", tpm, "--new-lockout-auth-fd", "3", "--max-tries", "3", "--recovery", "1800", "--lockout-recovery", "1800")
	if !strings.Contains(out, "0 of 3 failures") || strings.Contains(out, "WARNING") {
		t.Fatalf("tpm da:\n%s", out)
	}
	out = s.must([][]byte{pin}, "ca", "create", tpm, "--out", ca, "--authority-tpm", "--pin-fd", "3", "--pcrs", "7,14,15", "--window", "15")
	if !strings.Contains(out, "opened by a PIN") || !strings.Contains(out, "@cert-authority * ecdsa-sha2-nistp256 ") {
		t.Fatalf("create:\n%s", out)
	}
	s.must(nil, "ca", "slot", "--ca", ca, "--add", "1", "--pcrs", "7,15")
	if out, err := s.run(nil, "ca", "approve", tpm, "--ca", ca, "--pin", string(pin)); err == nil || !strings.Contains(out, "flag provided but not defined: -pin") {
		t.Fatalf("--pin: %v\n%s", err, out)
	}

	// The PIN waits on its descriptor: it is in neither argv nor the
	// environment of the process that reads it.
	r, w, _ := os.Pipe()
	c := assh("ca", "approve", tpm, "--ca", ca, "--pin-fd", "3")
	c.ExtraFiles = []*os.File{r}
	var approveOut bytes.Buffer
	c.Stdout, c.Stderr = &approveOut, &approveOut
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	r.Close()
	w.Write(pin)
	for _, f := range []string{"cmdline", "environ"} {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/%s", c.Process.Pid, f))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, pin) {
			t.Fatalf("the PIN is in /proc/PID/%s", f)
		}
	}
	w.Close()
	if err := c.Wait(); err != nil || !strings.Contains(approveOut.String(), "Approved in slot 0 at generation 1") {
		t.Fatalf("approve: %v\n%s", err, approveOut.String())
	}
	s.out.Write(approveOut.Bytes())

	// An OpenSSH login through @cert-authority.
	client := filepath.Join(dir, "client")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", client).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	port := freePort(t)
	srv := start(t, "serve", tpm, "--ca", ca, "--listen", fmt.Sprintf("127.0.0.1:%d", port),
		"--authorized-keys", client+".pub", "--", "/bin/sh", "-c", "echo hello from $ASSH_USER")
	srv.wait(t, "listening on")
	caPub, _ := os.ReadFile(ca + ".pub")
	kh := filepath.Join(dir, "known_hosts")
	os.WriteFile(kh, []byte(fmt.Sprintf("@cert-authority [127.0.0.1]:%d %s", port, caPub)), 0o600)
	login, err := exec.Command("ssh", "-T", "-F", "/dev/null", "-i", client, "-p", fmt.Sprint(port),
		"-o", "UserKnownHostsFile="+kh, "-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes",
		"-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "someone@127.0.0.1").CombinedOutput()
	if err != nil || !strings.Contains(string(login), "hello from someone") {
		t.Fatalf("ssh: %v\n%s\n%s", err, login, srv.String())
	}
	s.out.WriteString(srv.String())

	// Combination Y boots: PCR 15 moves on. The agent finds no slot
	// approved, serves a temporary key and records the state; the move is
	// approved with the PIN, in both slots.
	sw.Reboot(t)
	extend(t, sw, 15, "combination Y")
	runDir := filepath.Join(dir, "run")
	if out := agentTemporary(t, s, sw, ca, runDir); !strings.Contains(out, "slot 0: PCR 15 not as approved; slot 1: no approved PCR state") {
		t.Fatalf("agent in Y before the move:\n%s", out)
	}
	values := filepath.Join(runDir, "agent.pcrs.json")
	out = s.must([][]byte{pin}, "ca", "approve", tpm, "--ca", ca, "--values", values, "--next-generation", "--pin-fd", "3")
	if !strings.Contains(out, "generation 2: every approval before it is revoked") || !strings.Contains(out, "Approved in slot 0 at generation 2") {
		t.Fatalf("the move:\n%s", out)
	}
	s.must([][]byte{pin}, "ca", "approve", tpm, "--ca", ca, "--slot", "1", "--values", values, "--pin-fd", "3")
	out = s.must(nil, "ca", "show", tpm, "--ca", ca)
	if !strings.Contains(out, "generation 1 (revoked)") || !strings.Contains(out, "counter is at generation 2") || !strings.Contains(out, "slot 1, PCR 7 and 15:") {
		t.Fatalf("show:\n%s", out)
	}

	sw.Reboot(t)
	extend(t, sw, 15, "combination Y")
	if out := agentSigns(t, s, sw, ca, runDir); !strings.Contains(out, "through slot 0") {
		t.Fatalf("agent in Y:\n%s", out)
	}

	// The OS of combination Y changed (PCR 14): slot 1 certifies.
	sw.Reboot(t)
	extend(t, sw, 15, "combination Y")
	extend(t, sw, 14, "another OS")
	if out := agentSigns(t, s, sw, ca, runDir); !strings.Contains(out, "through slot 1") {
		t.Fatalf("agent in Y with another OS:\n%s", out)
	}

	// Combination X again: its approval is revoked.
	sw.Reboot(t)
	if out := agentTemporary(t, s, sw, ca, filepath.Join(dir, "run-x")); !strings.Contains(out, "revoked") {
		t.Fatalf("agent in X after the move:\n%s", out)
	}

	// A PIN change: the old PIN opens nothing.
	s.must([][]byte{pin, newPIN}, "ca", "pin", tpm, "--ca", ca, "--pin-fd", "3", "--new-pin-fd", "4")
	if out, err := s.run([][]byte{pin}, "ca", "approve", tpm, "--ca", ca, "--pin-fd", "3"); err == nil || !strings.Contains(out, "wrong PIN") {
		t.Fatalf("approve with the old PIN: %v\n%s", err, out)
	}
	s.must([][]byte{newPIN}, "ca", "approve", tpm, "--ca", ca, "--pin-fd", "3")
	if out := s.must([][]byte{lockout}, "tpm", "da", tpm, "--lockout-auth-fd", "3", "--reset"); !strings.Contains(out, "0 of 3 failures") {
		t.Fatalf("reset:\n%s", out)
	}

	for _, secret := range [][]byte{pin, newPIN, lockout} {
		if bytes.Contains(s.out.Bytes(), secret) {
			t.Fatalf("%q is in an output", secret)
		}
		filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				if b, _ := os.ReadFile(path); bytes.Contains(b, secret) {
					t.Errorf("%q is in %s", secret, path)
				}
			}
			return nil
		})
	}
}
