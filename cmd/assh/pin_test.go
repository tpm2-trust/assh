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
	// approved with the PIN, once for both slots.
	sw.Reboot(t)
	extend(t, sw, 15, "combination Y")
	runDir := filepath.Join(dir, "run")
	if out := agentTemporary(t, s, sw, ca, runDir); !strings.Contains(out, "slot 0: PCR 15 not as approved; slot 1: no approved PCR state") {
		t.Fatalf("agent in Y before the move:\n%s", out)
	}
	values := filepath.Join(runDir, "agent.pcrs.json")
	out = s.must([][]byte{pin}, "ca", "approve", tpm, "--ca", ca, "--slot", "0,1", "--values", values, "--next-generation", "--pin-fd", "3")
	if !strings.Contains(out, "generation 2: every approval before it is revoked") || !strings.Contains(out, "Approved in slots 0 and 1 at generation 2") {
		t.Fatalf("the move:\n%s", out)
	}
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

// The first boot of a machine, before its CA exists: the agent, with
// assh.conf naming the slots, serves a temporary key, records the PCRs of
// the slots and closes the window. In the same boot the CA is created and
// this recorded state approved in both slots with one PIN - and still
// nothing certifies before the next boot (the window is closed). The next
// boot, in the same state, certifies through slot 0.
func TestAgentBeforeTheCA(t *testing.T) {
	sw := swtpmtest.Start(t)
	dir := t.TempDir()
	s := &secrets{t: t}
	ca, state, runDir := filepath.Join(dir, "ca.json"), filepath.Join(dir, "agent.pcrs.json"), filepath.Join(dir, "run")
	pin, lockout := []byte("pin-first-8Hk2"), []byte("lockout-first-Wd61")
	conf := filepath.Join(dir, "assh.conf")
	os.WriteFile(conf, []byte(fmt.Sprintf(`ASSH_TPM=%s
ASSH_CA=%s
ASSH_AUTHORITY_TPM=yes
ASSH_CA_SLOT_0=0,7,15
ASSH_CA_SLOT_1=7,15
ASSH_CA_WINDOW=15
ASSH_STATE=%s
ASSH_AGENT_DIR=%s
ASSH_AGENT_UID=%d
`, sw.Sock, ca, state, runDir, os.Getuid())), 0o644)
	boot := func() { extend(t, sw, 15, "combination:a") } // what the initrd measures

	boot()
	ag := start(t, "agent", "--config", conf)
	ag.wait(t, "agent at")
	ag.stop()
	if !strings.Contains(ag.String(), "is TEMPORARY: there is no CA at "+ca+" yet") || !strings.Contains(ag.String(), "PCR 15 is extended") {
		t.Fatalf("the agent before the CA:\n%s", ag.String())
	}
	if _, err := os.Stat(filepath.Join(runDir, "host-cert.pub")); err == nil {
		t.Fatal("a certificate without a CA")
	}
	if b, _ := os.ReadFile(filepath.Join(runDir, "sshd.conf")); string(b) != fmt.Sprintf("HostKey %s/host.pub\nHostKeyAgent %s/agent.sock\nHostKeyAlgorithms ecdsa-sha2-nistp256\n", runDir, runDir) {
		t.Fatalf("sshd.conf of a temporary key:\n%s", b)
	}
	b, err := os.ReadFile(state)
	if err != nil || !strings.Contains(string(b), `"0"`) || !strings.Contains(string(b), `"7"`) || !strings.Contains(string(b), `"15"`) {
		t.Fatalf("the state recorded: %v\n%s", err, b)
	}

	s.must([][]byte{lockout}, "tpm", "da", "--config", conf, "--new-lockout-auth-fd", "3", "--max-tries", "3", "--recovery", "1800", "--lockout-recovery", "1800")
	s.must([][]byte{pin}, "ca", "create", "--config", conf, "--pin-fd", "3")
	if out := s.must([][]byte{pin}, "ca", "approve", "--config", conf, "--values", state, "--pin-fd", "3"); !strings.Contains(out, "Approved in slots 0 and 1 at generation 1") {
		t.Fatalf("approve:\n%s", out)
	}
	if out := run(t, "ca", "show", "--config", conf); !strings.Contains(out, "\n  @cert-authority * ecdsa-sha2-nistp256 ") {
		t.Fatalf("show names no known_hosts line:\n%s", out)
	}
	// The window is closed: no certificate in this boot; the state of the
	// boot's first start stays as it was.
	ag = start(t, "agent", "--config", conf)
	ag.wait(t, "agent at")
	ag.stop()
	if !strings.Contains(ag.String(), "TEMPORARY") || !strings.Contains(ag.String(), "slot 0: PCR 15 not as approved") || !strings.Contains(ag.String(), "stays in "+state) {
		t.Fatalf("the agent in the boot of the creation:\n%s", ag.String())
	}
	if again, _ := os.ReadFile(state); !bytes.Equal(again, b) {
		t.Fatal("a restart replaced the state of the boot's first start")
	}
	os.Remove(state) // /run is empty after a reboot

	sw.Reboot(t)
	boot()
	ag = start(t, "agent", "--config", conf)
	ag.wait(t, "agent at")
	ag.stop()
	if !strings.Contains(ag.String(), "through slot 0") {
		t.Fatalf("the next boot:\n%s", ag.String())
	}
	if _, err := os.Stat(filepath.Join(runDir, "host-cert.pub")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(runDir, "sshd.conf")); !strings.Contains(string(b), "HostCertificate "+runDir+"/host-cert.pub\n") ||
		!strings.HasSuffix(string(b), "HostKeyAlgorithms ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp256\n") {
		t.Fatalf("sshd.conf of a certified key:\n%s", b)
	}
	if bytes.Contains(s.out.Bytes(), pin) || bytes.Contains(s.out.Bytes(), lockout) {
		t.Fatal("a secret in the output")
	}
}

// A TPM whose only active bank is SHA-1 (an old ThinkPad's): with
// ASSH_CA_BANK=auto nothing reads it until 'tpm sha1 --allow' - the agent
// serves a temporary key and records nothing, 'ca create' refuses; once
// allowed, the CA reads SHA-1 and the next boot certifies; forbidden again,
// the agent is back to a temporary key.
func TestSHA1(t *testing.T) {
	sw := swtpmtest.StartBanks(t, "sha1")
	dir := t.TempDir()
	s := &secrets{t: t}
	ca, state, runDir := filepath.Join(dir, "ca.json"), filepath.Join(dir, "agent.pcrs.json"), filepath.Join(dir, "run")
	pin, lockout := []byte("pin-sha1-4Jq9"), []byte("lockout-sha1-Pz73")
	conf := filepath.Join(dir, "assh.conf")
	os.WriteFile(conf, []byte(fmt.Sprintf(`ASSH_TPM=%s
ASSH_CA=%s
ASSH_CA_BANK=auto
ASSH_AUTHORITY_TPM=yes
ASSH_CA_SLOT_0=0,7,15
ASSH_CA_WINDOW=15
ASSH_STATE=%s
ASSH_AGENT_DIR=%s
ASSH_AGENT_UID=%d
`, sw.Sock, ca, state, runDir, os.Getuid())), 0o644)
	agent := func() string {
		t.Helper()
		ag := start(t, "agent", "--config", conf)
		ag.wait(t, "agent at")
		ag.stop()
		return ag.String()
	}

	s.must([][]byte{lockout}, "tpm", "da", "--config", conf, "--new-lockout-auth-fd", "3", "--max-tries", "3", "--recovery", "1800", "--lockout-recovery", "1800")
	if out := agent(); !strings.Contains(out, "is TEMPORARY: no CA at "+ca+", and none can be made") || !strings.Contains(out, "sha1 is not allowed") || !strings.Contains(out, "PCR 15 is extended") {
		t.Fatalf("the agent, sha1 not allowed:\n%s", out)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatalf("a state recorded: %v", err)
	}
	if out, err := s.run([][]byte{pin}, "ca", "create", "--config", conf, "--pin-fd", "3"); err == nil || !strings.Contains(out, "sha1 is not allowed") {
		t.Fatalf("ca create, sha1 not allowed: %v\n%s", err, out)
	}
	if out := run(t, "tpm", "sha1", "--config", conf, "--allow"); !strings.Contains(out, "active PCR banks: sha1\n") || !strings.Contains(out, "sha1 allowed: yes") || !strings.Contains(out, "bank auto: sha1") {
		t.Fatalf("tpm sha1 --allow:\n%s", out)
	}

	sw.Reboot(t)
	if out := agent(); !strings.Contains(out, "there is no CA at "+ca+" yet") {
		t.Fatalf("the agent, sha1 allowed:\n%s", out)
	}
	if b, err := os.ReadFile(state); err != nil || !strings.Contains(string(b), `"bank": "sha1"`) {
		t.Fatalf("the state: %v\n%s", err, b)
	}
	s.must([][]byte{pin}, "ca", "create", "--config", conf, "--pin-fd", "3")
	s.must([][]byte{pin}, "ca", "approve", "--config", conf, "--values", state, "--pin-fd", "3")
	if out := run(t, "ca", "show", "--config", conf); !strings.Contains(out, "(sha1)") {
		t.Fatalf("ca show:\n%s", out)
	}
	os.Remove(state)

	sw.Reboot(t)
	if out := agent(); !strings.Contains(out, "through slot 0") {
		t.Fatalf("the next boot:\n%s", out)
	}
	os.Remove(state)

	if out := run(t, "tpm", "sha1", "--config", conf, "--forbid"); !strings.Contains(out, "sha1 allowed: no") {
		t.Fatalf("tpm sha1 --forbid:\n%s", out)
	}
	sw.Reboot(t)
	if out := agent(); !strings.Contains(out, "is TEMPORARY: the CA reads sha1, and sha1 is no longer allowed") {
		t.Fatalf("the agent, sha1 forbidden again:\n%s", out)
	}
	if bytes.Contains(s.out.Bytes(), pin) || bytes.Contains(s.out.Bytes(), lockout) {
		t.Fatal("a secret in the output")
	}
}

// A move ahead: in a boot of combination a, the state of combination b is
// approved with the next generation (--events: PCR 15 as b's initrd leaves
// it), so b's next boot certifies at once and a's no longer. Then 'ca
// remove' takes the CA, its PIN index and counter; a new CA is created at
// the same handles.
func TestMoveAhead(t *testing.T) {
	sw := swtpmtest.Start(t)
	dir := t.TempDir()
	s := &secrets{t: t}
	ca, state, runDir := filepath.Join(dir, "ca.json"), filepath.Join(dir, "agent.pcrs.json"), filepath.Join(dir, "run")
	pin, lockout := []byte("pin-ahead-3Fv8"), []byte("lockout-ahead-Qe25")
	conf := filepath.Join(dir, "assh.conf")
	os.WriteFile(conf, []byte(fmt.Sprintf(`ASSH_TPM=%s
ASSH_CA=%s
ASSH_AUTHORITY_TPM=yes
ASSH_CA_SLOT_0=0,7,15
ASSH_CA_WINDOW=15
ASSH_STATE=%s
ASSH_AGENT_DIR=%s
ASSH_AGENT_UID=%d
`, sw.Sock, ca, state, runDir, os.Getuid())), 0o644)
	boot := func(name string) string {
		t.Helper()
		sw.Reboot(t)
		os.Remove(state)
		extend(t, sw, 15, "combination:"+name)
		extend(t, sw, 15, "sealed")
		ag := start(t, "agent", "--config", conf)
		ag.wait(t, "agent at")
		ag.stop()
		return ag.String()
	}

	boot("a")
	s.must([][]byte{lockout}, "tpm", "da", "--config", conf, "--new-lockout-auth-fd", "3", "--max-tries", "3", "--recovery", "1800", "--lockout-recovery", "1800")
	s.must([][]byte{pin}, "ca", "create", "--config", conf, "--pin-fd", "3")
	s.must([][]byte{pin}, "ca", "approve", "--config", conf, "--values", state, "--pin-fd", "3")
	if out := boot("a"); !strings.Contains(out, "through slot 0") {
		t.Fatalf("a, approved:\n%s", out)
	}
	if out, err := s.run([][]byte{pin}, "ca", "approve", "--config", conf, "--values", state, "--events", "14:x", "--pin-fd", "3"); err == nil || !strings.Contains(out, "no slot of the CA reads PCR 14") {
		t.Fatalf("--events for a PCR no slot reads: %v\n%s", err, out)
	}
	s.must([][]byte{pin}, "ca", "approve", "--config", conf, "--values", state,
		"--events", "15:combination:b", "--events", "15:sealed", "--next-generation", "--pin-fd", "3")
	if out := boot("b"); !strings.Contains(out, "through slot 0") {
		t.Fatalf("b, approved ahead:\n%s", out)
	}
	if out := boot("a"); !strings.Contains(out, "TEMPORARY") {
		t.Fatalf("a after the move:\n%s", out)
	}

	out := run(t, "ca", "remove", "--config", conf)
	for _, want := range []string{"removed NV index 0x01802913", "removed NV index 0x01802912", "removed " + ca + "\n"} {
		if !strings.Contains(out, want) {
			t.Fatalf("ca remove:\n%s", out)
		}
	}
	if out := run(t, "ca", "remove", "--config", conf); !strings.Contains(out, "nothing to remove") {
		t.Fatalf("ca remove again:\n%s", out)
	}
	boot("a")
	s.must([][]byte{pin}, "ca", "create", "--config", conf, "--pin-fd", "3")
	if bytes.Contains(s.out.Bytes(), pin) || bytes.Contains(s.out.Bytes(), lockout) {
		t.Fatal("a secret in the output")
	}
}

// An RSA host key: sshd.conf offers rsa-sha2-512 only where the TPM has
// SHA-512 (swtpm has), rsa-sha2-256 always, never ssh-rsa.
func TestAgentRSA(t *testing.T) {
	sw := swtpmtest.Start(t)
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run")
	conf := filepath.Join(dir, "assh.conf")
	os.WriteFile(conf, []byte(fmt.Sprintf(`ASSH_TPM=%s
ASSH_CA=%s
ASSH_HOSTKEY_TYPE=rsa2048
ASSH_CA_SLOT_0=7,15
ASSH_CA_WINDOW=15
ASSH_AGENT_DIR=%s
ASSH_AGENT_UID=%d
`, sw.Sock, filepath.Join(dir, "ca.json"), runDir, os.Getuid())), 0o644)
	ag := start(t, "agent", "--config", conf)
	ag.wait(t, "agent at")
	ag.stop()
	if b, _ := os.ReadFile(filepath.Join(runDir, "sshd.conf")); !strings.HasSuffix(string(b), "HostKeyAlgorithms rsa-sha2-512,rsa-sha2-256\n") {
		t.Fatalf("sshd.conf:\n%s\n%s", b, ag.String())
	}
}
