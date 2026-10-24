package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/tpm2-trust/assh/internal/swtpmtest"
)

// TestMain is also the assh command, when a test starts this binary with
// ASSH_AS_MAIN=1, and its unprivileged half.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == childArg {
		if err := childMain(); err != nil {
			fmt.Fprintln(os.Stderr, "assh:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Getenv("ASSH_AS_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// output collects a running command's output.
type output struct {
	mu  sync.Mutex
	b   bytes.Buffer
	cmd *exec.Cmd
}

// stop ends the command and waits for it.
func (o *output) stop() {
	o.cmd.Process.Signal(syscall.SIGTERM)
	o.cmd.Wait()
}

func (o *output) Write(p []byte) (int, error) { o.mu.Lock(); defer o.mu.Unlock(); return o.b.Write(p) }

func (o *output) String() string { o.mu.Lock(); defer o.mu.Unlock(); return o.b.String() }

func (o *output) wait(t *testing.T, want string) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); !strings.Contains(o.String(), want); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("never said %q:\n%s", want, o.String())
		}
	}
}

func assh(args ...string) *exec.Cmd {
	c := exec.Command(os.Args[0], args...)
	c.Env = append(os.Environ(), "ASSH_AS_MAIN=1")
	return c
}

func run(t *testing.T, args ...string) string {
	t.Helper()
	out, err := assh(args...).CombinedOutput()
	if err != nil {
		t.Fatalf("assh %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// start runs assh in the background until the test ends.
func start(t *testing.T, args ...string) *output {
	t.Helper()
	c := assh(args...)
	out := &output{cmd: c}
	c.Stdout, c.Stderr = out, out
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(out.stop)
	return out
}

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// sshLogin logs in to the server at port with OpenSSH's client, as
// someone who trusts what known_hosts holds and nothing else.
func sshLogin(client, knownHosts string, port int) (string, error) {
	out, err := exec.Command("ssh", "-T", "-F", "/dev/null", "-i", client, "-p", fmt.Sprint(port),
		"-o", "UserKnownHostsFile="+knownHosts, "-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes",
		"-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "someone@127.0.0.1").CombinedOutput()
	return string(out), err
}

// offeredKey is the host key the server at port offers.
func offeredKey(t *testing.T, port int) ssh.PublicKey {
	t.Helper()
	var key ssh.PublicKey
	ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &ssh.ClientConfig{
		User: "nobody",
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = k
			return errors.New("seen")
		},
	})
	if key == nil {
		t.Fatalf("no host key from port %d", port)
	}
	return key
}

// The whole life with an authority elsewhere: a CA in the TPM with a
// window, approved; 'serve' certifies its host key and closes the window;
// OpenSSH's client trusts the CA and logs in. A second server in the same
// boot gets no certificate: it serves a temporary key, which ssh refuses
// until its fingerprint is checked and the key is in known_hosts. The
// recorded state is approved with a signature made by openssl. After a
// reboot the certified key is taken beside the temporary key's line; after
// another 'agent' lends its host key to whoever asks as sshd would.
func TestCommand(t *testing.T) {
	for _, tool := range []string{"ssh", "ssh-keygen", "openssl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	sw := swtpmtest.Start(t)
	dir := t.TempDir()
	auth, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(auth)
	writePEM(t, filepath.Join(dir, "auth.key"), "PRIVATE KEY", der)
	der, _ = x509.MarshalPKIXPublicKey(auth.Public())
	writePEM(t, filepath.Join(dir, "auth.pub"), "PUBLIC KEY", der)
	client := filepath.Join(dir, "client")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", client).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	ca := filepath.Join(dir, "ca.json")
	tpm := "--tpm=" + sw.Sock

	out := run(t, "ca", "create", tpm, "--out", ca, "--authority", filepath.Join(dir, "auth.pub"), "--pcrs", "0,7,15", "--window", "15")
	if !strings.Contains(out, "@cert-authority * ecdsa-sha2-nistp256 ") || !strings.Contains(out, "window: PCR 15") {
		t.Fatalf("create:\n%s", out)
	}
	if out, err := assh("ca", "slot", "--ca", ca, "--add", "1", "--pcrs", "0,7").CombinedOutput(); err == nil || !strings.Contains(string(out), "the window would not close it") {
		t.Fatalf("a slot without the window: %v\n%s", err, out)
	}
	if out := run(t, "ca", "slot", "--ca", ca, "--add", "1", "--pcrs", "7,15"); !strings.Contains(out, "slot 1: signs while PCR 7 and 15") {
		t.Fatalf("slot --add:\n%s", out)
	}
	run(t, "ca", "slot", "--ca", ca, "--remove", "1")
	run(t, "ca", "approve", tpm, "--ca", ca, "--authority-key", filepath.Join(dir, "auth.key"))
	if out := run(t, "ca", "show", tpm, "--ca", ca); !strings.Contains(out, "approved in slot 0 now: the CA signs") {
		t.Fatalf("show:\n%s", out)
	}

	port := freePort(t)
	state := filepath.Join(dir, "serve.pcrs.json")
	srv := start(t, "serve", tpm, "--ca", ca, "--listen", fmt.Sprintf("127.0.0.1:%d", port),
		"--authorized-keys", client+".pub", "--state", state,
		"--", "/bin/sh", "-c", "echo hello from $ASSH_USER")
	srv.wait(t, "listening on")
	if !strings.Contains(srv.String(), "PCR 15 is extended") || !strings.Contains(srv.String(), "through slot 0") {
		t.Fatalf("serve:\n%s", srv.String())
	}
	caPub, _ := os.ReadFile(ca + ".pub")
	kh := filepath.Join(dir, "known_hosts")
	os.WriteFile(kh, []byte(fmt.Sprintf("@cert-authority [127.0.0.1]:%d %s", port, caPub)), 0o600)
	if login, err := sshLogin(client, kh, port); err != nil || !strings.Contains(login, "hello from someone") {
		t.Fatalf("ssh: %v\n%s\n%s", err, login, srv.String())
	}

	// The window is closed: a second server serves a temporary key.
	port2 := freePort(t)
	second := start(t, "serve", tpm, "--ca", ca, "--listen", fmt.Sprintf("127.0.0.1:%d", port2),
		"--authorized-keys", client+".pub", "--state", state+".2", "--", "/bin/sh", "-c", "echo hello from $ASSH_USER")
	second.wait(t, "listening on")
	if !strings.Contains(second.String(), "is TEMPORARY") || !strings.Contains(second.String(), "slot 0: PCR 15 not as approved") || !strings.Contains(second.String(), "--values "+state+".2") {
		t.Fatalf("second serve:\n%s", second.String())
	}
	kh2 := filepath.Join(dir, "known_hosts2")
	caLine := fmt.Sprintf("@cert-authority [127.0.0.1]:%d %s", port2, caPub)
	os.WriteFile(kh2, []byte(caLine), 0o600)
	if login, err := sshLogin(client, kh2, port2); err == nil || !strings.Contains(login, "Host key verification failed") {
		t.Fatalf("ssh took the temporary key: %v\n%s", err, login)
	}
	temp := offeredKey(t, port2)
	if !strings.Contains(second.String(), "host key "+ssh.FingerprintSHA256(temp)+" is TEMPORARY") {
		t.Fatalf("the temporary key offered, %s, is not the one logged:\n%s", ssh.FingerprintSHA256(temp), second.String())
	}
	os.WriteFile(kh2, []byte(caLine+fmt.Sprintf("[127.0.0.1]:%d %s", port2, ssh.MarshalAuthorizedKey(temp))), 0o600)
	if login, err := sshLogin(client, kh2, port2); err != nil || !strings.Contains(login, "hello from someone") {
		t.Fatalf("ssh with the temporary key in known_hosts: %v\n%s", err, login)
	}
	second.stop()

	digest := filepath.Join(dir, "digest")
	run(t, "ca", "approve", tpm, "--ca", ca, "--values", state+".2", "--digest", digest)
	sig := filepath.Join(dir, "sig")
	if out, err := exec.Command("openssl", "pkeyutl", "-sign", "-inkey", filepath.Join(dir, "auth.key"),
		"-pkeyopt", "digest:sha256", "-in", digest, "-out", sig).CombinedOutput(); err != nil {
		t.Fatalf("openssl: %v %s", err, out)
	}
	if out := run(t, "ca", "approve", tpm, "--ca", ca, "--values", state+".2", "--signature", sig); !strings.Contains(out, "Approved in slot 0: 2 state(s)") {
		t.Fatalf("approve:\n%s", out)
	}

	// The next boot certifies again: the client takes the certificate
	// beside the line of the temporary key it accepted before.
	srv.stop()
	sw.Reboot(t)
	third := start(t, "serve", tpm, "--ca", ca, "--listen", fmt.Sprintf("127.0.0.1:%d", port2),
		"--authorized-keys", client+".pub", "--", "/bin/sh", "-c", "echo hello from $ASSH_USER")
	third.wait(t, "listening on")
	if !strings.Contains(third.String(), "through slot 0") {
		t.Fatalf("serve after the reboot:\n%s", third.String())
	}
	if login, err := sshLogin(client, kh2, port2); err != nil || !strings.Contains(login, "hello from someone") {
		t.Fatalf("ssh with the certified key beside the temporary key's line: %v\n%s", err, login)
	}
	third.stop()

	sw.Reboot(t)
	runDir := filepath.Join(dir, "run")
	ag := start(t, "agent", tpm, "--ca", ca, "--dir", runDir, "--uid", fmt.Sprint(os.Getuid()))
	ag.wait(t, "agent at")
	c, err := net.Dial("unix", filepath.Join(runDir, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	pubLine, _ := os.ReadFile(filepath.Join(runDir, "host.pub"))
	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubLine)
	if err != nil {
		t.Fatal(err)
	}
	s, err := sshagent.NewClient(c).Sign(pub, []byte("exchange hash"))
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Verify([]byte("exchange hash"), s); err != nil {
		t.Fatal(err)
	}
	certLine, _ := os.ReadFile(filepath.Join(runDir, "host-cert.pub"))
	certKey, _, _, _, err := ssh.ParseAuthorizedKey(certLine)
	if err != nil {
		t.Fatal(err)
	}
	caKey, _, _, _, _ := ssh.ParseAuthorizedKey(caPub)
	if cert, ok := certKey.(*ssh.Certificate); !ok || !bytes.Equal(cert.SignatureKey.Marshal(), caKey.Marshal()) || !bytes.Equal(cert.Key.Marshal(), pub.Marshal()) {
		t.Fatalf("certificate %v", certKey)
	}
}
