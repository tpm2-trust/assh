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

// The whole life with an authority elsewhere: a CA in the TPM, approved,
// signing from the boot after its creation; 'serve' certifies its host key
// and closes the window;
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

	slot1 := func(pcrs string) string {
		conf := filepath.Join(dir, "slot1-"+pcrs+".conf")
		if err := os.WriteFile(conf, []byte("ASSH_CA_SLOT_1="+pcrs+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return "--config=" + conf
	}
	create := []string{"ca", "create", tpm, "--authority", filepath.Join(dir, "auth.pub"), "--pcrs", "0,7,15"}
	out := run(t, append(create, slot1("7,15"), "--out", ca)...)
	if !strings.Contains(out, "@cert-authority * ecdsa-sha2-nistp256 ") || !strings.Contains(out, "window: NV index 0x01802915") ||
		!strings.Contains(out, "slot 1: signs while PCR 7 and 15") || !strings.Contains(out, "it signs from the next boot on") {
		t.Fatalf("create:\n%s", out)
	}
	if out, err := assh("ca", "approve", "--yes", tpm, "--ca", ca, "--slot", "0,1", "--digest", filepath.Join(dir, "d")).CombinedOutput(); err == nil || !strings.Contains(string(out), "for one slot") {
		t.Fatalf("a digest for two slots: %v\n%s", err, out)
	}
	if out := run(t, "ca", "approve", "--yes", tpm, "--ca", ca, "--slot", "0,1", "--authority-key", filepath.Join(dir, "auth.key")); !strings.Contains(out, "Approved in slots 0 and 1: 2 state(s)") {
		t.Fatalf("approve two slots:\n%s", out)
	}
	for _, bad := range []string{"0,0", "0,3", "x"} {
		if out, err := assh("ca", "approve", "--yes", tpm, "--ca", ca, "--slot", bad, "--authority-key", filepath.Join(dir, "auth.key")).CombinedOutput(); err == nil {
			t.Fatalf("--slot %s: %s", bad, out)
		}
	}
	if out := run(t, "ca", "show", tpm, "--ca", ca); !strings.Contains(out, "The window is closed until the next boot") || strings.Contains(out, "the CA signs.") {
		t.Fatalf("show in the boot of the creation:\n%s", out)
	}
	sw.Reboot(t)
	if out := run(t, "ca", "show", tpm, "--ca", ca); !strings.Contains(out, "approved in slot 0 now, and the window is open: the CA signs") {
		t.Fatalf("show:\n%s", out)
	}

	port := freePort(t)
	state := filepath.Join(dir, "serve.pcrs.json")
	srv := start(t, "serve", tpm, "--ca", ca, "--listen", fmt.Sprintf("127.0.0.1:%d", port),
		"--authorized-keys", client+".pub", "--state", state,
		"--", "/bin/sh", "-c", "echo hello from $ASSH_USER")
	srv.wait(t, "listening on")
	if !strings.Contains(srv.String(), "the window is closed (NV index 0x01802915)") || !strings.Contains(srv.String(), "through slot 0") {
		t.Fatalf("serve:\n%s", srv.String())
	}
	caPub, _ := os.ReadFile(ca + ".pub")
	kh := filepath.Join(dir, "known_hosts")
	os.WriteFile(kh, []byte(fmt.Sprintf("@cert-authority [127.0.0.1]:%d %s", port, caPub)), 0o600)
	if login, err := sshLogin(client, kh, port); err != nil || !strings.Contains(login, "hello from someone") {
		t.Fatalf("ssh: %v\n%s\n%s", err, login, srv.String())
	}

	// The window is closed: a second server serves a temporary key, in a
	// state of PCR 15 not approved yet (approved below, from its record).
	extend(t, sw, 15, "another combination")
	port2 := freePort(t)
	second := start(t, "serve", tpm, "--ca", ca, "--listen", fmt.Sprintf("127.0.0.1:%d", port2),
		"--authorized-keys", client+".pub", "--state", state+".2", "--", "/bin/sh", "-c", "echo hello from $ASSH_USER")
	second.wait(t, "listening on")
	if !strings.Contains(second.String(), "is TEMPORARY: the CA's window is closed until the next boot") {
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
	run(t, "ca", "approve", "--yes", tpm, "--ca", ca, "--values", state+".2", "--digest", digest)
	sig := filepath.Join(dir, "sig")
	if out, err := exec.Command("openssl", "pkeyutl", "-sign", "-inkey", filepath.Join(dir, "auth.key"),
		"-pkeyopt", "digest:sha256", "-in", digest, "-out", sig).CombinedOutput(); err != nil {
		t.Fatalf("openssl: %v %s", err, out)
	}
	if out := run(t, "ca", "approve", "--yes", tpm, "--ca", ca, "--values", state+".2", "--signature", sig); !strings.Contains(out, "Approved in slot 0: 3 state(s)") {
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

// assh.conf in place of the flags: 'ca create' makes every slot it names,
// 'ca approve' approves them all, every command takes the file's slots
// after an edit (the CA file stays as it is), and 'serve' takes its CA,
// address, keys and certificate name from it; a flag given wins over the
// file, and a --config file that is not there is an error.
func TestConfig(t *testing.T) {
	for _, tool := range []string{"ssh", "ssh-keygen"} {
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
	port := freePort(t)
	conf := filepath.Join(dir, "assh.conf")
	write := func(slot1 string) {
		t.Helper()
		c := fmt.Sprintf(`# a test's
ASSH_TPM=%s
ASSH_CA=%s
ASSH_CA_SLOT_0=0,2,7,15
ASSH_CA_SLOT_1=%s
ASSH_AUTHORITY=%s
ASSH_LISTEN=127.0.0.1:%d
ASSH_AUTHORIZED_KEYS=%s
ASSH_KEY_ID="configured host"
ASSH_STATE=%s
`, sw.Sock, ca, slot1, filepath.Join(dir, "auth.pub"), port, client+".pub", filepath.Join(dir, "state.json"))
		if err := os.WriteFile(conf, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("7,15")

	if out := run(t, "ca", "create", "--config", conf); !strings.Contains(out, "slot 0: signs while PCR 0, 2, 7 and 15") || !strings.Contains(out, "slot 1: signs while PCR 7 and 15") {
		t.Fatalf("create:\n%s", out)
	}
	if out := run(t, "ca", "approve", "--yes", "--config="+conf, "--authority-key", filepath.Join(dir, "auth.key")); !strings.Contains(out, "Approved in slots 0 and 1: 2 state(s)") {
		t.Fatalf("approve:\n%s", out)
	}
	write("0,7,15")
	for range 2 {
		if out := run(t, "ca", "show", "--config", conf); !strings.Contains(out, "the CA's slots are assh.conf's") || !strings.Contains(out, "slot 1: signs while PCR 0, 7 and 15 (sha256) hold an approved state; 0 approved") || !strings.Contains(out, "slot 0: signs while PCR 0, 2, 7 and 15 (sha256) hold an approved state; 1 approved") {
			t.Fatalf("show after the edit:\n%s", out)
		}
	}
	if b, _ := os.ReadFile(ca); !strings.Contains(string(b), `"slot": 1`) || strings.Count(string(b), `"signature"`) != 2 {
		t.Fatalf("the CA file changed: %s", b)
	}
	if out, err := assh("ca", "show", "--config", conf, "--ca", filepath.Join(dir, "none.json")).CombinedOutput(); err == nil || !strings.Contains(string(out), "none.json") {
		t.Fatalf("--ca wins: %v\n%s", err, out)
	}
	if out, err := assh("ca", "show", "--config", filepath.Join(dir, "none.conf")).CombinedOutput(); err == nil || !strings.Contains(string(out), "none.conf") {
		t.Fatalf("a --config that is not there: %v\n%s", err, out)
	}

	sw.Reboot(t) // a CA signs from the boot after its creation
	srv := start(t, "serve", "--config", conf, "--", "/bin/sh", "-c", "echo hello from $ASSH_USER")
	srv.wait(t, "listening on")
	if !strings.Contains(srv.String(), "through slot 0") {
		t.Fatalf("serve:\n%s", srv.String())
	}
	cert, ok := offeredKey(t, port).(*ssh.Certificate)
	if !ok || cert.KeyId != "configured host slot=0 pcrs=0,2,7,15" {
		t.Fatalf("the host certificate: %v", cert)
	}
	pub, _ := os.ReadFile(ca + ".pub")
	known := filepath.Join(dir, "known_hosts")
	os.WriteFile(known, []byte("@cert-authority 127.0.0.1 "+string(pub)), 0o644)
	if out, err := sshLogin(client, known, port); err != nil || !strings.Contains(out, "hello from someone") {
		t.Fatalf("login: %v\n%s", err, out)
	}
}
