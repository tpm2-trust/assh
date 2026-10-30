package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/tpm2-trust/assh/internal/swtpmtest"
)

// authorityFiles writes an ECDSA authority's key and public key into dir.
func authorityFiles(t *testing.T, dir string) (key, pub string) {
	t.Helper()
	auth, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(auth)
	key, pub = filepath.Join(dir, "auth.key"), filepath.Join(dir, "auth.pub")
	writePEM(t, key, "PRIVATE KEY", der)
	der, _ = x509.MarshalPKIXPublicKey(auth.Public())
	writePEM(t, pub, "PUBLIC KEY", der)
	return key, pub
}

// The window closes however the agent ends: a host key type it does not
// know, a CA file it cannot read - and 'assh close', which the unit runs
// after the agent, closes it on its own, with no CA there or an assh.conf
// that does not parse.
func TestWindowClosedOnError(t *testing.T) {
	sw := swtpmtest.Start(t)
	dir := t.TempDir()
	key, pub := authorityFiles(t, dir)
	ca, runDir := filepath.Join(dir, "ca.json"), filepath.Join(dir, "run")
	conf := filepath.Join(dir, "assh.conf")
	os.WriteFile(conf, []byte(fmt.Sprintf("ASSH_TPM=%s\nASSH_CA=%s\nASSH_CA_SLOT_0=7\nASSH_AUTHORITY=%s\nASSH_AGENT_DIR=%s\nASSH_AGENT_UID=%d\n",
		sw.Sock, ca, pub, runDir, os.Getuid())), 0o644)
	run(t, "ca", "create", "--config", conf)
	run(t, "ca", "approve", "--yes", "--config", conf, "--authority-key", key)
	open := func() bool {
		t.Helper()
		out := run(t, "ca", "show", "--config", conf)
		return strings.Contains(out, "the window is open: the CA signs")
	}

	sw.Reboot(t)
	if !open() {
		t.Fatal("the window is not open in the boot after the creation")
	}
	if out, err := assh("agent", "--config", conf, "--key-type", "nonsense").CombinedOutput(); err == nil || !strings.Contains(string(out), "the window is closed") {
		t.Fatalf("an agent that fails: %v\n%s", err, out)
	}
	if open() {
		t.Fatal("an agent that failed left the window open")
	}

	sw.Reboot(t)
	good, _ := os.ReadFile(ca)
	os.WriteFile(ca, []byte("{not a CA"), 0o600)
	if out, err := assh("agent", "--config", conf).CombinedOutput(); err == nil || !strings.Contains(string(out), "the window is closed") {
		t.Fatalf("an agent with an unreadable CA file: %v\n%s", err, out)
	}
	os.WriteFile(ca, good, 0o600)
	if open() {
		t.Fatal("an unreadable CA file left the window open")
	}

	sw.Reboot(t)
	os.WriteFile(filepath.Join(dir, "broken.conf"), []byte("ASSH_NOPE=1\n"), 0o644)
	if out, err := assh("close", "--tpm", sw.Sock, "--config", filepath.Join(dir, "broken.conf")).CombinedOutput(); err == nil || !strings.Contains(string(out), "closing the default window index") {
		t.Fatalf("close with an assh.conf that does not parse: %v\n%s", err, out)
	}
	if open() {
		t.Fatal("close left the window open")
	}
	if out := run(t, "close", "--config", conf); strings.Contains(out, "error") {
		t.Fatalf("close twice:\n%s", out)
	}
	run(t, "close", "--tpm", sw.Sock, "--ca", filepath.Join(dir, "none.json"))
}

// An approval made where the key is: 'ca approve --digest' writes the
// statement beside the digest, 'ca sign' signs what it says - refusing a
// statement for another authority - and 'ca approve --signature' takes it.
func TestStatementSign(t *testing.T) {
	sw := swtpmtest.Start(t)
	dir := t.TempDir()
	key, pub := authorityFiles(t, dir)
	ca := filepath.Join(dir, "ca.json")
	tpm := "--tpm=" + sw.Sock
	run(t, "ca", "create", tpm, "--out", ca, "--authority", pub, "--pcrs", "7")
	digest, sig := filepath.Join(dir, "d"), filepath.Join(dir, "sig")
	out := run(t, "ca", "approve", tpm, "--ca", ca, "--digest", digest)
	if !strings.Contains(out, "slot 0: the CA signs while these PCRs (sha256) hold:") || !strings.Contains(out, "ca sign") {
		t.Fatalf("approve --digest:\n%s", out)
	}
	otherKey, _ := authorityFiles(t, t.TempDir())
	if out, err := assh("ca", "sign", "--yes", "--authority-key", otherKey, "--statement", digest+".statement", "--signature", sig).CombinedOutput(); err == nil || !strings.Contains(string(out), "is for the authority") {
		t.Fatalf("another authority's key: %v\n%s", err, out)
	}
	if out := run(t, "ca", "sign", "--yes", "--authority-key", key, "--statement", digest+".statement", "--signature", sig); !strings.Contains(out, "PCR  7") {
		t.Fatalf("ca sign:\n%s", out)
	}
	if out := run(t, "ca", "approve", tpm, "--ca", ca, "--signature", sig); !strings.Contains(out, "Approved in slot 0: 1 state(s)") {
		t.Fatalf("approve --signature:\n%s", out)
	}
}

// A slot whose signed PCRs' key is not ASSH_PCR_KEY is not approved: the
// CA file could name root's key.
func TestSignedKeyChecked(t *testing.T) {
	sw := swtpmtest.Start(t)
	dir := t.TempDir()
	key, pub := authorityFiles(t, dir)
	pcrKey := func(name string) string {
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		p := filepath.Join(dir, name)
		writePEM(t, p, "PUBLIC KEY", der)
		return p
	}
	build, other := pcrKey("build.pem"), pcrKey("other.pem")
	conf := filepath.Join(dir, "assh.conf")
	write := func(k string) {
		os.WriteFile(conf, []byte(fmt.Sprintf("ASSH_TPM=%s\nASSH_CA=%s\nASSH_AUTHORITY=%s\nASSH_CA_SLOT_0=7\nASSH_CA_SLOT_0_SIGNED=11\nASSH_PCR_KEY=%s\n",
			sw.Sock, filepath.Join(dir, "ca.json"), pub, k)), 0o644)
	}
	write(build)
	run(t, "ca", "create", "--config", conf)
	write(other)
	if out, err := assh("ca", "approve", "--yes", "--config", conf, "--authority-key", key).CombinedOutput(); err == nil || !strings.Contains(string(out), "not by ASSH_PCR_KEY") {
		t.Fatalf("approve with another ASSH_PCR_KEY: %v\n%s", err, out)
	}
	write(build)
	run(t, "ca", "approve", "--yes", "--config", conf, "--authority-key", key)
}

// 'ca remove' leaves what is not defined as aSSH's and says so; --force
// removes it, after showing it.
func TestRemoveForce(t *testing.T) {
	sw := swtpmtest.Start(t)
	c, err := transport.OpenTPM(sw.Sock)
	if err != nil {
		t.Fatal(err)
	}
	leftover := tpm2.TPMSNVPublic{NVIndex: 0x01802912, NameAlg: tpm2.TPMAlgSHA256, DataSize: 8,
		Attributes: tpm2.TPMANV{NT: tpm2.TPMNTCounter, OwnerWrite: true, OwnerRead: true, NoDA: true}}
	_, err = tpm2.NVDefineSpace{AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)}, PublicInfo: tpm2.New2B(leftover)}.Execute(c)
	c.Close()
	if err != nil {
		t.Fatal(err)
	}
	none := filepath.Join(t.TempDir(), "none.json")
	tpm := "--tpm=" + sw.Sock
	if out, err := assh("ca", "remove", tpm, "--ca", none).CombinedOutput(); err == nil || !strings.Contains(string(out), "--force") {
		t.Fatalf("a leftover without --force: %v\n%s", err, out)
	}
	out := run(t, "ca", "remove", tpm, "--ca", none, "--force", "--yes")
	if !strings.Contains(out, "At aSSH's counter handle 0x01802912: an NV index of 8 bytes") || !strings.Contains(out, "removed NV index 0x01802912") {
		t.Fatalf("--force:\n%s", out)
	}
	if out := run(t, "ca", "remove", tpm, "--ca", none); !strings.Contains(out, "nothing to remove") {
		t.Fatalf("after --force:\n%s", out)
	}
}
