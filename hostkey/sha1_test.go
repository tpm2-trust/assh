package hostkey

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/tpm2-trust/assh/internal/swtpmtest"
)

// Auto is SHA-256 where it is active, the flag or not; SHA-1 only where it
// is the one bank and allowed; an index of another kind at SHA1Handle
// allows nothing.
func TestResolveBank(t *testing.T) {
	both := swtpmtest.StartBanks(t, "sha1", "sha256").Open(t)
	if b, err := ResolveBank(both, Auto); err != nil || b != SHA256 {
		t.Fatalf("both banks: %v %v", b, err)
	}
	if err := AllowSHA1(both, true); err != nil {
		t.Fatal(err)
	}
	if b, err := ResolveBank(both, Auto); err != nil || b != SHA256 {
		t.Fatalf("both banks, sha1 allowed: %v %v", b, err)
	}

	old := swtpmtest.StartBanks(t, "sha1").Open(t)
	if active, err := ActiveBanks(old); err != nil || !slices.Equal(active, []Bank{SHA1}) {
		t.Fatalf("active %v %v", active, err)
	}
	if _, err := ResolveBank(old, Auto); !errors.Is(err, ErrSHA1NotAllowed) {
		t.Fatalf("not allowed: %v", err)
	}
	if _, err := CreateCA(old, authority(t).Public(), CAOptions{Type: P256, Bank: Auto, PCRs: []int{7}}); !errors.Is(err, ErrSHA1NotAllowed) {
		t.Fatalf("CreateCA, not allowed: %v", err)
	}
	if b, err := ResolveBank(old, SHA256); err != nil || b != SHA256 {
		t.Fatalf("a bank named is the bank: %v %v", b, err)
	}
	for _, allow := range []bool{true, true, false, false, true} {
		if err := AllowSHA1(old, allow); err != nil {
			t.Fatal(err)
		}
		b, err := ResolveBank(old, Auto)
		if allow && (err != nil || b != SHA1) || !allow && !errors.Is(err, ErrSHA1NotAllowed) {
			t.Fatalf("allowed %v: %v %v", allow, b, err)
		}
	}
	ca, err := CreateCA(old, authority(t).Public(), CAOptions{Type: P256, Bank: Auto, PCRs: []int{7}})
	if err != nil || ca.Bank != SHA1 {
		t.Fatalf("CreateCA, allowed: %v", err)
	}
	swtpmtest.NoneLeft(t, old, "CreateCA")

	if err := AllowSHA1(old, false); err != nil {
		t.Fatal(err)
	}
	pub := sha1Public()
	pub.DataSize = 8
	owner := tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)}
	if _, err := (tpm2.NVDefineSpace{AuthHandle: owner, PublicInfo: tpm2.New2B(pub)}).Execute(old); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveBank(old, Auto); err == nil || !strings.Contains(err.Error(), "is not assh's sha1 flag") {
		t.Fatalf("another index: %v", err)
	}
}

// A list of key types: parsed in order (duplicates once), and a key is made
// with the first the TPM takes - swtpm takes both.
func TestResolveType(t *testing.T) {
	if l, err := ParseType("rsa, p256, rsa2048"); err != nil || l != "rsa2048,p256" || !slices.Equal(l.Choices(), []Type{RSA2048, P256}) {
		t.Fatalf("%q %v", l, err)
	}
	if _, err := ParseType("rsa2048,ed25519"); err == nil {
		t.Fatal("an unknown type in a list")
	}
	tpm := swtpmtest.Start(t).Open(t)
	for _, l := range []Type{"rsa2048,p256", "p256,rsa2048", P256} {
		if got, err := ResolveType(tpm, l); err != nil || got != l.Choices()[0] {
			t.Errorf("%s: %s %v", l, got, err)
		}
	}
	ca, err := CreateCA(tpm, authority(t).Public(), CAOptions{Type: "rsa2048,p256", Bank: SHA256, PCRs: []int{7}})
	if err != nil || ca.Type != RSA2048 {
		t.Fatalf("CreateCA of a list: %v", err)
	}
	hk, err := TemporaryKey(tpm, errors.New("test"), IssueOptions{Type: "p256,rsa2048", Open: func() (transport.TPMCloser, error) { return nil, errors.New("not here") }})
	if err != nil || hk.PublicKey().Type() != "ecdsa-sha2-nistp256" {
		t.Fatalf("a host key of a list: %v", err)
	}
	swtpmtest.NoneLeft(t, tpm, "ResolveType")
}
