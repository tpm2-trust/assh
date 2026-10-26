package hostkey

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"

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
