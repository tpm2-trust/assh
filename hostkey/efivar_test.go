package hostkey

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/tpm2-trust/assh/internal/swtpmtest"
)

// A CA kept in an EFI variable: written as efivarfs takes it (the
// attributes, then the file in one piece), read back with its approvals,
// and it certifies as the file did. No variable is an error os.IsNotExist
// knows; a name efivarfs would not take is refused.
func TestCAInEFIVariable(t *testing.T) {
	dir := t.TempDir()
	old := efivarsDir
	efivarsDir = dir
	defer func() { efivarsDir = old }()

	if _, err := LoadCA("efi:AsshTestCA"); !os.IsNotExist(err) {
		t.Fatalf("no variable: %v", err)
	}
	for _, bad := range []string{"efi:", "efi:../x", "efi:a/b", "efi:a b"} {
		if _, err := LoadCA(bad); err == nil || os.IsNotExist(err) {
			t.Errorf("%q: %v", bad, err)
		}
	}

	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	auth := authority(t)
	ca, err := CreateCA(tpm, auth.Public(), CAOptions{Type: P256, Bank: SHA256, PCRs: []int{0, 2, 7, 15}, Window: 15, PolicyRef: []byte("assh test")})
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.AddSlot(1, []int{7, 15}); err != nil {
		t.Fatal(err)
	}
	now, err := ca.ReadPCRs(tpm)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []int{0, 1} {
		if err := ca.Approve(auth, s, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := ca.Save("efi:AsshTestCA"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "AsshTestCA-"+VarGUID))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte{7, 0, 0, 0, '{'}) || bytes.Contains(raw, []byte("\n")) {
		t.Fatalf("the variable: % x...", raw[:min(16, len(raw))])
	}
	t.Logf("the variable: %d bytes, two slots, two approvals", len(raw))

	got, err := LoadCA("efi:AsshTestCA")
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint() != ca.Fingerprint() || len(got.Approvals) != 2 || !got.Approvals[1].Equal(&ca.Approvals[1]) {
		t.Fatalf("read back: %s, %d approvals", got.Fingerprint(), len(got.Approvals))
	}
	certified(t, tpm, got, IssueOptions{Open: sw.Opener()}, 0)

	// Written again, smaller: the variable is the new contents alone.
	if err := got.Only(func(a Approval) bool { return a.Slot == 1 }).Save("efi:AsshTestCA"); err != nil {
		t.Fatal(err)
	}
	if got, err = LoadCA("efi:AsshTestCA"); err != nil || len(got.Approvals) != 1 {
		t.Fatalf("rewritten: %v", err)
	}
}
