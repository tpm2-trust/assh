package hostkey

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/tpm2-trust/assh/persist"
)

// RemoveCA removes the CA's file and its indices; without a file the
// indices defined as aSSH's at the handles given, and nothing else. A new
// CA can be created at the same handles afterwards.
func TestRemoveCA(t *testing.T) {
	_, tpm, ca := pinCA(t)
	path := filepath.Join(t.TempDir(), "ca.json")
	if err := ca.Save(path); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path+".pub", []byte("x"), 0o644)
	all := []tpm2.TPMHandle{DefaultPINHandle, DefaultCounterHandle, DefaultWindowHandle}
	removed, err := RemoveCA(tpm, path, Handles{})
	if err != nil || len(removed) != 5 {
		t.Fatalf("removed %v: %v", removed, err)
	}
	for _, p := range []string{path, path + ".pub"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still there", p)
		}
	}
	for _, h := range all {
		if _, _, err := persist.ReadNVPublic(tpm, h); err == nil {
			t.Errorf("0x%08X still there", uint32(h))
		}
	}
	if removed, err := RemoveCA(tpm, path, Handles{}); err != nil || len(removed) != 0 {
		t.Fatalf("again: %v %v", removed, err)
	}

	// Indices without their file (the file deleted first): removed by
	// their definition, the counter's policy from the PIN index the TPM
	// holds.
	if _, err = CreatePINCA(tpm, PINCAOptions{CAOptions: CAOptions{Type: P256, Bank: SHA256, PCRs: []int{7, 15}}, PIN: pinOf(testPIN)}); err != nil {
		t.Fatal(err)
	}
	if removed, err := RemoveCA(tpm, path, Handles{}); err != nil || len(removed) != 3 {
		t.Fatalf("by definition: %v %v", removed, err)
	}
}

// What a CA file names is no proof: a file edited to name another owner
// index as its PIN index, counter or window leaves that index; and without
// a file, an index of the counter's generic attributes stays.
func TestRemoveCAForeign(t *testing.T) {
	_, tpm, ca := pinCA(t)
	owner := tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)}
	define := func(pub tpm2.TPMSNVPublic) {
		t.Helper()
		if _, err := (tpm2.NVDefineSpace{AuthHandle: owner, PublicInfo: tpm2.New2B(pub)}).Execute(tpm); err != nil {
			t.Fatal(err)
		}
	}
	// Another program's index, and a counter with G's attributes but
	// another policy.
	victim := sha1Public()
	victim.NVIndex = 0x01802920
	define(victim)
	lookalike := tpm2.TPMSNVPublic{NVIndex: 0x01802921, NameAlg: tpm2.TPMAlgSHA256, DataSize: 8,
		Attributes: tpm2.TPMANV{NT: tpm2.TPMNTCounter, PolicyWrite: true, AuthRead: true, NoDA: true}}
	define(lookalike)

	forged := *ca
	auth := *ca.AuthorityTPM
	auth.PIN = tpm2.Marshal(victim)
	forged.AuthorityTPM = &auth
	forged.Counter = &Counter{Public: tpm2.Marshal(lookalike)}
	path := filepath.Join(t.TempDir(), "ca.json")
	b, err := forged.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	// ParseCA refuses such a file; RemoveCA must hold without that.
	if _, err := LoadCA(path); err == nil {
		removed, err := RemoveCA(tpm, path, Handles{})
		if !errors.Is(err, ErrLeft) {
			t.Fatalf("forged file: %v %v", removed, err)
		}
	} else {
		removed, left := removeIndices(tpm, Handles{PIN: victim.NVIndex, Counter: lookalike.NVIndex})
		if len(removed) != 0 || len(left) != 2 {
			t.Fatalf("handles of a forged file: removed %v, left %v", removed, left)
		}
	}
	for _, h := range []tpm2.TPMHandle{victim.NVIndex, lookalike.NVIndex} {
		if _, _, err := persist.ReadNVPublic(tpm, h); err != nil {
			t.Errorf("0x%08X was removed", uint32(h))
		}
	}

	// Without a file: the lookalike at the counter's handle stays.
	removed, err := RemoveCA(tpm, filepath.Join(t.TempDir(), "none"), Handles{PIN: DefaultPINHandle, Counter: lookalike.NVIndex})
	if !errors.Is(err, ErrLeft) || !strings.Contains(err.Error(), "0x01802921") {
		t.Fatalf("a lookalike counter: %v %v", removed, err)
	}
	if _, _, err := persist.ReadNVPublic(tpm, lookalike.NVIndex); err != nil {
		t.Error("the lookalike counter was removed")
	}
}
