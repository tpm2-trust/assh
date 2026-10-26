package hostkey

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/tpm2-trust/assh/internal/swtpmtest"
)

// EventChain is what the TPM holds after TPM2_PCR_Event from a reset, in
// either bank.
func TestEventChain(t *testing.T) {
	events := []string{"safespace-combination:b", "safespace-identity:sealed"}
	for _, banks := range [][]string{{"sha1", "sha256"}, {"sha1"}} {
		sw := swtpmtest.StartBanks(t, banks...)
		tpm := sw.Open(t)
		for _, e := range events {
			if _, err := (tpm2.PCREvent{PCRHandle: tpm2.AuthHandle{Handle: 15, Auth: tpm2.PasswordAuth(nil)},
				EventData: tpm2.TPM2BEvent{Buffer: []byte(e)}}).Execute(tpm); err != nil {
				t.Fatal(err)
			}
		}
		for _, b := range banks {
			now, err := ReadPCRs(tpm, Bank(b), []int{15})
			if err != nil {
				t.Fatal(err)
			}
			want, err := EventChain(Bank(b), events)
			if err != nil || !bytes.Equal(now[15], want) {
				t.Errorf("%s: the TPM %x, EventChain %x %v", b, now[15], want, err)
			}
		}
	}
	if _, err := EventChain(Auto, events); err == nil {
		t.Error("EventChain of auto")
	}
}

// RemoveCA removes the CA's file and the indices it names; without a file
// the indices of aSSH's shape at the handles given, and nothing else. A
// new CA can be created at the same handles afterwards.
func TestRemoveCA(t *testing.T) {
	_, tpm, ca := pinCA(t)
	path := filepath.Join(t.TempDir(), "ca.json")
	if err := ca.Save(path); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path+".pub", []byte("x"), 0o644)
	handles := []tpm2.TPMHandle{DefaultPINHandle, DefaultCounterHandle}
	removed, err := RemoveCA(tpm, path, handles)
	if err != nil || len(removed) != 4 {
		t.Fatalf("removed %v: %v", removed, err)
	}
	for _, p := range []string{path, path + ".pub"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still there", p)
		}
	}
	for _, h := range handles {
		if _, _, err := readNVPublic(tpm, h); err == nil {
			t.Errorf("0x%08X still there", uint32(h))
		}
	}
	if removed, err := RemoveCA(tpm, path, handles); err != nil || len(removed) != 0 {
		t.Fatalf("again: %v %v", removed, err)
	}

	// Indices without their file (the file deleted first): removed by shape.
	ca, err = CreatePINCA(tpm, PINCAOptions{CAOptions: CAOptions{Type: P256, Bank: SHA256, PCRs: []int{7, 15}}, PIN: pinOf(testPIN)})
	if err != nil {
		t.Fatal(err)
	}
	if removed, err := RemoveCA(tpm, path, handles); err != nil || len(removed) != 2 {
		t.Fatalf("by shape: %v %v", removed, err)
	}

	// Another index at the handle stays, with or without a file.
	other := sha1Public()
	other.NVIndex = DefaultPINHandle
	owner := tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)}
	if _, err := (tpm2.NVDefineSpace{AuthHandle: owner, PublicInfo: tpm2.New2B(other)}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	if removed, err := RemoveCA(tpm, path, handles); err != nil || len(removed) != 0 {
		t.Fatalf("another index: %v %v", removed, err)
	}
	if err := ca.Save(path); err != nil {
		t.Fatal(err)
	}
	removed, err = RemoveCA(tpm, path, handles)
	if err != nil || slices.Contains(removed, "NV index 0x01802913") || !slices.Contains(removed, path) {
		t.Fatalf("a file whose PIN index was replaced: %v %v", removed, err)
	}
	if _, _, err := readNVPublic(tpm, DefaultPINHandle); err != nil {
		t.Fatal("the other index was removed")
	}
}
