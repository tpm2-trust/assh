package persist

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/tpm2-trust/assh/internal/swtpmtest"
)

// An index is removed only when it is the caller's, by its shape or its
// name; one that is not is left and named; none there is not an error.
func TestRemoveNV(t *testing.T) {
	tpm := swtpmtest.Start(t).Open(t)
	owner := tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)}
	pub := tpm2.TPMSNVPublic{NVIndex: 0x01802990, NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{NT: tpm2.TPMNTOrdinary, OwnerWrite: true, OwnerRead: true, NoDA: true}, DataSize: 4}
	define := func() {
		t.Helper()
		if _, err := (tpm2.NVDefineSpace{AuthHandle: owner, PublicInfo: tpm2.New2B(pub)}).Execute(tpm); err != nil {
			t.Fatal(err)
		}
	}

	if ok, err := RemoveNV(tpm, pub.NVIndex, Shaped(pub)); ok || err != nil {
		t.Fatalf("nothing there: %v %v", ok, err)
	}

	define()
	other := pub
	other.DataSize = 8
	if ok, err := RemoveNV(tpm, pub.NVIndex, Shaped(other)); ok || !errors.Is(err, ErrNotOurs) {
		t.Fatalf("another shape: %v %v", ok, err)
	}
	// Written: the TPM's own attribute is not part of the shape.
	if _, err := (tpm2.NVWrite{AuthHandle: owner, NVIndex: tpm2.NamedHandle{Handle: pub.NVIndex, Name: name(t, pub)},
		Data: tpm2.TPM2BMaxNVBuffer{Buffer: []byte{1, 2, 3, 4}}}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	if ok, err := RemoveNV(tpm, pub.NVIndex, Shaped(pub)); !ok || err != nil {
		t.Fatalf("its shape, written: %v %v", ok, err)
	}

	define()
	if ok, err := RemoveNV(tpm, pub.NVIndex, Named(tpm2.TPM2BName{Buffer: []byte("another")})); ok || !errors.Is(err, ErrNotOurs) {
		t.Fatalf("another name: %v %v", ok, err)
	}
	if ok, err := RemoveNV(tpm, pub.NVIndex, Named(name(t, pub))); !ok || err != nil {
		t.Fatalf("its name: %v %v", ok, err)
	}
}

func name(t *testing.T, pub tpm2.TPMSNVPublic) tpm2.TPM2BName {
	t.Helper()
	n, err := tpm2.NVName(&pub)
	if err != nil {
		t.Fatal(err)
	}
	return *n
}

// A variable of aSSH's GUID or another's: written with its attributes in
// one piece, replaced in place, read without them, removed; none there is
// not an error. A name efivarfs would not take is refused.
func TestVars(t *testing.T) {
	old := VarDir
	VarDir = t.TempDir()
	defer func() { VarDir = old }()

	for _, c := range []struct{ location, file string }{
		{"efi:AsshTest", "AsshTest-" + VarGUID},
		{"efi:SafespaceSelect-8a3e6c1d-4b2f-4e9a-b7d5-1c0f9e2a6b34", "SafespaceSelect-8a3e6c1d-4b2f-4e9a-b7d5-1c0f9e2a6b34"},
	} {
		if _, err := ReadVar(c.location); !os.IsNotExist(err) {
			t.Fatalf("%s before: %v", c.location, err)
		}
		for _, v := range []string{"first", "2nd"} {
			if err := WriteVar(c.location, []byte(v)); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(VarDir, c.file))
			if err != nil || string(raw) != "\x07\x00\x00\x00"+v {
				t.Fatalf("%s: %q %v", c.file, raw, err)
			}
			if got, err := ReadVar(c.location); err != nil || string(got) != v {
				t.Fatalf("%s read: %q %v", c.location, got, err)
			}
		}
		if ok, err := RemoveVar(c.location); !ok || err != nil {
			t.Fatalf("%s removed: %v %v", c.location, ok, err)
		}
		if ok, err := RemoveVar(c.location); ok || err != nil {
			t.Fatalf("%s removed twice: %v %v", c.location, ok, err)
		}
	}
	for _, bad := range []string{"efi:", "efi:../x", "efi:a/b", "efi:a b"} {
		if _, err := VarPath(bad); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
}
