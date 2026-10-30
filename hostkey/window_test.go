package hostkey

import (
	"crypto"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/tpm2-trust/assh/internal/swtpmtest"
	"github.com/tpm2-trust/assh/persist"
)

// The window is the CA's own, closed in the boot that makes the CA: once
// closed, the CA signs nothing in an approved state - also for a slot that does not read PCR 15, approved
// from an edited file - until the next boot. A window index defined again
// alike does not reopen it.
func TestWindow(t *testing.T) {
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	auth := authority(t)
	// Slot 0 reads PCR 7 alone: nothing of the approval knows a window.
	ca, err := CreateCA(tpm, auth.Public(), CAOptions{Type: P256, Bank: SHA256, PCRs: []int{7}})
	if err != nil {
		t.Fatal(err)
	}
	now, _ := ca.ReadPCRs(tpm)
	if err := ca.Approve(auth, 0, now); err != nil {
		t.Fatal(err)
	}
	opts := IssueOptions{Principals: []string{"host.example"}, Open: sw.Opener()}
	// Approved in the boot of its creation, it signs nothing in that boot.
	if open, err := ca.WindowOpen(tpm); err != nil || open {
		t.Fatalf("a new CA's window: open %v, %v", open, err)
	}
	if hk, err := Issue(tpm, ca, opts); err != nil || !errors.Is(hk.Temporary, ErrWindowClosed) {
		t.Fatalf("in the boot of its creation: %v %v", hk, err)
	}
	sw.Reboot(t)
	certified(t, tpm, ca, opts, 0)
	if err := ca.Close(tpm); err != nil {
		t.Fatal(err)
	}
	if open, err := ca.WindowOpen(tpm); err != nil || open {
		t.Fatalf("open after Close: %v %v", open, err)
	}
	if hk, err := Issue(tpm, ca, opts); err != nil || !errors.Is(hk.Temporary, ErrWindowClosed) {
		t.Fatalf("after Close: %v %v", hk, err)
	}
	// Past the software's check: the TPM refuses.
	caPub, _ := ca.PublicKey()
	if _, err := (&caSigner{t: tpm, ca: ca, approval: &ca.Approvals[0], pub: caPub}).Sign(rand.Reader, make([]byte, 32), crypto.SHA256); !errors.Is(err, ErrWindowClosed) {
		t.Fatalf("the TPM after Close: %v", err)
	}
	swtpmtest.NoneLeft(t, tpm, "refused signature")
	if err := ca.Close(tpm); err != nil {
		t.Fatalf("closed twice: %v", err)
	}

	// The next boot opens it again.
	sw.Reboot(t)
	certified(t, tpm, ca, opts, 0)

	// W undefined and defined again alike, then given its one increment:
	// its value is above v, the CA signs nothing.
	w, _ := ca.window()
	if ok, err := persist.RemoveNV(tpm, w.NVIndex, persist.Any); err != nil || !ok {
		t.Fatal(err)
	}
	clone, err := defineWindow(tpm, w.NVIndex)
	if err != nil {
		t.Fatal(err)
	}
	if clone.Value == ca.Window.Value {
		t.Fatalf("the clone holds v = %d", clone.Value)
	}
	if hk, err := Issue(tpm, ca, opts); err != nil || hk.Temporary == nil {
		t.Fatalf("with a cloned window index: %v %v", hk, err)
	}
	swtpmtest.NoneLeft(t, tpm, "cloned window")
}

// In an approved state the CA signs and does nothing else: Certify with
// its session fails. Its ADMIN role takes no empty password.
func TestCASignsAlone(t *testing.T) {
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	auth := authority(t)
	ca, err := CreateCA(tpm, auth.Public(), CAOptions{Type: P256, Bank: SHA256, PCRs: []int{7}})
	if err != nil {
		t.Fatal(err)
	}
	sw.Reboot(t) // a CA signs from the boot after its creation
	now, _ := ca.ReadPCRs(tpm)
	if err := ca.Approve(auth, 0, now); err != nil {
		t.Fatal(err)
	}
	caPub, _ := ca.PublicKey()
	s := &caSigner{t: tpm, ca: ca, approval: &ca.Approvals[0], pub: caPub}
	key, session, done, err := s.open()
	if err != nil {
		t.Fatal(err)
	}
	null := tpm2.AuthHandle{Handle: tpm2.TPMRHNull, Auth: tpm2.PasswordAuth(nil)}
	named := tpm2.AuthHandle{Handle: key.ObjectHandle, Name: key.Name, Auth: session}
	if _, err := (tpm2.Certify{ObjectHandle: named, SignHandle: null}).Execute(tpm); !errors.Is(err, tpm2.TPMRCPolicyCC) {
		t.Fatalf("Certify with the CA's signing session: %v, want TPM_RC_POLICY_CC", err)
	}
	done()
	key, _, done, err = s.open()
	if err != nil {
		t.Fatal(err)
	}
	admin := tpm2.AuthHandle{Handle: key.ObjectHandle, Name: key.Name, Auth: tpm2.PasswordAuth(nil)}
	if _, err := (tpm2.Certify{ObjectHandle: admin, SignHandle: null}).Execute(tpm); !errors.Is(err, tpm2.TPMRCAuthType) {
		t.Fatalf("the CA's ADMIN role with an empty password: %v, want TPM_RC_AUTH_TYPE (a policy session only)", err)
	}
	done()
	swtpmtest.NoneLeft(t, tpm, "Certify")
}

// CloseWindow locks a window index and nothing else: a foreign index at
// the handle stays as it is; none there is no error.
func TestCloseWindow(t *testing.T) {
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	if ok, err := CloseWindow(tpm, DefaultWindowHandle); ok || err != nil {
		t.Fatalf("none there: %v %v", ok, err)
	}
	other := sha1Public()
	other.NVIndex = DefaultWindowHandle
	other.Attributes.ReadSTClear = true
	owner := tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)}
	if _, err := (tpm2.NVDefineSpace{AuthHandle: owner, PublicInfo: tpm2.New2B(other)}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	if _, err := CloseWindow(tpm, DefaultWindowHandle); err == nil {
		t.Fatal("a foreign index was taken for a window")
	}
	pub, _, _ := persist.ReadNVPublic(tpm, DefaultWindowHandle)
	if pub.Attributes.ReadLocked {
		t.Fatal("the foreign index was read-locked")
	}
}
