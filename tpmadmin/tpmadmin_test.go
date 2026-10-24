package tpmadmin

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/tpm2-trust/assh/hostkey"
	"github.com/tpm2-trust/assh/internal/swtpmtest"
)

func pinOf(b []byte) hostkey.PIN {
	return func() ([]byte, error) { return append([]byte(nil), b...), nil }
}

func approve(t *testing.T, sw *swtpmtest.SWTPM, ca *hostkey.CA, pin []byte) error {
	t.Helper()
	tpm := sw.Open(t)
	now, err := ca.ReadPCRs(tpm)
	if err != nil {
		t.Fatal(err)
	}
	a, err := ca.TPMAuthority(tpm, pinOf(pin))
	if err != nil {
		t.Fatal(err)
	}
	return ca.Approve(a, 0, now)
}

// certified is why the CA did not certify a host key, nil when it did.
func certified(tpm transport.TPM, sw *swtpmtest.SWTPM, ca *hostkey.CA) error {
	hk, err := hostkey.Issue(tpm, ca, hostkey.IssueOptions{Open: sw.Opener()})
	if err != nil {
		return err
	}
	return hk.Temporary
}

// A PIN change: the old PIN opens nothing, the new one approves, the CA and
// its approvals stay; neither PIN crosses the bus.
func TestChangePIN(t *testing.T) {
	sw := swtpmtest.Start(t)
	sw.SetLockout(t, 3, 1800, 1800)
	tpm := sw.Open(t)
	oldPIN, newPIN := []byte("old-pin-1"), []byte("new-pin-2")
	ca, err := hostkey.CreatePINCA(tpm, hostkey.PINCAOptions{CAOptions: hostkey.CAOptions{Type: hostkey.P256, Bank: hostkey.SHA256, PCRs: []int{7}}, PIN: pinOf(oldPIN)})
	if err != nil {
		t.Fatal(err)
	}
	if err := approve(t, sw, ca, oldPIN); err != nil {
		t.Fatal(err)
	}
	before, _ := ca.Marshal()

	if err := ChangePIN(tpm, ca, pinOf([]byte("wrong-pin")), pinOf(newPIN)); !errors.Is(err, hostkey.ErrWrongPIN) {
		t.Fatalf("change with a wrong PIN: %v", err)
	}
	if err := ChangePIN(tpm, ca, pinOf(oldPIN), pinOf([]byte("short"))); err == nil {
		t.Fatal("changed to a PIN of 5 bytes")
	}
	swtpmtest.NoneLeft(t, tpm, "refused ChangePIN")
	rec := &swtpmtest.Recorder{TPM: tpm}
	if err := ChangePIN(rec, ca, pinOf(oldPIN), pinOf(newPIN)); err != nil {
		t.Fatal(err)
	}
	swtpmtest.NoneLeft(t, tpm, "ChangePIN")
	if bytes.Contains(rec.Bytes, oldPIN) || bytes.Contains(rec.Bytes, newPIN) {
		t.Fatal("a PIN crossed the bus")
	}
	sw.ResetLockout(t)

	if err := approve(t, sw, ca, oldPIN); !errors.Is(err, hostkey.ErrWrongPIN) {
		t.Fatalf("approve with the old PIN: %v", err)
	}
	if err := ca.NextGeneration(tpm, pinOf(oldPIN)); !errors.Is(err, hostkey.ErrWrongPIN) {
		t.Fatalf("next generation with the old PIN: %v", err)
	}
	if after, _ := ca.Marshal(); !bytes.Equal(before, after) {
		t.Fatal("the PIN change changed the CA file")
	}
	if err := certified(tpm, sw, ca); err != nil {
		t.Fatalf("issue with the approval from before the change: %v", err)
	}
	if err := ca.NextGeneration(tpm, pinOf(newPIN)); err != nil {
		t.Fatal(err)
	}
	if err := approve(t, sw, ca, newPIN); err != nil {
		t.Fatal(err)
	}
	if err := certified(tpm, sw, ca); err != nil {
		t.Fatal(err)
	}
}

// The dictionary attack parameters are set, read back and reset with the
// lockout authorization, which can be changed; a wrong one is refused.
func TestDA(t *testing.T) {
	sw := swtpmtest.Start(t)
	sw.SetLockout(t, 10, 10, 10)
	tpm := sw.Open(t)
	if err := SetDA(tpm, swtpmtest.LockoutAuth, 3, 1800, 1800); err != nil {
		t.Fatal(err)
	}
	s, err := ReadDA(tpm)
	if err != nil {
		t.Fatal(err)
	}
	if s.MaxTries != 3 || s.Recovery != 1800 || s.LockoutRecovery != 1800 || !s.LockoutAuthSet || s.InLockout || s.Failures != 0 {
		t.Fatalf("%+v", s)
	}

	ca, err := hostkey.CreatePINCA(tpm, hostkey.PINCAOptions{CAOptions: hostkey.CAOptions{Type: hostkey.P256, Bank: hostkey.SHA256, PCRs: []int{7}}, PIN: pinOf([]byte("the-pin"))})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		approve(t, sw, ca, []byte("wrong-pin"))
	}
	if s, _ := ReadDA(tpm); !s.InLockout || s.Failures != 3 {
		t.Fatalf("after 3 wrong PINs: %+v", s)
	}
	if err := ResetDA(tpm, swtpmtest.LockoutAuth); err != nil {
		t.Fatal(err)
	}
	if s, _ := ReadDA(tpm); s.InLockout || s.Failures != 0 {
		t.Fatalf("after the reset: %+v", s)
	}

	newAuth := []byte("another lockout auth")
	if err := SetLockoutAuth(tpm, swtpmtest.LockoutAuth, nil); err == nil {
		t.Fatal("set an empty lockout authorization")
	}
	rec := &swtpmtest.Recorder{TPM: tpm}
	if err := SetLockoutAuth(rec, swtpmtest.LockoutAuth, newAuth); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rec.Bytes, newAuth) || bytes.Contains(rec.Bytes, swtpmtest.LockoutAuth) {
		t.Fatal("a lockout authorization crossed the bus")
	}
	if err := ResetDA(tpm, newAuth); err != nil {
		t.Fatal(err)
	}
	if err := ResetDA(tpm, swtpmtest.LockoutAuth); err == nil {
		t.Fatal("reset with the old lockout authorization")
	}
	swtpmtest.NoneLeft(t, tpm, "tpmadmin")
}
