package hostkey

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/tpm2-trust/assh/internal/swtpmtest"
)

// signPCRs is what systemd-measure sign writes for values of pcrs in bank:
// the PolicyPCR digest and key's signature over it.
func signPCRs(t *testing.T, key *rsa.PrivateKey, bank Bank, pcrs []int, values map[int][]byte) PCRSignatures {
	t.Helper()
	pol, err := PCRPolicy(bank, pcrs, values)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(pol)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	p := PCRSignatures{}
	p[string(bank)] = append(p[string(bank)], struct {
		PCRs []int  `json:"pcrs"`
		Pol  string `json:"pol"`
		Sig  string `json:"sig"`
	}{pcrs, hex.EncodeToString(pol), base64.StdEncoding.EncodeToString(sig)})
	return p
}

func event(t *testing.T, tpm transport.TPM, pcr int, e string) {
	t.Helper()
	swtpmtest.Extend(t, tpm, pcr, e)
}

// A CA made once: its authority, made in the TPM for the creation, approves
// slot 0 (PCR 0, 7, 15 approved, PCR 11 signed by the build's key) and slot 1
// (PCR 7, 15), and is gone. A boot of the build signed: slot 0; an update
// (another PCR 11, signed): slot 0 with no new approval; PCR 11 unsigned or
// signed by another key: slot 1; PCR 0 changed: slot 1; the combination
// changed: nothing - and nothing can approve anything any more.
func TestCreateOnceCA(t *testing.T) {
	for _, bank := range []Bank{SHA256, SHA1} {
		t.Run(string(bank), func(t *testing.T) {
			sw := swtpmtest.StartBanks(t, string(bank))
			build, _ := rsa.GenerateKey(rand.Reader, 2048)
			other, _ := rsa.GenerateKey(rand.Reader, 2048)
			signed, err := NewSigned([]int{11}, &build.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			boot := func(uki, combination string) transport.TPMCloser {
				t.Helper()
				sw.Reboot(t)
				tpm := sw.Open(t)
				event(t, tpm, 11, uki)
				event(t, tpm, 15, "combination:"+combination)
				return tpm
			}
			tpm := boot("uki A", "a")
			values, err := ReadPCRs(tpm, bank, []int{0, 7, 15})
			if err != nil {
				t.Fatal(err)
			}
			ca, err := CreateOnceCA(tpm, CAOptions{Type: P256, Bank: bank,
				Slots: []SlotSpec{{Number: 0, PCRs: []int{0, 7, 15}, Signed: signed}, {Number: 1, PCRs: []int{7, 15}}}}, values)
			swtpmtest.NoneLeft(t, tpm, "CreateOnceCA")
			if err != nil {
				t.Fatal(err)
			}
			if ca.AuthorityTPM != nil || ca.Counter != nil || len(ca.Approvals) != 2 {
				t.Fatalf("the CA: %+v", ca)
			}
			b, _ := ca.Marshal()
			if ca, err = ParseCA(b); err != nil {
				t.Fatal(err)
			}
			sigsOf := func(tpm transport.TPM, key *rsa.PrivateKey) PCRSignatures {
				now, err := ReadPCRs(tpm, bank, []int{11})
				if err != nil {
					t.Fatal(err)
				}
				return signPCRs(t, key, bank, []int{11}, now)
			}
			opts := func(tpm transport.TPM, key *rsa.PrivateKey) IssueOptions {
				o := IssueOptions{Type: P256, Principals: []string{"host.example"}, KeyID: "test", Open: sw.Opener()}
				if key != nil {
					o.PCRSignatures = sigsOf(tpm, key)
				}
				return o
			}

			// Not in the boot it was made in: its window is closed.
			if hk, err := Issue(tpm, ca, opts(tpm, build)); err != nil || !errors.Is(hk.Temporary, ErrWindowClosed) {
				t.Fatalf("in the boot of its creation: %v %v", hk, err)
			}
			// The next boot of that build, signed: slot 0.
			tpm = boot("uki A", "a")
			checkTrusted(t, ca, certified(t, tpm, ca, opts(tpm, build), 0))
			// An update: another UKI, its own signature - slot 0, no approval.
			tpm = boot("uki B", "a")
			hk := certified(t, tpm, ca, opts(tpm, build), 0)
			if !strings.Contains(hk.Cert.KeyId, "slot=0 pcrs=0,7,15") {
				t.Fatalf("key ID %q", hk.Cert.KeyId)
			}
			// No signature, or another key's: slot 1, and why slot 0 is not.
			tpm = boot("uki B", "a")
			certified(t, tpm, ca, opts(tpm, nil), 1)
			tpm = boot("uki B", "a")
			certified(t, tpm, ca, opts(tpm, other), 1)
			tpm = boot("uki B", "a")
			event(t, tpm, 15, "assh: closed")
			if m := temporary(t, tpm, ca, opts(tpm, nil)); !strings.Contains(m.Error(), "slot 0: PCR 15 not as approved") {
				t.Fatalf("closed: %v", m)
			}
			// The firmware changed (PCR 0): slot 1 only.
			tpm = boot("uki B", "a")
			event(t, tpm, 0, "firmware update")
			certified(t, tpm, ca, opts(tpm, build), 1)
			// Another combination: nothing.
			tpm = boot("uki B", "b")
			if m := temporary(t, tpm, ca, opts(tpm, build)); !strings.Contains(m.Error(), "slot 1: PCR 15 not as approved") {
				t.Fatalf("another combination: %v", m)
			}
			// A CA with the signed slot alone: without the build's
			// signature nothing, and the reason says so.
			tpm = boot("uki B", "a")
			values, _ = ReadPCRs(tpm, bank, []int{0, 7, 15})
			only, err := CreateOnceCA(tpm, CAOptions{Type: P256, Bank: bank, WindowHandle: 0x01802916,
				Slots: []SlotSpec{{Number: 0, PCRs: []int{0, 7, 15}, Signed: signed}}}, values)
			if err != nil {
				t.Fatal(err)
			}
			tpm = boot("uki B", "a")
			if m := temporary(t, tpm, only, opts(tpm, other)); m.Error() != "slot 0: PCR 11: no signature of the slot's key for this value" {
				t.Fatalf("an unsigned value: %v", m)
			}
		})
	}
}

// NewSigned takes RSA keys of 2048 bits only; a slot's signed PCRs are not
// its approved ones.
func TestSigned(t *testing.T) {
	k3072, _ := rsa.GenerateKey(rand.Reader, 3072)
	if _, err := NewSigned([]int{11}, &k3072.PublicKey); err == nil {
		t.Fatal("RSA-3072")
	}
	if _, err := NewSigned([]int{11}, authority(t).Public()); err == nil {
		t.Fatal("ECDSA")
	}
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	s, err := NewSigned([]int{11}, &k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ca := &CA{Bank: SHA256, Slots: []Slot{{Number: 0, PCRs: []int{7, 11}}}}
	if err := ca.SetSigned(0, s); err == nil {
		t.Fatal("a PCR approved and signed")
	}
}
