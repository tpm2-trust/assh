package hostkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"

	"github.com/tpm2-trust/assh/internal/swtpmtest"
)

func authority(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The CA is created in the TPM and certifies a host key of this boot in
// an approved state; a client that trusts the CA accepts the key. Closing
// the window (a PCR extended) stops the CA, not the host key it
// certified: the next key is temporary. After a reboot that host key is
// gone.
func TestCertifiedHostKey(t *testing.T) {
	for _, typ := range []Type{P256, RSA2048} {
		t.Run(string(typ), func(t *testing.T) {
			sw := swtpmtest.Start(t)
			tpm := sw.Open(t)
			auth := authority(t)
			ca, err := CreateCA(tpm, auth.Public(), CAOptions{Type: typ, Bank: SHA256, PCRs: []int{15, 7, 0}, Window: 15, PolicyRef: []byte("assh test")})
			if err != nil {
				t.Fatal(err)
			}
			if len(ca.Slots) != 1 || !slices.Equal(ca.Slots[0].PCRs, []int{0, 7, 15}) || !slices.Equal(ca.PCRs(), []int{0, 7, 15}) {
				t.Fatalf("slots %v", ca.Slots)
			}
			opts := IssueOptions{Type: typ, KeyID: "test boot", Principals: []string{"host.example"}, Open: sw.Opener()}
			if m := temporary(t, tpm, ca, opts); len(m.Slots) != 1 || !m.Slots[0].None {
				t.Fatalf("issue without an approval: %v", m)
			}
			now, err := ca.ReadPCRs(tpm)
			if err != nil {
				t.Fatal(err)
			}
			if err := ca.Approve(auth, 0, now); err != nil {
				t.Fatal(err)
			}
			// What a file round trip keeps.
			b, err := ca.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if ca, err = ParseCA(b); err != nil {
				t.Fatal(err)
			}
			hk := certified(t, tpm, ca, opts, 0)
			if hk.Cert.KeyId != "test boot" || hk.Cert.CertType != ssh.HostCert {
				t.Fatalf("cert %+v", hk.Cert)
			}
			checkTrusted(t, ca, hk)

			if err := Close(tpm, 15, "assh: closed"); err != nil {
				t.Fatal(err)
			}
			if m := temporary(t, tpm, ca, opts); !slices.Equal(m.Slots[0].Changed, []int{15}) {
				t.Fatalf("issue after closing: %v", m)
			}
			checkTrusted(t, ca, hk)

			// A reboot: the NULL hierarchy's seed changes.
			sw.Reboot(t)
			if _, err := hk.Signer.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); err == nil {
				t.Fatal("the host key signed after a reboot")
			}
		})
	}
}

// certified issues a host key that slot certifies.
func certified(t *testing.T, tpm transport.TPMCloser, ca *CA, o IssueOptions, slot int) *HostKey {
	t.Helper()
	hk, err := Issue(tpm, ca, o)
	swtpmtest.NoneLeft(t, tpm, "Issue")
	if err != nil {
		t.Fatal(err)
	}
	if hk.Temporary != nil || hk.Cert == nil || hk.Slot != slot {
		t.Fatalf("not certified through slot %d: slot %d, %v", slot, hk.Slot, hk.Temporary)
	}
	return hk
}

// temporary issues a host key the CA does not certify, for no slot
// approved: it signs, and a client that trusts only the CA refuses it.
func temporary(t *testing.T, tpm transport.TPMCloser, ca *CA, o IssueOptions) *MismatchError {
	t.Helper()
	hk, err := Issue(tpm, ca, o)
	swtpmtest.NoneLeft(t, tpm, "Issue")
	if err != nil {
		t.Fatal(err)
	}
	checkTemporary(t, ca, hk)
	var m *MismatchError
	if !errors.As(hk.Temporary, &m) {
		t.Fatalf("temporary, but not for a mismatch: %v", hk.Temporary)
	}
	return m
}

// checkTemporary checks a temporary key: no certificate, no slot, it
// signs, and a client that trusts the CA does not take it.
func checkTemporary(t *testing.T, ca *CA, hk *HostKey) {
	t.Helper()
	if hk.Temporary == nil || hk.Cert != nil || hk.Slot != -1 {
		t.Fatalf("not a temporary key: %+v", hk)
	}
	if _, isCert := hk.SSH().PublicKey().(*ssh.Certificate); isCert || hk.Fingerprint() != ssh.FingerprintSHA256(hk.SSH().PublicKey()) {
		t.Fatal("a temporary key with a certificate")
	}
	checkSigns(t, hk)
	if ca == nil {
		return
	}
	caKey, err := ca.SSHPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	checker := &ssh.CertChecker{IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
		return string(auth.Marshal()) == string(caKey.Marshal())
	}}
	addr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 22}
	if err := checker.CheckHostKey("host.example:22", addr, hk.SSH().PublicKey()); err == nil {
		t.Fatal("a client that trusts the CA takes a temporary key")
	}
}

// Slots: Issue scans them from 0 up and takes the first approved for the
// PCRs as they are. A narrow slot certifies while its PCR holds; the broad
// one after that PCR moved (the OS); neither after a PCR both read moved
// (the firmware) - then the key is temporary. The window closes every
// slot.
func TestSlots(t *testing.T) {
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	auth := authority(t)
	ca, err := CreateCA(tpm, auth.Public(), CAOptions{Type: P256, Bank: SHA256, PCRs: []int{7, 14, 15}, Window: 15})
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.AddSlot(1, []int{15, 7}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct {
		n    int
		pcrs []int
	}{{1, []int{8, 15}}, {2, []int{7}}, {2, []int{7, 15}}, {16, []int{8, 15}}, {-1, []int{8, 15}}, {2, nil}, {2, []int{15, 24}}} {
		if err := ca.AddSlot(bad.n, bad.pcrs); err == nil {
			t.Errorf("slot %d with %v added", bad.n, bad.pcrs)
		}
	}
	if _, err := CreateCA(tpm, auth.Public(), CAOptions{Type: P256, Bank: SHA256, PCRs: []int{7}, Window: 15}); err == nil {
		t.Error("a CA whose slot 0 does not read the window")
	}
	for _, w := range []int{16, 23, 24} {
		if _, err := CreateCA(tpm, auth.Public(), CAOptions{Type: P256, Bank: SHA256, PCRs: []int{7, w}, Window: w}); err == nil {
			t.Errorf("PCR %d as the window", w)
		}
	}
	now, err := ca.ReadPCRs(tpm)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ca.PCRs(), []int{7, 14, 15}) || len(now) != 3 {
		t.Fatalf("read %v for %v", now, ca.PCRs())
	}
	for _, slot := range []int{1, 0} {
		if err := ca.Approve(auth, slot, now); err != nil {
			t.Fatal(err)
		}
	}
	if a := ca.Approved(now); a == nil || a.Slot != 0 || len(a.PCRs) != 3 {
		t.Fatalf("approved %+v", a)
	}
	if a := ca.Approvals[0]; a.Slot != 1 || len(a.PCRs) != 2 {
		t.Fatalf("slot 1's approval holds %v", a.PCRs)
	}
	b, _ := ca.Marshal()
	if ca, err = ParseCA(b); err != nil {
		t.Fatal(err)
	}
	opts := IssueOptions{Principals: []string{"host.example"}, Open: sw.Opener()}
	checkTrusted(t, ca, certified(t, tpm, ca, opts, 0))

	// The OS moved: slot 1 certifies.
	if err := Close(tpm, 14, "another OS"); err != nil {
		t.Fatal(err)
	}
	checkTrusted(t, ca, certified(t, tpm, ca, opts, 1))
	// The window closes it too.
	if err := Close(tpm, 15, "assh: closed"); err != nil {
		t.Fatal(err)
	}
	if m := temporary(t, tpm, ca, opts); len(m.Slots) != 2 || !slices.Equal(m.Slots[0].Changed, []int{14, 15}) || !slices.Equal(m.Slots[1].Changed, []int{15}) {
		t.Fatalf("after closing: %v", m)
	}

	// The firmware moved: no slot certifies.
	sw.Reboot(t)
	checkTrusted(t, ca, certified(t, tpm, ca, opts, 0))
	if err := Close(tpm, 7, "another firmware"); err != nil {
		t.Fatal(err)
	}
	m := temporary(t, tpm, ca, opts)
	if m.Error() != "slot 0: PCR 7 not as approved; slot 1: PCR 7 not as approved" {
		t.Fatal(m)
	}

	if err := ca.RemoveSlot(0); err != nil {
		t.Fatal(err)
	}
	if len(ca.Slots) != 1 || len(ca.Approvals) != 1 || ca.Approvals[0].Slot != 1 {
		t.Fatalf("after removing slot 0: %v %v", ca.Slots, ca.Approvals)
	}
	if err := ca.RemoveSlot(1); err == nil {
		t.Fatal("removed the last slot")
	}
	if err := ca.RemoveSlot(5); err == nil {
		t.Fatal("removed a slot the CA does not have")
	}

	// Room for 16, no more; each its own selection, each with the window.
	others := []int{0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 17, 18}
	for i, n := range []int{0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} {
		if err := ca.AddSlot(n, []int{others[i], 15}); err != nil {
			t.Fatal(err)
		}
	}
	if len(ca.Slots) != MaxSlots || ca.Slots[0].Number != 0 || ca.Slots[15].Number != 15 {
		t.Fatalf("%d slots", len(ca.Slots))
	}
	if err := ca.AddSlot(16, []int{19, 15}); err == nil {
		t.Fatal("a 17th slot")
	}
	b, _ = ca.Marshal()
	if _, err := ParseCA(b); err != nil {
		t.Fatal(err)
	}
}

// A CA file the TPM cannot use - from another TPM, or one cleared - gives
// a temporary key, and so does a server without a CA (TemporaryKey).
func TestTemporaryKey(t *testing.T) {
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	auth := authority(t)
	ca, err := CreateCA(tpm, auth.Public(), CAOptions{Type: P256, Bank: SHA256, PCRs: []int{7}})
	if err != nil {
		t.Fatal(err)
	}
	now, _ := ca.ReadPCRs(tpm)
	if err := ca.Approve(auth, 0, now); err != nil {
		t.Fatal(err)
	}
	other := swtpmtest.Start(t)
	otpm := other.Open(t)
	hk, err := Issue(otpm, ca, IssueOptions{Open: other.Opener()})
	if err != nil {
		t.Fatal(err)
	}
	checkTemporary(t, ca, hk)
	if !strings.Contains(hk.Temporary.Error(), "does not load in this TPM") {
		t.Fatalf("why: %v", hk.Temporary)
	}
	swtpmtest.NoneLeft(t, otpm, "Issue on another TPM")

	hk, err = TemporaryKey(tpm, errors.New("no CA here"), IssueOptions{Type: RSA2048, Open: sw.Opener()})
	if err != nil {
		t.Fatal(err)
	}
	checkTemporary(t, nil, hk)
	if hk.Temporary.Error() != "no CA here" {
		t.Fatal(hk.Temporary)
	}
	swtpmtest.NoneLeft(t, tpm, "TemporaryKey")
}

// checkTrusted signs as an SSH server does and checks the result as a
// client that trusts the CA does.
func checkTrusted(t *testing.T, ca *CA, hk *HostKey) {
	t.Helper()
	caKey, err := ca.SSHPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	checker := &ssh.CertChecker{IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
		return string(auth.Marshal()) == string(caKey.Marshal())
	}}
	addr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 22}
	if err := checker.CheckHostKey("host.example:22", addr, hk.SSH().PublicKey()); err != nil {
		t.Fatalf("a client that trusts the CA refuses: %v", err)
	}
	checkSigns(t, hk)
	line, err := ca.KnownHosts("host.example")
	if err != nil || !strings.HasPrefix(line, "@cert-authority host.example ") {
		t.Fatalf("%q %v", line, err)
	}
}

// checkSigns signs as an SSH server does, and checks the signature.
func checkSigns(t *testing.T, hk *HostKey) {
	t.Helper()
	var sig *ssh.Signature
	var err error
	if _, isRSA := hk.Signer.Public().(*rsa.PublicKey); isRSA {
		ms := hk.SSH().(ssh.MultiAlgorithmSigner)
		sig, err = ms.SignWithAlgorithm(rand.Reader, []byte("exchange hash"), ms.Algorithms()[0])
	} else {
		sig, err = hk.SSH().Sign(rand.Reader, []byte("exchange hash"))
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := hk.SSH().PublicKey().Verify([]byte("exchange hash"), sig); err != nil {
		t.Fatal(err)
	}
}

// An approval is checked when it is added: a signature of another key, or
// over other values, is refused. A signature made elsewhere is taken.
func TestApprovalChecked(t *testing.T) {
	auth := authority(t)
	tpm := swtpmtest.Start(t).Open(t)
	ca, err := CreateCA(tpm, auth.Public(), CAOptions{Type: P256, Bank: SHA256, PCRs: []int{0, 7}, PolicyRef: []byte("assh test")})
	if err != nil {
		t.Fatal(err)
	}
	values := map[int][]byte{0: make([]byte, 32), 7: make([]byte, 32)}
	if _, err := ca.ApprovalDigest(1, values); err == nil {
		t.Fatal("a digest for a slot the CA does not have")
	}
	digest, err := ca.ApprovalDigest(0, values)
	if err != nil {
		t.Fatal(err)
	}
	other := authority(t)
	sig, _ := other.Sign(rand.Reader, digest, crypto.SHA256)
	if err := ca.AddApproval(0, values, sig); err == nil {
		t.Fatal("took another key's signature")
	}
	sig, _ = auth.Sign(rand.Reader, digest, crypto.SHA256)
	values2 := map[int][]byte{0: make([]byte, 32), 7: append(make([]byte, 31), 1)}
	if err := ca.AddApproval(0, values2, sig); err == nil {
		t.Fatal("took a signature over other values")
	}
	if err := ca.AddApproval(0, values, sig); err != nil {
		t.Fatal(err)
	}
	if ca.Approved(values) == nil || ca.Approved(values2) != nil || len(ca.Approvals) != 1 {
		t.Fatalf("approvals %+v", ca.Approvals)
	}
	if err := ca.AddApproval(0, map[int][]byte{0: make([]byte, 32)}, sig); err == nil {
		t.Fatal("took values for too few PCRs")
	}
	rsaAuth, _ := rsa.GenerateKey(rand.Reader, 2048)
	ca2, err := CreateCA(tpm, rsaAuth.Public(), CAOptions{Type: RSA2048, Bank: SHA256, PCRs: []int{0, 7}, PolicyRef: []byte("assh test")})
	if err != nil {
		t.Fatal(err)
	}
	if err := ca2.Approve(rsaAuth, 0, values); err != nil {
		t.Fatal(err)
	}
	if err := Close(tpm, 16, "x"); err == nil {
		t.Fatal("closed with a resettable PCR")
	}
}

func TestParsePCRs(t *testing.T) {
	p, err := ParsePCRs("15, 0,7,7")
	if err != nil || len(p) != 3 || p[0] != 0 || p[2] != 15 {
		t.Fatalf("%v %v", p, err)
	}
	for _, bad := range []string{"", "24", "a", "-1", "07"} {
		if _, err := ParsePCRs(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	if s := PCRList([]int{0, 7, 15}); s != "PCR 0, 7 and 15" {
		t.Fatal(s)
	}
}
