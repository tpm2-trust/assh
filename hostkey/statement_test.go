package hostkey

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/tpm2-trust/assh/internal/swtpmtest"
)

// A statement's digest, computed from the statement alone, is the CA's
// ApprovalDigest: with a key elsewhere and signed PCRs, and with a counter.
func TestStatement(t *testing.T) {
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	build, _ := rsa.GenerateKey(rand.Reader, 2048)
	signed, err := NewSigned([]int{11}, &build.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := CreateCA(tpm, authority(t).Public(), CAOptions{Type: P256, Bank: SHA256, Use: "assh test",
		Slots: []SlotSpec{{Number: 0, PCRs: []int{0, 7}, Signed: signed}, {Number: 1, PCRs: []int{7}}}})
	if err != nil {
		t.Fatal(err)
	}
	values, _ := ca.ReadPCRs(tpm)
	for _, slot := range []int{0, 1} {
		st, err := ca.Statement(slot, values)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := st.Marshal()
		back, err := ParseStatement(b)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := back.Digest()
		want, _ := ca.ApprovalDigest(slot, values)
		if !bytes.Equal(got, want) {
			t.Fatalf("slot %d: the statement's digest differs", slot)
		}
		// What it says, the digest follows: another value is another digest.
		back.PCRs["7"] = back.PCRs["7"][:62] + "ff"
		if other, _ := back.Digest(); bytes.Equal(other, want) {
			t.Fatalf("slot %d: a changed statement has the same digest", slot)
		}
	}

	_, ptpm, pca := pinCA(t)
	pvalues, _ := pca.ReadPCRs(ptpm)
	st, err := pca.Statement(0, pvalues)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := st.Digest()
	want, _ := pca.ApprovalDigest(0, pvalues)
	if !bytes.Equal(got, want) || st.Generation != 1 {
		t.Fatalf("with a counter: the statement's digest differs, generation %d", st.Generation)
	}
}

// An approval opens the CA it was made for alone: a second CA with the same
// authority, use and PCRs has another nonce, so another digest; it does not
// take the first one's signature, and with the approval copied into its
// file, the TPM refuses it.
func TestApprovalBoundToItsCA(t *testing.T) {
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	auth := authority(t)
	opts := CAOptions{Type: P256, Bank: SHA256, PCRs: []int{0, 7}, Use: "assh test"}
	one, err := CreateCA(tpm, auth.Public(), opts)
	if err != nil {
		t.Fatal(err)
	}
	two, err := CreateCA(tpm, auth.Public(), opts)
	if err != nil {
		t.Fatal(err)
	}
	sw.Reboot(t)
	values, err := one.ReadPCRs(tpm)
	if err != nil {
		t.Fatal(err)
	}
	d1, _ := one.ApprovalDigest(0, values)
	d2, _ := two.ApprovalDigest(0, values)
	if bytes.Equal(d1, d2) || bytes.Equal(one.Nonce, two.Nonce) || len(one.Nonce) != NonceSize {
		t.Fatal("two CAs of one authority, use and PCRs share an approval digest")
	}
	sig, err := auth.Sign(rand.Reader, d1, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := two.AddApproval(0, values, sig); err == nil {
		t.Fatal("a CA took an approval signed for another")
	}
	if err := one.AddApproval(0, values, sig); err != nil {
		t.Fatal(err)
	}
	issue := IssueOptions{Type: P256, KeyID: "test", Principals: []string{"host.example"}, Open: sw.Opener()}
	certified(t, tpm, one, issue, 0)
	two.Approvals = append(two.Approvals[:0], one.Approvals...)
	hk, err := Issue(tpm, two, issue)
	swtpmtest.NoneLeft(t, tpm, "Issue")
	if err != nil {
		t.Fatal(err)
	}
	checkTemporary(t, two, hk)
	if hk.Temporary == nil || !strings.Contains(hk.Temporary.Error(), "does not accept the approval's signature") {
		t.Fatalf("the other CA with the copied approval: %v", hk.Temporary)
	}
	// A statement names what binds it: without the nonce there is no digest.
	st, _ := one.Statement(0, values)
	if got, _ := st.Digest(); !bytes.Equal(got, d1) {
		t.Fatal("the statement's digest is not the CA's")
	}
	st.Nonce = ""
	if _, err := st.Digest(); err == nil {
		t.Fatal("a statement without a nonce has a digest")
	}
}
