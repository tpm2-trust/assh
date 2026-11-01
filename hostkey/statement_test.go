package hostkey

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
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
	ca, err := CreateCA(tpm, authority(t).Public(), CAOptions{Type: P256, Bank: SHA256, PolicyRef: []byte("assh test"),
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
