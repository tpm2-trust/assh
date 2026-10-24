package hostkey

import (
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/tpm2-trust/assh/internal/swtpmtest"
)

// A host key signs whatever zero bytes its authorization value holds: the
// TPM drops only trailing ones, and go-tpm's HMAC sessions must agree
// (fixed after go-tpm v0.9.8, google/go-tpm#446).
func TestHostKeysSign(t *testing.T) {
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	tmpl, _ := keyTemplate(P256, nil)
	for _, tc := range []struct {
		name  string
		zeros []int
	}{
		{"no zero", nil},
		{"zero inside", []int{5}},
		{"zero first", []int{0}},
		{"trailing zeros", []int{30, 31}},
		{"zeros everywhere", []int{0, 7, 8, 20, 31}},
	} {
		auth := make([]byte, 32)
		for i := range auth {
			auth[i] = byte(i + 1)
		}
		for _, z := range tc.zeros {
			auth[z] = 0
		}
		p, err := createPrimary(tpm, tpm2.TPMRHNull)
		if err != nil {
			t.Fatal(err)
		}
		key, err := createKey(tpm, p, tmpl, auth)
		flush(tpm, p.handle)
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := key.OutPublic.Contents()
		s, _ := newSigner(tpm2.Marshal(pub), key.OutPrivate.Buffer, auth, sw.Opener())
		if _, err := s.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}
