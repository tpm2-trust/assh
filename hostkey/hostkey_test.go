package hostkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/mrwiora/assh/internal/swtpmtest"
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
// certified. After a reboot that host key is gone.
func TestCertifiedHostKey(t *testing.T) {
	for _, typ := range []Type{P256, RSA2048} {
		t.Run(string(typ), func(t *testing.T) {
			sw := swtpmtest.Start(t)
			tpm := sw.Open(t)
			auth := authority(t)
			ca, err := CreateCA(tpm, typ, SHA256, []int{15, 7, 0}, auth.Public(), []byte("assh test"))
			if err != nil {
				t.Fatal(err)
			}
			if len(ca.PCRs) != 3 || ca.PCRs[0] != 0 || ca.PCRs[2] != 15 {
				t.Fatalf("pcrs %v", ca.PCRs)
			}
			opts := IssueOptions{Type: typ, KeyID: "test boot", Principals: []string{"host.example"}, Open: sw.Opener()}
			if _, err := Issue(tpm, ca, opts); !isMismatch(err, true) {
				t.Fatalf("issue without an approval: %v", err)
			}
			now, err := ca.ReadPCRs(tpm)
			if err != nil {
				t.Fatal(err)
			}
			if err := ca.Approve(auth, now); err != nil {
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
			hk, err := Issue(tpm, ca, opts)
			if err != nil {
				t.Fatal(err)
			}
			if hk.Cert.KeyId != "test boot" || hk.Cert.CertType != ssh.HostCert {
				t.Fatalf("cert %+v", hk.Cert)
			}
			checkTrusted(t, ca, hk)

			if err := Close(tpm, 15, "assh: closed"); err != nil {
				t.Fatal(err)
			}
			var m *MismatchError
			if _, err := Issue(tpm, ca, opts); !errors.As(err, &m) || len(m.Changed) != 1 || m.Changed[0] != 15 {
				t.Fatalf("issue after closing: %v", err)
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

func isMismatch(err error, none bool) bool {
	var m *MismatchError
	return errors.As(err, &m) && m.None == none
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
	var sig *ssh.Signature
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
	line, err := ca.KnownHosts("host.example")
	if err != nil || !strings.HasPrefix(line, "@cert-authority host.example ") {
		t.Fatalf("%q %v", line, err)
	}
}

// An approval is checked when it is added: a signature of another key, or
// over other values, is refused. A signature made elsewhere is taken.
func TestApprovalChecked(t *testing.T) {
	auth := authority(t)
	tpm := swtpmtest.Start(t).Open(t)
	ca, err := CreateCA(tpm, P256, SHA256, []int{0, 7}, auth.Public(), []byte("assh test"))
	if err != nil {
		t.Fatal(err)
	}
	values := map[int][]byte{0: make([]byte, 32), 7: make([]byte, 32)}
	digest, err := ca.ApprovalDigest(values)
	if err != nil {
		t.Fatal(err)
	}
	other := authority(t)
	sig, _ := other.Sign(rand.Reader, digest, crypto.SHA256)
	if err := ca.AddApproval(values, sig); err == nil {
		t.Fatal("took another key's signature")
	}
	sig, _ = auth.Sign(rand.Reader, digest, crypto.SHA256)
	values2 := map[int][]byte{0: make([]byte, 32), 7: append(make([]byte, 31), 1)}
	if err := ca.AddApproval(values2, sig); err == nil {
		t.Fatal("took a signature over other values")
	}
	if err := ca.AddApproval(values, sig); err != nil {
		t.Fatal(err)
	}
	if ca.Approved(values) == nil || ca.Approved(values2) != nil || len(ca.Approvals) != 1 {
		t.Fatalf("approvals %+v", ca.Approvals)
	}
	if err := ca.AddApproval(map[int][]byte{0: make([]byte, 32)}, sig); err == nil {
		t.Fatal("took values for too few PCRs")
	}
	rsaAuth, _ := rsa.GenerateKey(rand.Reader, 2048)
	ca2, err := CreateCA(tpm, RSA2048, SHA256, []int{0, 7}, rsaAuth.Public(), []byte("assh test"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ca2.Approve(rsaAuth, values); err != nil {
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
