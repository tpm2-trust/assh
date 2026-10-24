package hostkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// Signer signs with a host key of this boot. It opens the TPM for every
// signature and loads the key afresh under the NULL hierarchy, so it holds
// no TPM handle another user of the TPM could flush. Its authorization
// value is in this process's memory alone; after a reboot the key loads
// nowhere.
type Signer struct {
	open    func() (transport.TPMCloser, error)
	public  []byte
	private []byte
	auth    []byte
	pub     crypto.PublicKey

	mu sync.Mutex // one signature at a time
}

func newSigner(public, private, auth []byte, open func() (transport.TPMCloser, error)) (*Signer, error) {
	tp, err := tpm2.Unmarshal[tpm2.TPMTPublic](public)
	if err != nil {
		return nil, err
	}
	pub, err := tpm2.Pub(*tp)
	if err != nil {
		return nil, err
	}
	return &Signer{open: open, public: public, private: private, auth: auth, pub: pub}, nil
}

// Public is the key's public half.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// Sign signs a digest: ECDSA (ASN.1 DER, as crypto/ecdsa gives it) or RSA
// PKCS #1 v1.5, with the hash opts names - SHA-256, or SHA-384 and SHA-512
// where the TPM has them.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.open()
	if err != nil {
		return nil, fmt.Errorf("opening the TPM: %w", err)
	}
	defer t.Close()
	p, err := createPrimary(t, tpm2.TPMRHNull)
	if err != nil {
		return nil, err
	}
	defer flush(t, p.handle)
	key, err := loadKey(t, p, s.public, s.private)
	if err != nil {
		return nil, fmt.Errorf("the host key does not load (the TPM was reset since): %w", err)
	}
	defer flush(t, key.ObjectHandle)
	// An HMAC session proves the authorization value without sending it.
	return sign(t, key, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(s.auth)), s.pub, digest, opts)
}

// sign has the TPM sign digest with the loaded key, authorized by session,
// and gives the signature as Go's crypto.Signer does.
func sign(t transport.TPM, key *tpm2.LoadResponse, session tpm2.Session, pub crypto.PublicKey, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, pss := opts.(*rsa.PSSOptions); pss {
		return nil, errors.New("RSA-PSS is not offered")
	}
	h := opts.HashFunc()
	var alg tpm2.TPMAlgID
	switch h {
	case crypto.SHA256:
		alg = tpm2.TPMAlgSHA256
	case crypto.SHA384:
		alg = tpm2.TPMAlgSHA384
	case crypto.SHA512:
		alg = tpm2.TPMAlgSHA512
	default:
		return nil, fmt.Errorf("no signature over %v", h)
	}
	if len(digest) != h.Size() {
		return nil, fmt.Errorf("a digest of %d bytes for %v", len(digest), h)
	}
	var scheme tpm2.TPMTSigScheme
	switch pub.(type) {
	case *ecdsa.PublicKey:
		scheme = tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: alg})}
	case *rsa.PublicKey:
		scheme = tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSchemeHash{HashAlg: alg})}
	default:
		return nil, fmt.Errorf("a key of type %T", pub)
	}
	rsp, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{Handle: key.ObjectHandle, Name: key.Name, Auth: session},
		Digest:    tpm2.TPM2BDigest{Buffer: digest},
		InScheme:  scheme,
		Validation: tpm2.TPMTTKHashCheck{
			Tag:       tpm2.TPMSTHashCheck,
			Hierarchy: tpm2.TPMRHNull,
		},
	}.Execute(t)
	if err != nil {
		return nil, err
	}
	switch rsp.Signature.SigAlg {
	case tpm2.TPMAlgECDSA:
		e, err := rsp.Signature.Signature.ECDSA()
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(struct{ R, S *big.Int }{
			new(big.Int).SetBytes(e.SignatureR.Buffer), new(big.Int).SetBytes(e.SignatureS.Buffer)})
	case tpm2.TPMAlgRSASSA:
		r, err := rsp.Signature.Signature.RSASSA()
		if err != nil {
			return nil, err
		}
		return r.Sig.Buffer, nil
	}
	return nil, fmt.Errorf("the TPM signed with algorithm %v", rsp.Signature.SigAlg)
}

// SSHSigner is a signer as an SSH key: ecdsa-sha2-nistp256, or for RSA
// rsa-sha2-256 alone (SHA-1's ssh-rsa is not offered, and SHA-512 is
// missing from many TPMs).
func SSHSigner(s crypto.Signer) (ssh.Signer, error) {
	sg, err := ssh.NewSignerFromSigner(s)
	if err != nil {
		return nil, err
	}
	if _, ok := s.Public().(*rsa.PublicKey); ok {
		as, ok := sg.(ssh.AlgorithmSigner)
		if !ok {
			return nil, errors.New("the RSA signer chooses no algorithm")
		}
		return ssh.NewSignerWithAlgorithms(as, []string{ssh.KeyAlgoRSASHA256})
	}
	return sg, nil
}

// NoDump keeps this process's memory - the host key's authorization value
// - from core dumps and from ptrace by processes that are not root.
func NoDump() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
