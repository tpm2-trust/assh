package hostkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

// The policies, computed here as the TPM computes them in a SHA-256
// session:
//
//	CA key:   PolicyAuthorize(authority, policyRef)
//	approved: PolicyPCR(a slot's PCRs, H(values in index order))
//	          ; PolicyNV(counter == generation)    with a counter
//
// The authority signs ApprovalDigest = SHA-256(approved || policyRef). When
// the CA signs (caSigner.Sign), the TPM checks that signature
// (VerifySignature, a ticket), a session runs PolicyPCR and PolicyNV over
// the TPM's state as it is, and PolicyAuthorize with the ticket turns the
// approved digest into the CA's policy. No PCR value is in the CA's policy:
// a new state needs a new approval, never a new CA.

// authorityTemplate is an authority's public key elsewhere as the TPM loads
// it to check a signature. Its Name - a hash of exactly this - is part of the
// CA's policy, so it must not change.
func authorityTemplate(pub crypto.PublicKey) (tpm2.TPMTPublic, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		switch k.N.BitLen() {
		case 2048, 3072, 4096:
		default:
			return tpm2.TPMTPublic{}, fmt.Errorf("an RSA authority of %d bits (2048, 3072 or 4096)", k.N.BitLen())
		}
		exp := uint32(k.E)
		if k.E == 65537 {
			exp = 0 // the TPM's default
		}
		return tpm2.TPMTPublic{
			Type:             tpm2.TPMAlgRSA,
			NameAlg:          tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{SignEncrypt: true},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme:  tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA256}),
				},
				KeyBits:  tpm2.TPMKeyBits(k.N.BitLen()),
				Exponent: exp,
			}),
			Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: pad(k.N.Bytes(), k.N.BitLen()/8)}),
		}, nil
	case *ecdsa.PublicKey:
		var curve tpm2.TPMECCCurve
		switch k.Curve {
		case elliptic.P256():
			curve = tpm2.TPMECCNistP256
		case elliptic.P384():
			curve = tpm2.TPMECCNistP384
		default:
			return tpm2.TPMTPublic{}, errors.New("an ECDSA authority on another curve than P-256 or P-384")
		}
		n := (k.Curve.Params().BitSize + 7) / 8
		return tpm2.TPMTPublic{
			Type:             tpm2.TPMAlgECC,
			NameAlg:          tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{SignEncrypt: true},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme:  tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
				},
				CurveID: curve,
			}),
			Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: pad(k.X.Bytes(), n)},
				Y: tpm2.TPM2BECCParameter{Buffer: pad(k.Y.Bytes(), n)},
			}),
		}, nil
	}
	return tpm2.TPMTPublic{}, fmt.Errorf("an authority of type %T (RSA or ECDSA)", pub)
}

func pad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

func (f *CA) authorityKey() (crypto.PublicKey, error) {
	if f.AuthorityTPM != nil {
		pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](f.AuthorityTPM.Public)
		if err != nil {
			return nil, fmt.Errorf("the authority's public part: %w", err)
		}
		return tpm2.Pub(*pub)
	}
	pub, err := x509.ParsePKIXPublicKey(f.Authority)
	if err != nil {
		return nil, fmt.Errorf("the authority's public key: %w", err)
	}
	if _, err := authorityTemplate(pub); err != nil {
		return nil, err
	}
	return pub, nil
}

// AuthorityKey is the public key whose signatures approve PCR states.
func (f *CA) AuthorityKey() crypto.PublicKey {
	k, _ := f.authorityKey()
	return k
}

// authorityName is the Name of the authority's key as the TPM checks its
// signatures: the key in the TPM itself, or the template of one elsewhere.
func (f *CA) authorityName() (tpm2.TPM2BName, error) {
	if f.AuthorityTPM != nil {
		p, err := tpm2.Unmarshal[tpm2.TPMTPublic](f.AuthorityTPM.Public)
		if err != nil {
			return tpm2.TPM2BName{}, err
		}
		return objectName(*p)
	}
	k, err := f.authorityKey()
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	name, _, err := templateName(k)
	return name, err
}

// templateName is a public key elsewhere as the TPM loads it to check its
// signatures (authorityTemplate), and its Name.
func templateName(k crypto.PublicKey) (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	tmpl, err := authorityTemplate(k)
	if err != nil {
		return tpm2.TPM2BName{}, tmpl, err
	}
	name, err := objectName(tmpl)
	return name, tmpl, err
}

func objectName(pub tpm2.TPMTPublic) (tpm2.TPM2BName, error) {
	name, err := tpm2.ObjectName(&pub)
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	return *name, nil
}

// caPolicyFor is the CA key's policy: whatever the authority of this Name
// approves, then Sign alone, while the window index w holds v - not
// read-locked.
func caPolicyFor(authority tpm2.TPM2BName, policyRef []byte, w tpm2.TPMSNVPublic, v uint64) []byte {
	return policyDigest(append([]func(*tpm2.PolicyCalculator) error{tpm2.PolicyAuthorize{
		PolicyRef: tpm2.TPM2BDigest{Buffer: policyRef},
		KeySign:   authority,
	}.Update}, windowGate(w, v)...)...)
}

// caPolicy is this CA's policy, as its key must carry it.
func (f *CA) caPolicy() ([]byte, error) {
	name, err := f.authorityName()
	if err != nil {
		return nil, err
	}
	w, err := f.window()
	if err != nil {
		return nil, err
	}
	return caPolicyFor(name, f.PolicyRef, w, f.Window.Value), nil
}

// selection is pcrs of bank as the TPM takes them.
func selection(bank Bank, pcrs []int) tpm2.TPMLPCRSelection {
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
		Hash:      bank.alg(),
		PCRSelect: pcrBitmap(pcrs),
	}}}
}

func pcrBitmap(pcrs []int) []byte {
	b := make([]byte, 3)
	for _, p := range pcrs {
		b[p/8] |= 1 << (p % 8)
	}
	return b
}

// approvedPolicy is the digest of a session that finds values in the
// slot's PCRs and, with a counter, gen in it.
func (f *CA) approvedPolicy(s *Slot, values map[int][]byte, gen uint64) ([]byte, error) {
	if err := f.checkValues(s, values); err != nil {
		return nil, err
	}
	h := sha256.New() // the session's hash, whatever the bank
	for _, i := range s.PCRs {
		h.Write(values[i])
	}
	calc, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return nil, err
	}
	if s.Signed != nil {
		// PolicyAuthorize resets the session's digest: the signed PCRs'
		// part is the key's Name alone, whatever value it signed.
		name, _, err := s.Signed.name()
		if err != nil {
			return nil, err
		}
		if err := (tpm2.PolicyAuthorize{KeySign: name}).Update(calc); err != nil {
			return nil, err
		}
	}
	if err := (tpm2.PolicyPCR{
		PcrDigest: tpm2.TPM2BDigest{Buffer: h.Sum(nil)},
		Pcrs:      selection(f.Bank, s.PCRs),
	}).Update(calc); err != nil {
		return nil, err
	}
	if f.Counter != nil {
		g, err := f.counter()
		if err != nil {
			return nil, err
		}
		if err := (tpm2.PolicyNV{
			NVIndex:   tpm2.NamedHandle{Handle: g.NVIndex, Name: nvName(g)},
			OperandB:  tpm2.TPM2BOperand{Buffer: binary.BigEndian.AppendUint64(nil, gen)},
			Operation: tpm2.TPMEOEq,
		}).Update(calc); err != nil {
			return nil, err
		}
	}
	return calc.Hash().Digest, nil
}

// ApprovalDigest is what the authority signs to approve values in slot at
// the file's generation: SHA-256 over the approved policy and the CA's
// policy reference. A signer that is not at hand (a token elsewhere) signs
// it there; AddApproval takes the signature. Values of PCRs the slot does
// not read are no part of it.
func (f *CA) ApprovalDigest(slot int, values map[int][]byte) ([]byte, error) {
	s := f.Slot(slot)
	if s == nil {
		return nil, fmt.Errorf("no slot %d", slot)
	}
	return f.approvalDigestAt(s, values, f.FileGeneration())
}

func (f *CA) approvalDigestAt(s *Slot, values map[int][]byte, gen uint64) ([]byte, error) {
	policy, err := f.approvedPolicy(s, values, gen)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(policy)
	h.Write(f.PolicyRef)
	return h.Sum(nil), nil
}

// Approve signs values in slot at the file's generation with the
// authority's private key and adds the approval. The signer may be a
// token, or the authority in the TPM (TPMAuthority): it is asked for one
// signature over a SHA-256 digest.
func (f *CA) Approve(authority crypto.Signer, slot int, values map[int][]byte) error {
	digest, err := f.ApprovalDigest(slot, values)
	if err != nil {
		return err
	}
	sig, err := authority.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("the authority's signature: %w", err)
	}
	return f.AddApproval(slot, values, sig)
}

// AddApproval adds values with the authority's signature over their
// ApprovalDigest: PKCS #1 v1.5 for RSA, ASN.1 DER for ECDSA, as Go's
// crypto.Signer and openssl make them. A signature the authority did not
// make is refused here, not at the boot. Values already approved in the
// slot at this generation get the new signature.
func (f *CA) AddApproval(slot int, values map[int][]byte, sig []byte) error {
	digest, err := f.ApprovalDigest(slot, values)
	if err != nil {
		return err
	}
	pub, err := f.authorityKey()
	if err != nil {
		return err
	}
	tsig, err := tpmSignature(pub, digest, sig)
	if err != nil {
		return err
	}
	b := tpm2.Marshal(tsig)
	s := f.Slot(slot)
	copied := map[int][]byte{}
	for _, i := range s.PCRs {
		copied[i] = append([]byte(nil), values[i]...)
	}
	gen := f.FileGeneration()
	for i := range f.Approvals {
		if a := &f.Approvals[i]; a.Slot == slot && a.Generation == gen && sameValues(s.PCRs, a.PCRs, values) {
			a.Signature = b
			return nil
		}
	}
	f.Approvals = append(f.Approvals, Approval{Slot: slot, PCRs: copied, Generation: gen, Signature: b})
	return nil
}

// tpmSignature checks sig over digest with the authority's key and gives
// it as the TPM takes it.
func tpmSignature(pub crypto.PublicKey, digest, sig []byte) (tpm2.TPMTSignature, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig); err != nil {
			return tpm2.TPMTSignature{}, errors.New("the signature is not the authority's (RSA PKCS #1 v1.5 over SHA-256)")
		}
		return tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgRSASSA,
			Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgRSASSA, &tpm2.TPMSSignatureRSA{
				Hash: tpm2.TPMAlgSHA256,
				Sig:  tpm2.TPM2BPublicKeyRSA{Buffer: sig},
			}),
		}, nil
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return tpm2.TPMTSignature{}, errors.New("the signature is not the authority's (ECDSA, ASN.1 DER)")
		}
		var rs struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(sig, &rs); err != nil {
			return tpm2.TPMTSignature{}, err
		}
		n := (k.Curve.Params().BitSize + 7) / 8
		return tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgECDSA,
			Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
				Hash:       tpm2.TPMAlgSHA256,
				SignatureR: tpm2.TPM2BECCParameter{Buffer: pad(rs.R.Bytes(), n)},
				SignatureS: tpm2.TPM2BECCParameter{Buffer: pad(rs.S.Bytes(), n)},
			}),
		}, nil
	}
	return tpm2.TPMTSignature{}, fmt.Errorf("an authority of type %T", pub)
}
