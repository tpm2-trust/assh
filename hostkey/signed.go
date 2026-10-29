package hostkey

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Signed are PCRs a slot takes from a key elsewhere instead of from an
// approval: the slot signs while their values are ones that key signed, as
// systemd's build signs PCR 11 of a unified kernel image for each boot
// phase (systemd-measure sign; the UKI's .pcrsig, on the running system
// /run/systemd/tpm2-pcr-signature.json). An update keeps the slot met: its
// new image carries its own signature. The key's Name is in every approval of
// the slot, so the authority approves that key along with the slot's PCRs.
//
// The policy of such a slot, computed as the TPM does it:
//
//	PolicyPCR(the signed PCRs) ; PolicyAuthorize(the key, no reference)
//	; PolicyPCR(the slot's PCRs) ; PolicyNV(counter)   (the approval)
type Signed struct {
	PCRs []int  `json:"pcrs"`
	Key  []byte `json:"key"` // PKIX DER: RSA of 2048 bits, which every TPM checks
}

// NewSigned is the PCRs signed by the RSA key in PEM or DER.
func NewSigned(pcrs []int, key crypto.PublicKey) (*Signed, error) {
	if _, err := rsa2048(key); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	pcrs = slices.Clone(pcrs)
	slices.Sort(pcrs)
	if err := checkSelection(pcrs); err != nil {
		return nil, err
	}
	return &Signed{PCRs: pcrs, Key: der}, nil
}

func rsa2048(k crypto.PublicKey) (*rsa.PublicKey, error) {
	rk, ok := k.(*rsa.PublicKey)
	if !ok || rk.N.BitLen() != 2048 {
		return nil, errors.New("the key of signed PCRs must be RSA with 2048 bits: what every TPM checks")
	}
	return rk, nil
}

func (s *Signed) key() (*rsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(s.Key)
	if err != nil {
		return nil, fmt.Errorf("the key of the signed PCRs: %w", err)
	}
	return rsa2048(k)
}

// name is the key's Name as the TPM loads it to check its signatures.
func (s *Signed) name() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	k, err := s.key()
	if err != nil {
		return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, err
	}
	return templateName(k)
}

// PCRPolicy is the digest of PolicyPCR over values of pcrs in bank, from a
// fresh SHA-256 session: what systemd-measure signs ("pol").
func PCRPolicy(bank Bank, pcrs []int, values map[int][]byte) ([]byte, error) {
	h := sha256.New()
	for _, i := range pcrs {
		v, ok := values[i]
		if !ok {
			return nil, fmt.Errorf("no value of PCR %d", i)
		}
		h.Write(v)
	}
	return policyDigest(tpm2.PolicyPCR{
		PcrDigest: tpm2.TPM2BDigest{Buffer: h.Sum(nil)},
		Pcrs:      selection(bank, pcrs),
	}.Update), nil
}

// PCRSignatures are signatures of PCR policies as systemd writes them
// (systemd-measure sign --json, a UKI's .pcrsig):
//
//	{"sha256": [{"pcrs": [11], "pkfp": "...", "pol": "<hex>", "sig": "<base64>"}, ...], "sha1": [...]}
//
// "sig" is RSA PKCS #1 v1.5 over SHA-256 of "pol" (no policy reference).
type PCRSignatures map[string][]struct {
	PCRs []int  `json:"pcrs"`
	Pol  string `json:"pol"`
	Sig  string `json:"sig"`
}

// ParsePCRSignatures reads systemd's JSON (trailing NULs allowed, as a
// section has them).
func ParsePCRSignatures(b []byte) (PCRSignatures, error) {
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	var p PCRSignatures
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("not systemd's PCR signatures: %w", err)
	}
	return p, nil
}

// find is the signature by s's key over pol in bank, checked here; nil for
// none.
func (p PCRSignatures) find(s *Signed, bank Bank, pol []byte) []byte {
	k, err := s.key()
	if err != nil {
		return nil
	}
	digest := sha256.Sum256(pol)
	for _, e := range p[string(bank)] {
		if !slices.Equal(e.PCRs, s.PCRs) {
			continue
		}
		if got, err := hex.DecodeString(e.Pol); err != nil || string(got) != string(pol) {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(e.Sig)
		if err != nil {
			continue
		}
		if rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) == nil {
			return sig
		}
	}
	return nil
}

// signedTicket has the TPM check the signature of s's key over the policy
// of now's values of the signed PCRs, and gives what PolicyAuthorize takes.
func (f *CA) signedTicket(t transport.TPM, s *Signed, now map[int][]byte, sigs PCRSignatures) (pol []byte, name tpm2.TPM2BName, ticket tpm2.TPMTTKVerified, err error) {
	pol, err = PCRPolicy(f.Bank, s.PCRs, now)
	if err != nil {
		return nil, name, ticket, err
	}
	sig := sigs.find(s, f.Bank, pol)
	if sig == nil {
		return nil, name, ticket, fmt.Errorf("PCR %s: no signature of its key for this value", PCRList(s.PCRs))
	}
	name, tmpl, err := s.name()
	if err != nil {
		return nil, name, ticket, err
	}
	k, _ := s.key()
	digest := sha256.Sum256(pol)
	tsig, err := tpmSignature(k, digest[:], sig)
	if err != nil {
		return nil, name, ticket, err
	}
	ext, err := tpm2.LoadExternal{InPublic: tpm2.New2B(tmpl), Hierarchy: tpm2.TPMRHOwner}.Execute(t)
	if err != nil {
		return nil, name, ticket, fmt.Errorf("loading the key of the signed PCRs: %w", err)
	}
	defer flush(t, ext.ObjectHandle)
	rsp, err := tpm2.VerifySignature{
		KeyHandle: ext.ObjectHandle,
		Digest:    tpm2.TPM2BDigest{Buffer: digest[:]},
		Signature: tsig,
	}.Execute(t)
	if err != nil {
		return nil, name, ticket, fmt.Errorf("the TPM does not accept the signature of PCR %s: %w", PCRList(s.PCRs), err)
	}
	return pol, ext.Name, rsp.Validation, nil
}
