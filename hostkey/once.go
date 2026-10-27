package hostkey

import (
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// SlotSpec is a slot CreateOnceCA makes: the PCRs approved for it, and
// PCRs a key elsewhere signs (nil: none).
type SlotSpec struct {
	Number int
	PCRs   []int
	Signed *Signed
}

// CreateOnceCA makes a CA whose approvals are made with it and never
// again. Its authority is a key made in the TPM under the NULL hierarchy
// for this call alone: it approves values (as they will be when the CA is to
// sign) in every slot of slots, then it is flushed - and the NULL hierarchy's
// seed is new at the next boot. Nothing can approve another state later: not
// root, not anyone who knows something, since there is nothing to know. A
// slot with signed PCRs still follows what their key signs (an update).
// slots must have slot 0.
func CreateOnceCA(t transport.TPM, o CAOptions, slots []SlotSpec, values map[int][]byte) (*CA, error) {
	i := slices.IndexFunc(slots, func(s SlotSpec) bool { return s.Number == 0 })
	if i < 0 {
		return nil, errors.New("no slot 0")
	}
	o.PCRs = slots[i].PCRs
	// The authority: made, its public part kept, nothing left loaded while
	// the CA is made (a TPM holds few objects at once).
	auth := make([]byte, 32)
	if _, err := rand.Read(auth); err != nil {
		return nil, err
	}
	defer clear(auth)
	tmpl, err := keyTemplate(P256, nil)
	if err != nil {
		return nil, err
	}
	p, err := createPrimary(t, tpm2.TPMRHNull)
	if err != nil {
		return nil, err
	}
	created, err := createKey(t, p, tmpl, auth)
	flush(t, p.handle)
	if err != nil {
		return nil, fmt.Errorf("creating the authority in the TPM: %w", err)
	}
	pubArea, err := created.OutPublic.Contents()
	if err != nil {
		return nil, err
	}
	pub, err := tpm2.Pub(*pubArea)
	if err != nil {
		return nil, err
	}
	ca, err := CreateCA(t, pub, o)
	if err != nil {
		return nil, err
	}
	for _, s := range slots {
		if s.Number != 0 {
			if err := ca.AddSlot(s.Number, s.PCRs); err != nil {
				return nil, err
			}
		}
		if s.Signed != nil {
			if err := ca.SetSigned(s.Number, s.Signed); err != nil {
				return nil, err
			}
		}
	}
	// The approvals, by the authority loaded once more (the NULL hierarchy's
	// seed is the same until the boot ends), then flushed for good.
	p, err = createPrimary(t, tpm2.TPMRHNull)
	if err != nil {
		return nil, err
	}
	key, err := loadKey(t, p, tpm2.Marshal(*pubArea), created.OutPrivate.Buffer)
	flush(t, p.handle)
	if err != nil {
		return nil, fmt.Errorf("loading the authority: %w", err)
	}
	defer flush(t, key.ObjectHandle)
	for _, s := range ca.Slots {
		digest, err := ca.ApprovalDigest(s.Number, values)
		if err != nil {
			return nil, fmt.Errorf("slot %d: %w", s.Number, err)
		}
		sig, err := sign(t, key, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(auth)), pub, digest, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("the authority's approval of slot %d: %w", s.Number, err)
		}
		if err := ca.AddApproval(s.Number, values, sig); err != nil {
			return nil, err
		}
	}
	return ca, nil
}
