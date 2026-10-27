package hostkey

import (
	"errors"
	"fmt"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// SHA1Handle is the NV index whose presence allows SHA-1 on a TPM: a CA of
// bank Auto reads SHA-1 where the TPM has no active SHA-256 bank, and only
// while it is there. The owner defines it (AllowSHA1); it holds nothing
// secret and is not signed: where SHA-256 is active it changes nothing,
// and which banks are active only the firmware decides. Others read it
// too (safearch's initrd, for its machine-id), so it stays at this handle.
const SHA1Handle tpm2.TPMHandle = 0x01802914

// ErrSHA1NotAllowed is a TPM whose only active bank is SHA-1, without
// SHA1Handle.
var ErrSHA1NotAllowed = fmt.Errorf("the TPM's only active PCR bank is sha1, and sha1 is not allowed on it (NV index 0x%08X: 'assh tpm sha1 --allow')", uint32(SHA1Handle))

// sha1Public is SHA1Handle as AllowSHA1 leaves it: one byte, written by
// the owner, read by the owner, noDA.
func sha1Public() tpm2.TPMSNVPublic {
	return tpm2.TPMSNVPublic{
		NVIndex: SHA1Handle,
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			NT:         tpm2.TPMNTOrdinary,
			OwnerWrite: true,
			OwnerRead:  true,
			NoDA:       true,
		},
		DataSize: 1,
	}
}

// ActiveBanks are the PCR banks the TPM extends (of SHA-256 and SHA-1):
// those with at least one PCR allocated.
func ActiveBanks(t transport.TPM) ([]Bank, error) {
	rsp, err := tpm2.GetCapability{Capability: tpm2.TPMCapPCRs, PropertyCount: 1}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("reading the PCR banks: %w", err)
	}
	sel, err := rsp.CapabilityData.Data.AssignedPCR()
	if err != nil {
		return nil, err
	}
	var banks []Bank
	for _, s := range sel.PCRSelections {
		if !slices.ContainsFunc(s.PCRSelect, func(b byte) bool { return b != 0 }) {
			continue
		}
		switch s.Hash {
		case tpm2.TPMAlgSHA256:
			banks = append(banks, SHA256)
		case tpm2.TPMAlgSHA1:
			banks = append(banks, SHA1)
		}
	}
	return banks, nil
}

// SHA1Allowed is whether SHA1Handle is there, as AllowSHA1 made it.
func SHA1Allowed(t transport.TPM) (bool, error) {
	pub, _, err := readNVPublic(t, SHA1Handle)
	if errors.Is(err, tpm2.TPMRCHandle) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading NV index 0x%08X: %w", uint32(SHA1Handle), err)
	}
	want := written(sha1Public())
	if pub.NameAlg != want.NameAlg || pub.Attributes != want.Attributes || pub.DataSize != want.DataSize || len(pub.AuthPolicy.Buffer) != 0 {
		return false, fmt.Errorf("NV index 0x%08X is not assh's sha1 flag: remove it, or allow sha1 again", uint32(SHA1Handle))
	}
	return true, nil
}

// AllowSHA1 defines SHA1Handle (allow) or removes it, with the owner's
// empty authorization.
func AllowSHA1(t transport.TPM, allow bool) error {
	_, _, err := readNVPublic(t, SHA1Handle)
	exists := err == nil
	if err != nil && !errors.Is(err, tpm2.TPMRCHandle) {
		return fmt.Errorf("reading NV index 0x%08X: %w", uint32(SHA1Handle), err)
	}
	if exists {
		if err := undefine(t, SHA1Handle); err != nil {
			return fmt.Errorf("removing NV index 0x%08X: %w", uint32(SHA1Handle), err)
		}
	}
	if !allow {
		return nil
	}
	owner := tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)}
	pub := sha1Public()
	if _, err := (tpm2.NVDefineSpace{AuthHandle: owner, PublicInfo: tpm2.New2B(pub)}).Execute(t); err != nil {
		return fmt.Errorf("defining NV index 0x%08X: %w", uint32(SHA1Handle), err)
	}
	if _, err := (tpm2.NVWrite{AuthHandle: owner, NVIndex: tpm2.NamedHandle{Handle: SHA1Handle, Name: nvName(pub)},
		Data: tpm2.TPM2BMaxNVBuffer{Buffer: []byte{1}}}).Execute(t); err != nil {
		return fmt.Errorf("writing NV index 0x%08X: %w", uint32(SHA1Handle), err)
	}
	return nil
}

// ResolveBank is b, or for Auto the bank the TPM gives: SHA-256 where it
// is active, else SHA-1 where that is active and allowed (SHA1Handle).
func ResolveBank(t transport.TPM, b Bank) (Bank, error) {
	if b != Auto {
		return b, nil
	}
	active, err := ActiveBanks(t)
	if err != nil {
		return "", err
	}
	switch {
	case slices.Contains(active, SHA256):
		return SHA256, nil
	case !slices.Contains(active, SHA1):
		return "", errors.New("the TPM has neither an active sha256 nor an active sha1 PCR bank")
	}
	ok, err := SHA1Allowed(t)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrSHA1NotAllowed
	}
	return SHA1, nil
}

// EventChain is the value a PCR of bank b holds after a reset (zero) and
// TPM2_PCR_Event with each event in turn: the value to approve for a state
// that is known before it is booted. Auto is not a bank here.
func EventChain(b Bank, events []string) ([]byte, error) {
	if b != SHA256 && b != SHA1 {
		return nil, fmt.Errorf("unknown PCR bank %q", b)
	}
	h, err := b.alg().Hash()
	if err != nil {
		return nil, err
	}
	pcr := make([]byte, b.size())
	for _, e := range events {
		d := h.New()
		d.Write([]byte(e))
		x := h.New()
		x.Write(pcr)
		x.Write(d.Sum(nil))
		pcr = x.Sum(nil)
	}
	return pcr, nil
}
