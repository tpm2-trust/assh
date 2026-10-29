// Package persist is how what is kept across reboots outside a file - NV
// indices in the TPM, EFI variables - is written and removed, by aSSH and
// by the programs built on it (tpm2-kira, safearch's scripts through the
// assh command), one way for all:
//
//   - Only what is provably one's own is removed: an NV index whose public
//     area is the one its owner defines (Shaped, Named), never just
//     whatever sits at a handle.
//   - Absent is not an error: a removal reports whether something went.
//   - An EFI variable is written in place, in one write, never removed
//     first: efivarfs replaces it whole, so a crash leaves the old value or
//     the new one, never none.
package persist

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Owned says whether the index at a handle, with this public area and
// name, is the caller's.
type Owned func(pub *tpm2.TPMSNVPublic, name tpm2.TPM2BName) bool

// ErrNotOurs: something is at the handle, and it is not the caller's.
var ErrNotOurs = errors.New("the NV index there is not ours")

// Named is ours when the index's name is name: the very index the caller
// defined, with its policy.
func Named(name tpm2.TPM2BName) Owned {
	return func(_ *tpm2.TPMSNVPublic, n tpm2.TPM2BName) bool { return bytes.Equal(n.Buffer, name.Buffer) }
}

// Shaped is ours when the index has want's name algorithm and attributes,
// and want's size unless that is 0 (any). The attributes the TPM changes
// while the index lives - written, the locks - are not compared; nor is the
// policy, which can name a key the caller no longer holds.
func Shaped(want tpm2.TPMSNVPublic) Owned {
	return func(pub *tpm2.TPMSNVPublic, _ tpm2.TPM2BName) bool {
		return pub.NameAlg == want.NameAlg && stable(pub.Attributes) == stable(want.Attributes) &&
			(want.DataSize == 0 || pub.DataSize == want.DataSize)
	}
}

// stable is a without the attributes the TPM sets on its own.
func stable(a tpm2.TPMANV) tpm2.TPMANV {
	a.Written, a.WriteLocked, a.ReadLocked = false, false, false
	return a
}

// ReadNVPublic is the index at h's public area and name.
func ReadNVPublic(t transport.TPM, h tpm2.TPMHandle) (*tpm2.TPMSNVPublic, tpm2.TPM2BName, error) {
	rsp, err := tpm2.NVReadPublic{NVIndex: h}.Execute(t)
	if err != nil {
		return nil, tpm2.TPM2BName{}, err
	}
	pub, err := rsp.NVPublic.Contents()
	if err != nil {
		return nil, tpm2.TPM2BName{}, err
	}
	return pub, rsp.NVName, nil
}

// RemoveNV removes the index at h, with the owner's empty authorization,
// when it is there and ours says it is the caller's. It reports whether it
// removed one; an index that is not the caller's is left, with ErrNotOurs.
func RemoveNV(t transport.TPM, h tpm2.TPMHandle, ours Owned) (bool, error) {
	pub, name, err := ReadNVPublic(t, h)
	if errors.Is(err, tpm2.TPMRCHandle) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading NV index 0x%08X: %w", uint32(h), err)
	}
	if !ours(pub, name) {
		return false, fmt.Errorf("NV index 0x%08X: %w", uint32(h), ErrNotOurs)
	}
	if _, err := (tpm2.NVUndefineSpace{AuthHandle: tpm2.TPMRHOwner, NVIndex: tpm2.NamedHandle{Handle: h, Name: name}}).Execute(t); err != nil {
		return false, fmt.Errorf("removing NV index 0x%08X: %w", uint32(h), err)
	}
	return true, nil
}
