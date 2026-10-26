package hostkey

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

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

// RemoveCA removes the CA at path and its PIN index and counter: those the
// file names, each only where the TPM holds that very index (the same
// name); with no file at path, those at handles that have the shape of
// aSSH's PIN index or counter. Other indices are left. It gives what it
// removed, and keeps going past what is not there.
func RemoveCA(t transport.TPM, path string, handles []tpm2.TPMHandle) ([]string, error) {
	var removed []string
	ca, err := LoadCA(path)
	switch {
	case err == nil:
		var pubs []tpm2.TPMSNVPublic
		if ca.AuthorityTPM != nil {
			p, _, err := ca.pinIndex()
			if err != nil {
				return nil, err
			}
			pubs = append(pubs, p)
		}
		if ca.Counter != nil {
			g, err := ca.counter()
			if err != nil {
				return nil, err
			}
			pubs = append(pubs, g)
		}
		for _, pub := range pubs {
			ok, err := removeIndex(t, pub.NVIndex, func(_ *tpm2.TPMSNVPublic, name tpm2.TPM2BName) bool {
				return bytes.Equal(name.Buffer, nvName(pub).Buffer)
			})
			if err != nil {
				return removed, err
			}
			if ok {
				removed = append(removed, fmt.Sprintf("NV index 0x%08X", uint32(pub.NVIndex)))
			}
		}
	case os.IsNotExist(err):
		pin, counter := written(pinIndexPublic(0)).Attributes, tpm2.TPMANV{NT: tpm2.TPMNTCounter, PolicyWrite: true, AuthRead: true, NoDA: true, Written: true}
		for _, h := range handles {
			ok, err := removeIndex(t, h, func(pub *tpm2.TPMSNVPublic, _ tpm2.TPM2BName) bool {
				return pub.DataSize == 8 && (pub.Attributes == pin || pub.Attributes == counter)
			})
			if err != nil {
				return removed, err
			}
			if ok {
				removed = append(removed, fmt.Sprintf("NV index 0x%08X", uint32(h)))
			}
		}
		return removed, nil
	default:
		return nil, err
	}
	if IsVar(path) {
		p, err := varPath(path)
		if err != nil {
			return removed, err
		}
		if _, err := setImmutable(p, false); err != nil {
			return removed, err
		}
		if err := os.Remove(p); err != nil {
			return removed, err
		}
		return append(removed, path), nil
	}
	for _, p := range []string{path, path + ".pub"} {
		if err := os.Remove(p); err == nil {
			removed = append(removed, p)
		} else if !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
	}
	return removed, nil
}

// removeIndex removes the index at h, with the owner's empty
// authorization, when it is there and ours says so.
func removeIndex(t transport.TPM, h tpm2.TPMHandle, ours func(*tpm2.TPMSNVPublic, tpm2.TPM2BName) bool) (bool, error) {
	pub, name, err := readNVPublic(t, h)
	if errors.Is(err, tpm2.TPMRCHandle) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading NV index 0x%08X: %w", uint32(h), err)
	}
	if !ours(pub, name) {
		return false, nil
	}
	if _, err := (tpm2.NVUndefineSpace{AuthHandle: tpm2.TPMRHOwner, NVIndex: tpm2.NamedHandle{Handle: h, Name: name}}).Execute(t); err != nil {
		return false, fmt.Errorf("removing NV index 0x%08X: %w", uint32(h), err)
	}
	return true, nil
}
