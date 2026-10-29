package hostkey

import (
	"errors"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tpm2-trust/assh/persist"
)

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
			ok, err := persist.RemoveNV(t, pub.NVIndex, persist.Named(nvName(pub)))
			if errors.Is(err, persist.ErrNotOurs) {
				continue
			}
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
			ok, err := persist.RemoveNV(t, h, func(pub *tpm2.TPMSNVPublic, _ tpm2.TPM2BName) bool {
				return pub.DataSize == 8 && (pub.Attributes == pin || pub.Attributes == counter)
			})
			if errors.Is(err, persist.ErrNotOurs) {
				continue
			}
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
	if persist.IsVar(path) {
		ok, err := persist.RemoveVar(path)
		if err != nil {
			return removed, err
		}
		if ok {
			removed = append(removed, path)
		}
		return removed, nil
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
