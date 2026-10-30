package hostkey

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/tpm2-trust/assh/persist"
)

// Handles are the NV handles of a CA's indices; 0 is the default handle.
type Handles struct{ PIN, Counter, Window tpm2.TPMHandle }

// Defaults is h with the default handle wherever it has 0.
func (h Handles) Defaults() Handles {
	if h.PIN == 0 {
		h.PIN = DefaultPINHandle
	}
	if h.Counter == 0 {
		h.Counter = DefaultCounterHandle
	}
	h.Window = windowHandle(h.Window)
	return h
}

// ErrLeft is an index at one of a CA's handles that RemoveCA left: it is
// not defined as aSSH defines it, or what it depends on is gone.
var ErrLeft = errors.New("left in the TPM")

// RemoveCA removes the CA at path and what it holds in the TPM: its window
// index, and with an authority in the TPM its PIN index and counter. An
// index goes only where the TPM holds one defined exactly as aSSH defines
// it at that handle - attributes, size, policy (persist.Defined); the
// counter's policy names the PIN index the TPM holds and its value, read
// there, never what the file says. The file names the handles; with no
// file at path, h does. What is left is named in an error that wraps
// ErrLeft; the rest is removed all the same. It gives what it removed;
// absent is no error.
func RemoveCA(t transport.TPM, path string, h Handles) ([]string, error) {
	h = h.Defaults()
	ca, err := LoadCA(path)
	switch {
	case err == nil:
		h = Handles{Window: ca.WindowHandle()}
		if ca.AuthorityTPM != nil {
			if p, _, err := ca.pinIndex(); err == nil {
				h.PIN = p.NVIndex
			}
		}
		if ca.Counter != nil {
			if g, err := ca.counter(); err == nil {
				h.Counter = g.NVIndex
			}
		}
	case os.IsNotExist(err):
		ca = nil
	default:
		return nil, err
	}
	removed, left := removeIndices(t, h)
	if ca != nil {
		gone, err := removeFile(path)
		removed = append(removed, gone...)
		if err != nil {
			return removed, err
		}
	}
	if len(left) > 0 {
		return removed, fmt.Errorf("%w: %s", ErrLeft, strings.Join(left, "; "))
	}
	return removed, nil
}

// removeIndices removes those of h's indices that are aSSH's: the PIN
// index P (its template is constant), the counter G (its policy names P
// and P's value, read from the P the TPM holds), the window index W. A
// handle of 0 is skipped.
func removeIndices(t transport.TPM, h Handles) (removed, left []string) {
	take := func(handle tpm2.TPMHandle, what string, want *tpm2.TPMSNVPublic) {
		if handle == 0 {
			return
		}
		if want == nil {
			if _, _, err := persist.ReadNVPublic(t, handle); err == nil {
				left = append(left, fmt.Sprintf("%s at 0x%08X: its PIN index is gone, so it cannot be told from another's", what, uint32(handle)))
			}
			return
		}
		ok, err := persist.RemoveNV(t, handle, persist.Defined(*want))
		switch {
		case errors.Is(err, persist.ErrNotOurs):
			left = append(left, fmt.Sprintf("%s at 0x%08X: not defined as aSSH's", what, uint32(handle)))
		case err != nil:
			left = append(left, fmt.Sprintf("%s at 0x%08X: %v", what, uint32(handle), err))
		case ok:
			removed = append(removed, fmt.Sprintf("%s, NV index 0x%08X", what, uint32(handle)))
		}
	}
	// G's template needs P's Name and value: G goes before P.
	var gWant *tpm2.TPMSNVPublic
	if h.PIN != 0 && h.Counter != 0 {
		p := written(pinIndexPublic(h.PIN))
		if pub, name, err := persist.ReadNVPublic(t, h.PIN); err == nil && persist.Defined(p)(pub, name) && pub.Attributes.Written {
			if k, err := readCount(t, h.PIN, name, tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)}); err == nil {
				g := counterPublic(h.Counter, p, k)
				gWant = &g
			}
		}
	}
	take(h.Counter, "counter", gWant)
	if h.PIN != 0 {
		p := pinIndexPublic(h.PIN)
		take(h.PIN, "PIN index", &p)
	}
	w := windowPublic(h.Window)
	take(h.Window, "window index", &w)
	return removed, left
}

// removeFile removes the CA file and its .pub, or the EFI variable.
func removeFile(path string) ([]string, error) {
	var removed []string
	if persist.IsVar(path) {
		ok, err := persist.RemoveVar(path)
		if err != nil {
			return nil, err
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
