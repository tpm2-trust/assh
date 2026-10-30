package hostkey

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/tpm2-trust/assh/persist"
)

// The window is W, an NV index of the CA's own:
//
//	W  an NV counter, read-lockable until the next boot (TPMA_NV_READ_STCLEAR),
//	   read with its empty authorization value, noDA. Its policy allows one
//	   increment, while it is unwritten: at the CA's creation, to the value v.
//
// The CA's policy is PolicyAuthorize(authority, ref) ; PolicyCommandCode(Sign)
// ; PolicyNV(W == v). Closing the window is TPM2_NV_ReadLock(W): PolicyNV then
// fails, whatever an approval says, until TPM2_Startup(CLEAR) - the next boot.
// W is closed when it is made: a CA signs from the boot after its creation.
// Undefined and defined again alike, W has its Name back but its first value
// lands above every value a counter has had (TPM 2.0 Part 1, 37.2.6.3): never
// v again. Deleting W stops the CA, as deleting the CA would.

// DefaultWindowHandle is W's NV handle unless the CA names another.
const DefaultWindowHandle tpm2.TPMHandle = 0x01802915

// ErrWindowClosed is a CA asked to sign after its window closed.
var ErrWindowClosed = errors.New("the CA's window is closed until the next boot")

// Window is W as the CA file has it: its public area, written, and v.
type Window struct {
	Public []byte `json:"public"`
	Value  uint64 `json:"value"`
}

// windowIncrement is W's policy: one increment, while it is unwritten.
func windowIncrement() []func(*tpm2.PolicyCalculator) error {
	return []func(*tpm2.PolicyCalculator) error{
		tpm2.PolicyCommandCode{Code: tpm2.TPMCCNVIncrement}.Update,
		tpm2.PolicyNVWritten{WrittenSet: false}.Update,
	}
}

// windowPublic is W as it is defined, unwritten.
func windowPublic(h tpm2.TPMHandle) tpm2.TPMSNVPublic {
	return tpm2.TPMSNVPublic{
		NVIndex: h,
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			NT:          tpm2.TPMNTCounter,
			PolicyWrite: true,
			AuthRead:    true,
			NoDA:        true,
			ReadSTClear: true,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: policyDigest(windowIncrement()...)},
		DataSize:   8,
	}
}

// defineWindow defines W at h, gives it its one value and closes it: a new
// CA signs from the next boot on.
func defineWindow(t transport.TPM, h tpm2.TPMHandle) (*Window, error) {
	if err := ownerNVHandle(h); err != nil {
		return nil, err
	}
	if _, _, err := persist.ReadNVPublic(t, h); err == nil {
		return nil, fmt.Errorf("NV handle 0x%08X is in use", uint32(h))
	}
	pub := windowPublic(h)
	if _, err := (tpm2.NVDefineSpace{AuthHandle: tpm2.TPMRHOwner, PublicInfo: tpm2.New2B(pub)}).Execute(t); err != nil {
		return nil, fmt.Errorf("defining the window index at 0x%08X: %w", uint32(h), err)
	}
	fail := func(err error) (*Window, error) {
		persist.RemoveNV(t, h, persist.Defined(pub))
		return nil, err
	}
	s, done, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return fail(err)
	}
	defer done()
	if _, err := (tpm2.PolicyCommandCode{PolicySession: s.Handle(), Code: tpm2.TPMCCNVIncrement}).Execute(t); err != nil {
		return fail(err)
	}
	if _, err := (tpm2.PolicyNVWritten{PolicySession: s.Handle(), WrittenSet: false}).Execute(t); err != nil {
		return fail(err)
	}
	name := nvName(pub)
	if _, err := (tpm2.NVIncrement{
		AuthHandle: tpm2.AuthHandle{Handle: h, Name: name, Auth: s},
		NVIndex:    tpm2.NamedHandle{Handle: h, Name: name},
	}).Execute(t); err != nil {
		return fail(fmt.Errorf("writing the window index: %w", err))
	}
	pub = written(pub)
	name = nvName(pub)
	v, err := readCount(t, h, name, tpm2.AuthHandle{Handle: h, Name: name, Auth: tpm2.PasswordAuth(nil)})
	if err != nil {
		return fail(fmt.Errorf("reading the window index: %w", err))
	}
	// Closed in the boot that makes it: the CA signs from the next boot on,
	// not in one whose window has been open to every process all along.
	if _, err := CloseWindow(t, h); err != nil {
		return fail(err)
	}
	return &Window{Public: tpm2.Marshal(pub), Value: v}, nil
}

// window is W as the file has it.
func (f *CA) window() (tpm2.TPMSNVPublic, error) {
	if f.Window == nil {
		return tpm2.TPMSNVPublic{}, errors.New("the CA has no window index")
	}
	pub, err := tpm2.Unmarshal[tpm2.TPMSNVPublic](f.Window.Public)
	if err != nil {
		return tpm2.TPMSNVPublic{}, fmt.Errorf("the window index: %w", err)
	}
	if want := written(windowPublic(pub.NVIndex)); !persist.Defined(want)(pub, nvName(*pub)) || !pub.Attributes.Written {
		return tpm2.TPMSNVPublic{}, fmt.Errorf("the window index at 0x%08X is not defined as a window", uint32(pub.NVIndex))
	}
	return *pub, nil
}

// WindowHandle is W's NV handle.
func (f *CA) WindowHandle() tpm2.TPMHandle {
	w, err := f.window()
	if err != nil {
		return 0
	}
	return w.NVIndex
}

// windowGate is PolicyCommandCode(Sign) ; PolicyNV(W == v), the part of the
// CA's policy after PolicyAuthorize.
func windowGate(w tpm2.TPMSNVPublic, v uint64) []func(*tpm2.PolicyCalculator) error {
	n := nvName(w)
	return []func(*tpm2.PolicyCalculator) error{
		tpm2.PolicyCommandCode{Code: tpm2.TPMCCSign}.Update,
		tpm2.PolicyNV{
			NVIndex:   tpm2.NamedHandle{Handle: w.NVIndex, Name: n},
			OperandB:  tpm2.TPM2BOperand{Buffer: binary.BigEndian.AppendUint64(nil, v)},
			Operation: tpm2.TPMEOEq,
		}.Update,
	}
}

// WindowOpen is whether the CA's window is open now: W there, as the file
// has it, and not read-locked.
func (f *CA) WindowOpen(t transport.TPM) (bool, error) {
	w, err := f.window()
	if err != nil {
		return false, err
	}
	pub, name, err := persist.ReadNVPublic(t, w.NVIndex)
	if errors.Is(err, tpm2.TPMRCHandle) {
		return false, fmt.Errorf("the window index at 0x%08X is not in this TPM (another TPM, a cleared one, or deleted): the CA signs nothing", uint32(w.NVIndex))
	}
	if err != nil {
		return false, err
	}
	if string(name.Buffer) != string(nvName(w).Buffer) && !pub.Attributes.ReadLocked {
		return false, fmt.Errorf("the window index at 0x%08X is not the CA's (deleted or replaced): the CA signs nothing", uint32(w.NVIndex))
	}
	return !pub.Attributes.ReadLocked, nil
}

// Close closes the CA's window until the next boot.
func (f *CA) Close(t transport.TPM) error {
	w, err := f.window()
	if err != nil {
		return err
	}
	_, err = CloseWindow(t, w.NVIndex)
	return err
}

// CloseWindow read-locks the window index at h until the next boot, for a
// program that has no CA file at hand (it could not be read): only an index
// defined as a window is locked, so that no other is. It reports whether
// one was there; none is no error.
func CloseWindow(t transport.TPM, h tpm2.TPMHandle) (bool, error) {
	pub, name, err := persist.ReadNVPublic(t, h)
	if errors.Is(err, tpm2.TPMRCHandle) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading NV index 0x%08X: %w", uint32(h), err)
	}
	if !persist.Defined(written(windowPublic(h)))(pub, name) {
		return false, fmt.Errorf("NV index 0x%08X is no window index: left as it is", uint32(h))
	}
	if !pub.Attributes.Written {
		return true, nil // PolicyNV fails on it anyway
	}
	if _, err := (tpm2.NVReadLock{
		AuthHandle: tpm2.AuthHandle{Handle: h, Name: name, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: h, Name: name},
	}).Execute(t); err != nil {
		return true, fmt.Errorf("closing the window (NV index 0x%08X): %w", uint32(h), err)
	}
	return true, nil
}

// ExtendPCR extends pcr with event in every bank (TPM2_PCR_Event): for what
// others bind to that PCR, beside the CA's window. 16 and 23, which any
// process can reset, and the DRTM PCRs 17-22 are refused.
func ExtendPCR(t transport.TPM, pcr int, event string) error {
	if pcr < 0 || pcr > 15 {
		return fmt.Errorf("PCR %d: 0 to 15 (16 to 23 can be reset)", pcr)
	}
	_, err := tpm2.PCREvent{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(pcr), Auth: tpm2.PasswordAuth(nil)},
		EventData: tpm2.TPM2BEvent{Buffer: []byte(event)},
	}.Execute(t)
	if err != nil {
		return fmt.Errorf("extending PCR %d: %w", pcr, err)
	}
	return nil
}
