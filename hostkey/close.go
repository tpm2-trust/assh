package hostkey

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// A CA is open while PCR 15 holds its open value, and closed by an extend
// of PCR 15:
//
//	CA policy = PolicyAuthorize(authority, ref) ; PolicyCommandCode(Sign)
//	            ; PolicyPCR(15 == the open value)
//
// The PolicyPCR is the CA's own, after PolicyAuthorize: fixed when the key
// is made, beyond any approval, so no approval - of a slot that reads PCR
// 15 or not - lets the CA sign once PCR 15 has moved. Closing is
// TPM2_PCR_Event(15, "assh-close"): the same digest in every bank as
// systemd-pcrextend's measurement of that word. A PCR goes back to zero
// only at TPM2_Startup(CLEAR) - the next boot; a resume from S3 (Startup
// STATE) keeps it, a resume from hibernation is a boot and does not.
//
// The open value is zero - PCR 15 as every boot starts it - unless the CA
// is made with OpenEvents (CreateOnceCA alone): then it is what those
// events make PCR 15 from zero, for a system whose initrd measures into
// PCR 15 before the agent (safearch's combination), and the CA is left
// open in the boot that makes it. A CA open at zero is closed in the boot
// that makes it: it signs from the next boot on.

// ClosePCR is the PCR whose extend closes a CA.
const ClosePCR = 15

// CloseEvent is what Close measures into ClosePCR.
const CloseEvent = "assh-close"

// ErrClosed is a CA asked to sign after PCR 15 moved from its open value.
var ErrClosed = errors.New("the CA is closed until the next boot (PCR 15 extended)")

// CloseHow is the way a close went.
type CloseHow int

const (
	// ClosedPCR15: PCR 15 moved in every bank, as it should.
	ClosedPCR15 CloseHow = iota
	// ClosedHierarchies: PCR 15 did not move and the owner hierarchy is off
	// (shEnable clear) until the next TPM2_Startup(CLEAR): no key or owner NV
	// index under it answers, whatever the PCRs hold. Keys under the NULL
	// hierarchy and extends still work.
	ClosedHierarchies
	// ClosedPCR7: PCR 15 did not move, the hierarchy stayed on, and PCR 7
	// moved, which every approval of a slot that reads PCR 7 reads. A slot
	// that does not read it stays as it was: on such a CA this is no close.
	ClosedPCR7
)

// CloseResult is a close that succeeded: how, and what each step met.
type CloseResult struct {
	How   CloseHow
	Steps []string
}

// Degraded is a close that needed another way than PCR 15.
func (r CloseResult) Degraded() bool { return r.How != ClosedPCR15 }

func (r CloseResult) String() string {
	var what string
	switch r.How {
	case ClosedPCR15:
		what = fmt.Sprintf("PCR %d extended (%s)", ClosePCR, CloseEvent)
	case ClosedHierarchies:
		what = fmt.Sprintf("PCR %d did not move: the owner hierarchy is off until the next boot", ClosePCR)
	case ClosedPCR7:
		what = fmt.Sprintf("PCR %d did not move and the owner hierarchy stays on: PCR 7 extended", ClosePCR)
	}
	if !r.Degraded() {
		return what
	}
	return what + " (" + strings.Join(r.Steps, "; ") + ")"
}

// CloseError is a close that failed on every way. Answers says whether the TPM
// still answers: one that does has refused everything, one that does not may
// come back.
type CloseError struct {
	Answers bool
	Steps   []string
}

func (e *CloseError) Error() string {
	state := "the TPM does not answer"
	if e.Answers {
		state = "the TPM answers and refuses"
	}
	return fmt.Sprintf("the close failed, %s: %s", state, strings.Join(e.Steps, "; "))
}

// Close closes every CA open at the value PCR 15 had, until the next boot. It
// needs no CA file: a CA that could not be read is closed all the same.
//
//  1. TPM2_PCR_Event(15, CloseEvent) in every bank the TPM has, tried once
//     more, each time read back: a PCR that holds what it held is a failure.
//  2. What the PCR did not take, the hierarchies: shEnable cleared with the
//     owner's empty authorization (the platform's where that is refused), then
//     ehEnable and, last, phEnable with the platform's: a firmware that locked
//     the platform refuses those two, which is said and is no failure. Before
//     phEnable the platform's authorization goes random, as a resume from S3
//     sets phEnable again.
//  3. A TPM with an owner password refuses that: TPM2_PCR_Event(7, CloseEvent),
//     read back.
//
// 2 and 3 are a success, Degraded in the result: the boot may go on, with no
// CA and nothing else under the owner hierarchy. All three failed is a
// *CloseError. Where systemd keeps its measurement log, an extend gets a record
// in it; the log's trouble is said on stderr and is never the close's.
func Close(t transport.TPM) (CloseResult, error) {
	var steps []string
	for try := 0; try < 2; try++ {
		err := extendChecked(t, ClosePCR)
		if err == nil {
			return CloseResult{How: ClosedPCR15}, nil
		}
		steps = append(steps, err.Error())
	}
	off, more := killHierarchies(t)
	steps = append(steps, more...)
	if off {
		return CloseResult{How: ClosedHierarchies, Steps: steps}, nil
	}
	err := extendChecked(t, closeFallbackPCR)
	if err == nil {
		return CloseResult{How: ClosedPCR7, Steps: steps}, nil
	}
	steps = append(steps, err.Error())
	return CloseResult{}, &CloseError{Answers: tpmAnswers(t), Steps: steps}
}

// closeFallbackPCR is what a close extends when PCR 15 and the hierarchies
// refused.
const closeFallbackPCR = 7

// extendChecked is TPM2_PCR_Event(pcr, CloseEvent), read back in every bank.
func extendChecked(t transport.TPM, pcr int) error {
	before, err := pcrBanks(t, pcr)
	if err != nil {
		return fmt.Errorf("PCR %d before the extend: %w", pcr, err)
	}
	log, logErr := openMeasureLog(t, pcr, CloseEvent)
	_, err = (tpm2.PCREvent{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(pcr), Auth: tpm2.PasswordAuth(nil)},
		EventData: tpm2.TPM2BEvent{Buffer: []byte(CloseEvent)},
	}).Execute(t)
	if logErr == nil {
		logErr = log.done(err == nil)
	}
	if logErr != nil {
		fmt.Fprintf(os.Stderr, "the measurement log has no record of the close: %v\n", logErr)
	}
	if err != nil {
		return fmt.Errorf("extending PCR %d: %w", pcr, err)
	}
	after, err := pcrBanks(t, pcr)
	if err != nil {
		return fmt.Errorf("PCR %d after the extend: %w", pcr, err)
	}
	for alg, was := range before {
		if bytes.Equal(after[alg], was) {
			return fmt.Errorf("PCR %d did not move in the %v bank", pcr, alg)
		}
	}
	return nil
}

// pcrBanks is pcr in every bank the TPM has it in.
func pcrBanks(t transport.TPM, pcr int) (map[tpm2.TPMIAlgHash][]byte, error) {
	rsp, err := tpm2.GetCapability{Capability: tpm2.TPMCapPCRs, PropertyCount: 8}.Execute(t)
	if err != nil {
		return nil, err
	}
	sel, err := rsp.CapabilityData.Data.AssignedPCR()
	if err != nil {
		return nil, err
	}
	out := map[tpm2.TPMIAlgHash][]byte{}
	for _, s := range sel.PCRSelections {
		if pcr/8 >= len(s.PCRSelect) || s.PCRSelect[pcr/8]&(1<<(pcr%8)) == 0 {
			continue
		}
		got, err := tpm2.PCRRead{PCRSelectionIn: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash: s.Hash, PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcr)),
		}}}}.Execute(t)
		if err != nil {
			return nil, err
		}
		if len(got.PCRValues.Digests) != 1 {
			return nil, fmt.Errorf("the %v bank does not give PCR %d", s.Hash, pcr)
		}
		out[s.Hash] = got.PCRValues.Digests[0].Buffer
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no bank of the TPM holds PCR %d", pcr)
	}
	return out, nil
}

// Hierarchies is what TPM2_Startup(CLEAR) enabled and is still on.
type Hierarchies struct {
	Platform, Storage, Endorsement bool
}

// ReadHierarchies reads them.
func ReadHierarchies(t transport.TPM) (Hierarchies, error) {
	rsp, err := tpm2.GetCapability{
		Capability: tpm2.TPMCapTPMProperties, Property: uint32(tpm2.TPMPTStartupClear), PropertyCount: 1,
	}.Execute(t)
	if err != nil {
		return Hierarchies{}, err
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return Hierarchies{}, err
	}
	if len(props.TPMProperty) != 1 || props.TPMProperty[0].Property != tpm2.TPMPTStartupClear {
		return Hierarchies{}, errors.New("the TPM does not give TPM_PT_STARTUP_CLEAR")
	}
	v := props.TPMProperty[0].Value
	return Hierarchies{Platform: v&1 != 0, Storage: v&2 != 0, Endorsement: v&4 != 0}, nil
}

// killHierarchies clears shEnable, read back, then ehEnable and phEnable. It
// says whether shEnable is clear, and what each step met.
func killHierarchies(t transport.TPM) (off bool, steps []string) {
	state, err := ReadHierarchies(t)
	if err != nil {
		return false, []string{"the hierarchies: " + err.Error()}
	}
	if state.Storage {
		err := hierarchyOff(t, tpm2.TPMRHOwner, tpm2.TPMRHOwner)
		if err != nil {
			steps = append(steps, "the owner refused to clear shEnable: "+err.Error())
			if err := hierarchyOff(t, tpm2.TPMRHPlatform, tpm2.TPMRHOwner); err != nil {
				steps = append(steps, "the platform refused to clear shEnable: "+err.Error())
			}
		}
		if state, err = ReadHierarchies(t); err != nil {
			return false, append(steps, "the hierarchies: "+err.Error())
		}
	}
	off = !state.Storage
	if !off {
		return false, append(steps, "shEnable is still set")
	}
	steps = append(steps, "shEnable clear")
	if state.Endorsement {
		if err := hierarchyOff(t, tpm2.TPMRHPlatform, tpm2.TPMRHEndorsement); err != nil {
			steps = append(steps, "ehEnable stays set, the platform's authorization refused (expected where the firmware locked it): "+err.Error())
		} else {
			steps = append(steps, "ehEnable clear")
		}
	}
	if state.Platform {
		// Every TPM2_Startup sets phEnable again, a resume from S3 too, which
		// keeps the rest: an empty platform authorization would then let root
		// set shEnable again. Only TPM2_Startup(CLEAR) resets this one.
		var auth []byte
		if b := make([]byte, 32); randomPlatformAuth(t, b) == nil {
			auth = b
		}
		if err := hierarchyOff(t, tpm2.TPMRHPlatform, tpm2.TPMRHPlatform, auth...); err != nil {
			steps = append(steps, "phEnable stays set, the platform's authorization refused (expected where the firmware locked it): "+err.Error())
		} else {
			steps = append(steps, "phEnable clear")
		}
	}
	return true, steps
}

// randomPlatformAuth gives the platform b, random, as its authorization.
func randomPlatformAuth(t transport.TPM, b []byte) error {
	if _, err := rand.Read(b); err != nil {
		return err
	}
	_, err := (tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHPlatform, Auth: tpm2.PasswordAuth(nil)},
		NewAuth:    tpm2.TPM2BAuth{Buffer: b},
	}).Execute(t)
	return err
}

// hierarchyOff is TPM2_HierarchyControl(auth, enable, NO) with that password,
// none by default. go-tpm has no such command, so its bytes are written here.
func hierarchyOff(t transport.TPM, auth, enable tpm2.TPMHandle, password ...byte) error {
	cmd := binary.BigEndian.AppendUint16(nil, uint16(tpm2.TPMSTSessions))
	cmd = binary.BigEndian.AppendUint32(cmd, 0) // the size, below
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(tpm2.TPMCCHierarchyControl))
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(auth))
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(9+len(password))) // one password session
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(tpm2.TPMRSPW))
	cmd = append(cmd, 0, 0, 0) // no nonce, no attributes
	cmd = binary.BigEndian.AppendUint16(cmd, uint16(len(password)))
	cmd = append(cmd, password...)
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(enable))
	cmd = append(cmd, 0) // state: NO
	binary.BigEndian.PutUint32(cmd[2:], uint32(len(cmd)))
	rsp, err := t.Send(cmd)
	if err != nil {
		return err
	}
	if len(rsp) < 10 {
		return fmt.Errorf("a response of %d bytes", len(rsp))
	}
	if rc := binary.BigEndian.Uint32(rsp[6:]); rc != 0 {
		return tpm2.TPMRC(rc)
	}
	return nil
}

// tpmAnswers is whether the TPM answers at all: a TPM in failure mode still
// gives its capabilities.
func tpmAnswers(t transport.TPM) bool {
	_, err := tpm2.GetCapability{
		Capability: tpm2.TPMCapTPMProperties, Property: uint32(tpm2.TPMPTManufacturer), PropertyCount: 1,
	}.Execute(t)
	return err == nil
}

// closeGate is PolicyCommandCode(Sign) ; PolicyPCR(15 == open), the part of
// the CA's policy after PolicyAuthorize.
func closeGate(bank Bank, open []byte) []func(*tpm2.PolicyCalculator) error {
	return []func(*tpm2.PolicyCalculator) error{
		tpm2.PolicyCommandCode{Code: tpm2.TPMCCSign}.Update,
		tpm2.PolicyPCR{PcrDigest: tpm2.TPM2BDigest{Buffer: openDigest(open)}, Pcrs: selection(bank, []int{ClosePCR})}.Update,
	}
}

// openDigest is what PolicyPCR compares: the SHA-256 of the open value
// (the session's hash, whatever the bank).
func openDigest(open []byte) []byte {
	d := sha256.Sum256(open)
	return d[:]
}

// checkOpenValue makes sure the file's open value fits its bank.
func (f *CA) checkOpenValue() error {
	if len(f.OpenValue) != f.Bank.size() {
		return fmt.Errorf("the CA's open value of PCR %d has %d bytes, the %s bank %d", ClosePCR, len(f.OpenValue), f.Bank, f.Bank.size())
	}
	return nil
}

// IsOpen is whether the CA is open now: PCR 15 holds its open value.
func (f *CA) IsOpen(t transport.TPM) (bool, error) {
	now, err := ReadPCRs(t, f.Bank, []int{ClosePCR})
	if err != nil {
		return false, err
	}
	return bytes.Equal(now[ClosePCR], f.OpenValue), nil
}
