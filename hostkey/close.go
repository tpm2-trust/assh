package hostkey

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"

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

// Close extends PCR 15 with CloseEvent in every bank the TPM has: every
// CA open at the value PCR 15 had signs nothing more until the next boot.
// It needs no CA file: a CA that could not be read is closed all the same.
// Where systemd keeps its measurement log, the extend gets a record in it;
// the log's trouble is said on stderr and is never the close's.
func Close(t transport.TPM) error {
	log, logErr := openMeasureLog(t, ClosePCR, CloseEvent)
	_, err := (tpm2.PCREvent{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(ClosePCR), Auth: tpm2.PasswordAuth(nil)},
		EventData: tpm2.TPM2BEvent{Buffer: []byte(CloseEvent)},
	}).Execute(t)
	if logErr == nil {
		logErr = log.done(err == nil)
	}
	if logErr != nil {
		fmt.Fprintf(os.Stderr, "the measurement log has no record of the close: %v\n", logErr)
	}
	if err != nil {
		return fmt.Errorf("closing the CA (extending PCR %d): %w", ClosePCR, err)
	}
	return nil
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
