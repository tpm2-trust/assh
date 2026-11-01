package hostkey

import (
	"crypto"
	_ "crypto/sha1"   // the banks of the record
	_ "crypto/sha256" // ...
	_ "crypto/sha512" // ...
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/sys/unix"
)

// measureLogDir is where systemd keeps its log of what userspace measured,
// /run/log/systemd/tpm2-measure.log. The record of the close is written to
// it only where the directory is there: it says what moved PCR 15 to
// whoever replays it (systemd-pcrlock, a status), and changes nothing of
// the close. A variable for the tests.
var measureLogDir = "/run/log/systemd"

const measureLogName = "tpm2-measure.log"

// measureLogLockWait bounds the wait for systemd's lock on the log: the
// close never hangs on whoever holds it, it goes on without the record.
const measureLogLockWait = time.Second

// measureDigest is one bank's digest in a record, measureRecord the record
// itself: what systemd-pcrextend appends for "--pcr=15 assh-close" (systemd
// 262, read from its output: a JSON text sequence, RFC 7464, one record of
// all banks per extend; content_type "systemd", eventType "phase" for a word).
type measureDigest struct {
	HashAlg string `json:"hashAlg"`
	Digest  string `json:"digest"`
}

type measureContent struct {
	String    string `json:"string"`
	BootID    string `json:"bootId"`
	Timestamp uint64 `json:"timestamp"`
	EventType string `json:"eventType"`
}

type measureRecord struct {
	PCR         int             `json:"pcr"`
	Digests     []measureDigest `json:"digests"`
	ContentType string          `json:"content_type"`
	Content     measureContent  `json:"content"`
}

// measureBanks are the banks systemd records, by the TPM's name of them.
var measureBanks = map[tpm2.TPMAlgID]struct {
	name string
	hash crypto.Hash
}{
	tpm2.TPMAlgSHA1:   {"sha1", crypto.SHA1},
	tpm2.TPMAlgSHA256: {"sha256", crypto.SHA256},
	tpm2.TPMAlgSHA384: {"sha384", crypto.SHA384},
	tpm2.TPMAlgSHA512: {"sha512", crypto.SHA512},
}

// measureLog is the log, open and locked for one extend. A nil *measureLog
// is no log: every method does nothing. As systemd does, the file's sticky
// bit is set while an extend is under way: found set, the log may lack a
// record.
type measureLog struct {
	f      *os.File
	record measureRecord
}

// openMeasureLog opens the log for an extend of pcr with event, or returns
// nil and why not. No directory is not a reason worth saying: nil, nil.
func openMeasureLog(t transport.TPM, pcr int, event string) (*measureLog, error) {
	if st, err := os.Stat(measureLogDir); err != nil || !st.IsDir() {
		return nil, nil
	}
	digests, err := eventDigests(t, pcr, event)
	if err != nil {
		return nil, err
	}
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		return nil, fmt.Errorf("the boot time: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(measureLogDir, measureLogName),
		os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	l := &measureLog{f: f, record: measureRecord{
		PCR:         pcr,
		Digests:     digests,
		ContentType: "systemd",
		Content: measureContent{
			String:    event,
			BootID:    strings.ReplaceAll(strings.TrimSpace(string(bootID)), "-", ""),
			Timestamp: uint64(now.Nano() / 1000),
			EventType: "phase",
		},
	}}
	if err := l.lockAndMark(); err != nil {
		f.Close()
		return nil, err
	}
	return l, nil
}

// lockAndMark takes the lock, which systemd's writers hold while they write,
// and sets the sticky bit.
func (l *measureLog) lockAndMark() error {
	st, err := l.f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", l.f.Name())
	}
	deadline := time.Now().Add(measureLogLockWait)
	for {
		err := unix.Flock(int(l.f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			return fmt.Errorf("locking %s: %w", l.f.Name(), err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s stays locked", l.f.Name())
		}
		time.Sleep(10 * time.Millisecond)
	}
	return l.f.Chmod(st.Mode().Perm() | os.ModeSticky)
}

// done ends the extend: the record appended if it happened, the sticky bit
// cleared either way, unlocked. Its error is about the log alone.
func (l *measureLog) done(extended bool) error {
	if l == nil {
		return nil
	}
	defer l.f.Close()
	if extended {
		line, err := l.record.marshal()
		if err == nil {
			_, err = l.f.Write(line)
		}
		if err != nil {
			return fmt.Errorf("writing %s: %w", l.f.Name(), err)
		}
	}
	return l.f.Chmod(0o600)
}

// marshal is the record as the log holds it: RS, the JSON, a newline.
func (r measureRecord) marshal() ([]byte, error) {
	j, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append(append([]byte{0x1e}, j...), '\n'), nil
}

// eventDigests is what TPM2_PCR_Event(pcr, event) extends in every bank
// that holds pcr: the digest of the event itself, in the bank's hash.
func eventDigests(t transport.TPM, pcr int, event string) ([]measureDigest, error) {
	rsp, err := tpm2.GetCapability{Capability: tpm2.TPMCapPCRs, PropertyCount: 8}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("the TPM's PCR banks: %w", err)
	}
	sel, err := rsp.CapabilityData.Data.AssignedPCR()
	if err != nil {
		return nil, fmt.Errorf("the TPM's PCR banks: %w", err)
	}
	var out []measureDigest
	for _, s := range sel.PCRSelections {
		bank, known := measureBanks[s.Hash]
		if !known || pcr/8 >= len(s.PCRSelect) || s.PCRSelect[pcr/8]&(1<<(pcr%8)) == 0 {
			continue
		}
		h := bank.hash.New()
		h.Write([]byte(event))
		out = append(out, measureDigest{HashAlg: bank.name, Digest: hex.EncodeToString(h.Sum(nil))})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no bank of the TPM holds PCR %d", pcr)
	}
	return out, nil
}
