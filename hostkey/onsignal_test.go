package hostkey

import (
	"bytes"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/tpm2-trust/assh/internal/swtpmtest"
)

func pcr15(t *testing.T, tpm transport.TPM) []byte {
	t.Helper()
	rsp, err := tpm2.PCRRead{PCRSelectionIn: selection(SHA256, []int{ClosePCR})}.Execute(tpm)
	if err != nil || len(rsp.PCRValues.Digests) != 1 {
		t.Fatalf("reading PCR %d: %v", ClosePCR, err)
	}
	return rsp.PCRValues.Digests[0].Buffer
}

// A signal while the CA may be open closes it before the process ends: with
// the TPM not opened yet (through the guard's own open), and through the
// TPM the caller uses. After Stop the signal is the caller's again.
func TestCloseOnSignal(t *testing.T) {
	for _, opened := range []bool{false, true} {
		sw := swtpmtest.Start(t)
		var logged []string
		exited := make(chan int, 1)
		g := CloseOnSignal(sw.Opener(), func(s string) { logged = append(logged, s) })
		g.exit = func(code int) { exited <- code }
		var tpm transport.TPMCloser
		if opened {
			tpm = g.TPM(sw.Open(t))
			if !bytes.Equal(pcr15(t, tpm), make([]byte, 32)) {
				t.Fatal("PCR 15 is not zero at the start")
			}
		}
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		select {
		case code := <-exited:
			if code != 128+int(syscall.SIGHUP) {
				t.Fatalf("opened %v: exit %d", opened, code)
			}
		case <-time.After(20 * time.Second):
			t.Fatalf("opened %v: the signal did not end the process", opened)
		}
		if tpm == nil {
			tpm = sw.Open(t)
		}
		if bytes.Equal(pcr15(t, tpm), make([]byte, 32)) {
			t.Fatalf("opened %v: PCR 15 is not extended: the CA is open\n%s", opened, strings.Join(logged, "\n"))
		}
		if all := strings.Join(logged, "\n"); !strings.Contains(all, "signal hangup") || strings.Contains(all, "NOT CLOSED") {
			t.Fatalf("opened %v: the log:\n%s", opened, all)
		}
		g.Stop()
		g.Stop() // twice is once
		tpm.Close()
	}
}
