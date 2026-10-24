// Package swtpmtest runs a software TPM (swtpm) for a test.
package swtpmtest

import (
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// SWTPM is a software TPM over a state directory: stopping and starting it
// again on the same directory is a reboot of the same TPM.
type SWTPM struct {
	Sock string
	dir  string
	cmd  *exec.Cmd
}

// Start runs swtpm for the duration of the test; the test is skipped where
// swtpm is not installed.
func Start(t *testing.T) *SWTPM {
	t.Helper()
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed")
	}
	dir := t.TempDir()
	s := &SWTPM{Sock: filepath.Join(dir, "swtpm.sock"), dir: dir}
	s.start(t)
	t.Cleanup(s.stop)
	return s
}

func (s *SWTPM) start(t *testing.T) {
	t.Helper()
	s.cmd = exec.Command("swtpm", "socket", "--tpm2",
		"--tpmstate", "dir="+s.dir,
		"--server", "type=unixio,path="+s.Sock,
		"--ctrl", "type=unixio,path="+s.Sock+".ctrl",
		"--flags", "not-need-init,startup-clear")
	if err := s.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if c, err := transport.OpenTPM(s.Sock); err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("swtpm did not start")
		}
	}
}

// stop ends the process; one that does not end at SIGTERM (it can sit in
// a read of a client's) is killed.
func (s *SWTPM) stop() {
	s.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { s.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		s.cmd.Process.Kill()
		<-done
	}
}

// Reboot shuts the TPM down as an operating system does before a reboot
// (TPM2_Shutdown(CLEAR)) and starts it again: a TPM reset, with the PCRs
// back at zero and a new NULL hierarchy seed. (swtpm keeps the NULL seed
// over a stop without the shutdown.)
func (s *SWTPM) Reboot(t *testing.T) {
	t.Helper()
	c, err := transport.OpenTPM(s.Sock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (tpm2.Shutdown{ShutdownType: tpm2.TPMSUClear}).Execute(c); err != nil {
		t.Fatal(err)
	}
	c.Close()
	s.stop()
	s.start(t)
}

// Open opens the TPM, closed with the test.
func (s *SWTPM) Open(t *testing.T) transport.TPMCloser {
	t.Helper()
	c, err := transport.OpenTPM(s.Sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// Opener opens the TPM anew on each call.
func (s *SWTPM) Opener() func() (transport.TPMCloser, error) {
	return func() (transport.TPMCloser, error) { return transport.OpenTPM(s.Sock) }
}
