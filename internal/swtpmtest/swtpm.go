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

// LockoutAuth is the lockout authorization SetLockout gives the TPM.
var LockoutAuth = []byte("swtpmtest lockout")

// SetLockout gives the TPM a lockout authorization (LockoutAuth) and the
// dictionary attack parameters maxTries, recovery and lockoutRecovery.
func (s *SWTPM) SetLockout(t *testing.T, maxTries, recovery, lockoutRecovery uint32) {
	t.Helper()
	c := s.Open(t)
	if _, err := (tpm2.HierarchyChangeAuth{AuthHandle: tpm2.TPMRHLockout, NewAuth: tpm2.TPM2BAuth{Buffer: LockoutAuth}}).Execute(c); err != nil {
		t.Fatal(err)
	}
	lockout := tpm2.AuthHandle{Handle: tpm2.TPMRHLockout, Auth: tpm2.PasswordAuth(LockoutAuth)}
	if _, err := (tpm2.DictionaryAttackParameters{AuthHandle: lockout, MaxTries: maxTries, RecoveryTime: recovery, LockoutRecovery: lockoutRecovery}).Execute(c); err != nil {
		t.Fatal(err)
	}
}

// ResetLockout forgets the counted authorization failures (needs
// SetLockout first).
func (s *SWTPM) ResetLockout(t *testing.T) {
	t.Helper()
	c := s.Open(t)
	lockout := tpm2.AuthHandle{Handle: tpm2.TPMRHLockout, Auth: tpm2.PasswordAuth(LockoutAuth)}
	if _, err := (tpm2.DictionaryAttackLockReset{LockHandle: lockout}).Execute(c); err != nil {
		t.Fatal(err)
	}
}

// NoneLeft fails the test when the TPM holds a transient object or a
// session: without a resource manager, whatever a command leaves stays.
// Leftovers are flushed.
func NoneLeft(t *testing.T, c transport.TPM, after string) {
	t.Helper()
	for _, first := range []uint32{0x80000000, 0x02000000} {
		rsp, err := tpm2.GetCapability{Capability: tpm2.TPMCapHandles, Property: first, PropertyCount: 64}.Execute(c)
		if err != nil {
			t.Fatal(err)
		}
		hs, err := rsp.CapabilityData.Data.Handles()
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range hs.Handle {
			t.Errorf("%s: handle 0x%08X left in the TPM", after, uint32(h))
			tpm2.FlushContext{FlushHandle: h}.Execute(c)
		}
	}
}

// Recorder is a TPM that keeps every byte sent to it and back.
type Recorder struct {
	transport.TPM
	Bytes []byte
}

// Send implements transport.TPM.
func (r *Recorder) Send(cmd []byte) ([]byte, error) {
	r.Bytes = append(r.Bytes, cmd...)
	rsp, err := r.TPM.Send(cmd)
	r.Bytes = append(r.Bytes, rsp...)
	return rsp, err
}
