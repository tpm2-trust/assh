package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/tpm2-trust/assh/internal/swtpmtest"
)

// What a descriptor gives is read to its end, in one buffer, up to the limit.
func TestReadSecretFromAFileDescriptor(t *testing.T) {
	// This process stays dumpable: the test below maps a user namespace from it.
	lock := lockForSecret
	lockForSecret = func() error { return nil }
	defer func() { lockForSecret = lock }()
	for _, tc := range []struct {
		name string
		n    int
		ok   bool
	}{{"empty", 0, true}, {"short", 8, true}, {"the limit", maxSecret, true}, {"past the limit", maxSecret + 1, false}, {"far past it", 3 * maxSecret, false}} {
		t.Run(tc.name, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			want := bytes.Repeat([]byte("x"), tc.n)
			go func() { w.Write(want); w.Close() }()
			got, err := readSecret(int(r.Fd()), "PIN", false)
			if tc.ok && (err != nil || !bytes.Equal(got, want)) {
				t.Errorf("%d bytes: %v", len(got), err)
			}
			if !tc.ok && (err == nil || !strings.Contains(err.Error(), "more than")) {
				t.Errorf("%d bytes: %v", len(got), err)
			}
		})
	}
}

// Root that cannot lock its memory reads no secret: uid 0 of a user namespace, as a
// container's, has no CAP_IPC_LOCK where the kernel asks. A user goes on, and is told.
func TestRefusedLockStopsBeforeTheSecret(t *testing.T) {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		t.Fatal(err)
	}
	if limit.Cur == unix.RLIM_INFINITY {
		t.Skip("no limit on locked memory here: nothing refuses")
	}
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed")
	}
	sw := swtpmtest.Start(t)
	s := &secrets{t: t}
	args := []string{"tpm", "da", "--tpm=" + sw.Sock, "--new-lockout-auth-fd", "3", "--max-tries", "3", "--recovery", "1800", "--lockout-recovery", "1800"}
	c := s.cmd([][]byte{[]byte("lockout-Zq93nB")}, args...)
	c.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}}
	out, err := c.CombinedOutput()
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOSPC) {
		t.Skipf("no user namespace here: %v", err)
	}
	if err == nil || !strings.Contains(string(out), "not reading the new lockout authorization") || !strings.Contains(string(out), "CAP_IPC_LOCK") {
		t.Fatalf("root without the lock: %v\n%s", err, out)
	}
	if out := s.must([][]byte{[]byte("lockout-Zq93nB")}, args...); !strings.Contains(out, "this secret can reach swap") {
		t.Fatalf("a user without the lock:\n%s", out)
	}
}
