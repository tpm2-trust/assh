package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestMain is also the confined process of TestApply: started again with
// SANDBOX_TEST_DIR set, it confines itself and checks from inside.
func TestMain(m *testing.M) {
	if dir := os.Getenv("SANDBOX_TEST_DIR"); dir != "" {
		os.Exit(confinedChecks(dir))
	}
	os.Exit(m.Run())
}

func confinedChecks(dir string) int {
	fail := func(format string, args ...any) int {
		os.Stderr.WriteString("FAIL: " + strings.TrimSpace(fmt.Sprintf(format, args...)) + "\n")
		return 1
	}
	// Threads that exist before Apply, busy elsewhere.
	for i := 0; i < 8; i++ {
		go func() {
			for {
				time.Sleep(time.Millisecond)
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	desc, err := Apply(Policy{ReadBeneath: []string{dir, "/proc"}})
	if err != nil {
		return fail("Apply: %v", err)
	}
	os.Stdout.WriteString(desc + "\n")
	if _, err := os.ReadFile(filepath.Join(dir, "allowed")); err != nil {
		return fail("a file beneath the policy's directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "allowed"), []byte("x"), 0o600); err == nil {
		return fail("a file beneath the policy's directory was written")
	}
	if strings.Contains(desc, "Landlock ABI") {
		if _, err := os.ReadFile("/etc/passwd"); err == nil {
			return fail("/etc/passwd was read")
		}
	}
	if err := unix.Unshare(unix.CLONE_NEWUTS); !errors.Is(err, unix.EPERM) {
		return fail("unshare: %v, want EPERM", err)
	}
	if d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err != nil || d != 0 {
		return fail("dumpable: %d %v, want 0", d, err)
	}
	if strings.Contains(desc, "refused") {
		// A fork into a new user namespace; should it ever succeed, the
		// copy exits at once.
		r, _, errno := unix.RawSyscall6(unix.SYS_CLONE, uintptr(unix.CLONE_NEWUSER|unix.SIGCHLD), 0, 0, 0, 0, 0)
		if errno == 0 && r == 0 {
			unix.RawSyscall(unix.SYS_EXIT_GROUP, 0, 0, 0)
		}
		if errno != unix.EPERM {
			return fail("clone(CLONE_NEWUSER): %v, want EPERM", errno)
		}
		if _, _, errno := unix.RawSyscall(unix.SYS_CLONE3, 0, 0, 0); errno != unix.ENOSYS {
			return fail("clone3: %v, want ENOSYS", errno)
		}
		// New threads still come: clone without a namespace is allowed.
		done := make(chan int)
		for i := 0; i < 4; i++ {
			go func() {
				runtime.LockOSThread()
				done <- unix.Gettid()
			}()
		}
		for i := 0; i < 4; i++ {
			<-done
		}
	}
	tasks, _ := filepath.Glob("/proc/self/task/*/status")
	if len(tasks) < 2 {
		return fail("only %d thread(s): the test checks nothing", len(tasks))
	}
	for _, t := range tasks {
		b, err := os.ReadFile(t)
		if errors.Is(err, os.ErrNotExist) {
			continue // the thread ended since the listing
		}
		if err != nil {
			return fail("%s: %v", t, err)
		}
		if !strings.Contains(string(b), "NoNewPrivs:\t1") {
			return fail("%s: a thread without no_new_privs", t)
		}
		if strings.Contains(desc, "refused") && !strings.Contains(string(b), "Seccomp:\t2") {
			return fail("%s: a thread without the filter", t)
		}
	}
	return 0
}

// TestApply confines a process with threads and checks every thread of it.
func TestApply(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "allowed"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "SANDBOX_TEST_DIR="+dir)
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("the confined process: %v", err)
	}
}
