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
	policy := Policy{ReadBeneath: []string{dir, "/proc"}}
	withSockets := os.Getenv("SANDBOX_TEST_SOCKETS") != ""
	if withSockets {
		policy.Sockets = []int{unix.AF_UNIX}
	}
	parent := os.Getppid()
	res, err := Apply(policy)
	if err != nil {
		return fail("Apply: %v", err)
	}
	desc := res.String()
	os.Stdout.WriteString(desc + "\n")
	if (len(res.Missing()) > 0) != strings.Contains(desc, "WARNING") {
		return fail("what is missing %q is not what the description warns of", res.Missing())
	}
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
	if res.Seccomp {
		// Not on the list: as if the kernel did not have them.
		if err := unix.Unshare(unix.CLONE_NEWUTS); !errors.Is(err, unix.ENOSYS) {
			return fail("unshare: %v, want ENOSYS", err)
		}
		if fd, err := unix.MemfdCreate("x", 0); !errors.Is(err, unix.ENOSYS) {
			return fail("memfd_create: %d %v, want ENOSYS", fd, err)
		}
		if _, _, errno := unix.RawSyscall(unix.SYS_SHMGET, 0, 4096, 0o600|unix.IPC_CREAT); errno != unix.ENOSYS {
			return fail("shmget: %v, want ENOSYS", errno)
		}
		if _, _, errno := unix.RawSyscall(unix.SYS_PIDFD_OPEN, uintptr(parent), 0, 0); errno != unix.ENOSYS {
			return fail("pidfd_open: %v, want ENOSYS", errno)
		}
		// By their argument: a signal to this process alone, a file never
		// to be written, a socket of the policy's families alone.
		if err := unix.Kill(parent, 0); !errors.Is(err, unix.EPERM) {
			return fail("kill(the parent, 0): %v, want EPERM", err)
		}
		if err := unix.Kill(os.Getpid(), 0); err != nil {
			return fail("kill(itself, 0): %v", err)
		}
		if _, err := unix.Open(filepath.Join(dir, "allowed"), unix.O_RDWR, 0); !errors.Is(err, unix.EPERM) {
			return fail("a file opened to be written: %v, want EPERM", err)
		}
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return fail("socketpair(AF_UNIX): %v", err)
		}
		unix.Close(fds[0])
		unix.Close(fds[1])
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if withSockets {
			if err != nil {
				return fail("socket(AF_UNIX) with the policy's family: %v", err)
			}
			unix.Close(fd)
			if _, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0); !errors.Is(err, unix.EPERM) {
				return fail("socket(AF_INET) with AF_UNIX alone in the policy: %v, want EPERM", err)
			}
			if _, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, 0); !errors.Is(err, unix.EPERM) {
				return fail("socket(AF_NETLINK): %v, want EPERM", err)
			}
		} else if !errors.Is(err, unix.ENOSYS) {
			return fail("socket without sockets in the policy: %v, want ENOSYS", err)
		}
	}
	if d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err != nil || d != 0 {
		return fail("dumpable: %d %v, want 0", d, err)
	}
	if res.Seccomp {
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
		if res.Seccomp && !strings.Contains(string(b), "Seccomp:\t2") {
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
	for _, sockets := range []string{"", "1"} {
		cmd := exec.Command(os.Args[0], "-test.run=^$")
		cmd.Env = append(os.Environ(), "SANDBOX_TEST_DIR="+dir, "SANDBOX_TEST_SOCKETS="+sockets)
		out, err := cmd.CombinedOutput()
		t.Logf("%s", out)
		if err != nil {
			t.Fatalf("the confined process (sockets %q): %v", sockets, err)
		}
		if strings.Contains(string(out), "WARNING") {
			t.Errorf("this kernel does not confine in full: the checks behind it did not all run")
		}
	}
}
