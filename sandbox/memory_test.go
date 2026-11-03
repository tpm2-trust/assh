package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// statusKiB is a line of /proc/self/status.
func statusKiB(name string) (uint64, error) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	m := regexp.MustCompile(`(?m)^` + name + `:\s+(\d+) kB$`).FindSubmatch(b)
	if m == nil {
		return 0, fmt.Errorf("no %s in /proc/self/status", name)
	}
	return strconv.ParseUint(string(m[1]), 10, 64)
}

// lockChecks is the process of the tests below, started again by them:
//
//   - refused: a low limit, no capability; the lock is refused and nothing is locked.
//   - covers: the whole process is locked, and gives back what it frees.
//   - covers-limited: the same under a low limit, with the capability.
func lockChecks(mode string) int {
	fail := func(format string, args ...any) int {
		os.Stderr.WriteString("FAIL: " + fmt.Sprintf(format, args...) + "\n")
		return 1
	}
	// Threads that exist before the lock, busy elsewhere.
	for range 8 {
		go func() {
			for {
				time.Sleep(time.Millisecond)
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	if mode != "covers" {
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: 1 << 16, Max: 1 << 16}); err != nil {
			return fail("the limit: %v", err)
		}
	}
	err := LockMemory()
	if d, derr := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); derr != nil || d != 0 {
		return fail("dumpable: %d %v, want 0", d, derr)
	}
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		return fail("the limit: %v", err)
	}
	if mode != "covers" && limit.Cur != 1<<16 {
		return fail("the limit is left at %d", limit.Cur)
	}
	locked, serr := statusKiB("VmLck")
	if serr != nil {
		return fail("%v", serr)
	}
	if mode == "refused" {
		if err == nil {
			return fail("the lock was taken under the limit, without the capability")
		}
		if !errors.Is(err, unix.EPERM) || !strings.Contains(err.Error(), "CAP_IPC_LOCK") {
			return fail("the refusal: %v", err)
		}
		if locked != 0 {
			return fail("VmLck %d kB after a refusal", locked)
		}
		// No mapping past the limit fails: the runtime lives on.
		b := make([]byte, 64<<20)
		b[len(b)-1] = 1
		runtime.KeepAlive(b)
		return 0
	}
	if err != nil {
		return fail("LockMemory: %v", err)
	}
	size, serr := statusKiB("VmSize")
	if serr != nil {
		return fail("%v", serr)
	}
	if locked*10 < size*9 {
		return fail("VmLck %d kB of VmSize %d kB", locked, size)
	}
	// The stack of a thread made after the lock, and a heap that grows.
	done := make(chan uint64)
	go func() {
		runtime.LockOSThread()
		b := make([]byte, 256<<20)
		for i := 0; i < len(b); i += 4096 {
			b[i] = 1
		}
		rss, _ := statusKiB("VmRSS")
		runtime.KeepAlive(b)
		done <- rss
	}()
	full := <-done
	if locked, _ = statusKiB("VmLck"); locked < 256<<10 {
		return fail("VmLck %d kB with 256 MiB more", locked)
	}
	if swap, _ := statusKiB("VmSwap"); swap != 0 {
		return fail("VmSwap %d kB", swap)
	}
	// Under the lock the runtime gives its free memory back: Argon2id's, every time.
	debug.FreeOSMemory()
	rss, _ := statusKiB("VmRSS")
	if full < 256<<10 || rss > full-(200<<10) {
		return fail("resident %d kB after freeing, %d kB before", rss, full)
	}
	// The lock does not cross an exec.
	cmd := exec.Command("/bin/sh", "-c", "grep VmLck /proc/self/status")
	out, err := cmd.CombinedOutput()
	if err != nil || !regexp.MustCompile(`VmLck:\s+0 kB`).Match(out) {
		return fail("after an exec: %s %v", out, err)
	}
	return 0
}

// A limit without the capability is refused, in a user namespace of its own: uid 0
// there has no CAP_IPC_LOCK where the kernel asks, as a container's root has not.
func TestLockMemoryRefused(t *testing.T) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "SANDBOX_TEST_LOCK=refused")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}}
	out, err := cmd.CombinedOutput()
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOSPC) {
		t.Skipf("no user namespace here: %v", err)
	}
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
}

// The whole process is locked. It takes CAP_IPC_LOCK or no limit; a user's test
// run has neither, the VM test's commands do, and this test as root on a VM.
func TestLockMemoryCovers(t *testing.T) {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 && limit.Cur != unix.RLIM_INFINITY {
		t.Skipf("a limit of %d bytes and no CAP_IPC_LOCK: as root, on a VM", limit.Cur)
	}
	modes := []string{"covers"}
	if os.Geteuid() == 0 {
		modes = append(modes, "covers-limited")
	}
	for _, mode := range modes {
		cmd := exec.Command(os.Args[0])
		cmd.Env = append(os.Environ(), "SANDBOX_TEST_LOCK="+mode)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: %v: %s", mode, err, out)
		}
	}
}
