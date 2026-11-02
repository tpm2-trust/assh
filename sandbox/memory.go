package sandbox

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// lockFlags lock every page of the process, now and to come, when it is first
// touched. MCL_ONFAULT is what keeps a Go process's memory its own to give back:
//
//   - The runtime reserves more than a gigabyte it never touches, and maps its
//     heap ahead of its use. Without MCL_ONFAULT all that is mapped readable is
//     made resident at once (about 40 MiB more at the start of every command).
//   - The kernel refuses MADV_DONTNEED on locked memory, so the runtime gives it
//     back by mapping over it. Without MCL_ONFAULT, MCL_FUTURE makes that new
//     mapping resident too: debug.FreeOSMemory would then change nothing.
//
// What is locked is the same: a page cannot be evicted from its first touch to its
// end. Only a page already in swap when the lock is taken stays there until
// touched, which is why the lock comes before any secret.
const lockFlags = unix.MCL_CURRENT | unix.MCL_FUTURE | unix.MCL_ONFAULT

// LockMemory keeps what this process holds out of swap and core files: it is
// not dumpable, and its memory is locked. Call it first thing, before any secret
// is in memory. An error means the memory is not locked and nothing of it is;
// the process is not dumpable all the same, unless that is the error.
//
// Both take the whole process in one call, not a thread at a time as Apply's
// no_new_privs must: mlockall and PR_SET_DUMPABLE are the address space's, shared
// by all its threads, and RLIMIT_MEMLOCK the thread group's. The lock does not
// cross an exec, and a process started after it has one only if it asks.
//
// Without CAP_IPC_LOCK any limit on locked memory is refused, however large: under
// MCL_FUTURE a mapping past the limit fails, and for the Go runtime that is fatal,
// at no place the program could answer. So the kernel is asked first: with the soft
// limit at 0, mlockall succeeds only with the capability, in the first user namespace
// (a namespace's own capability does not count, nor does capget say which it is).
func LockMemory() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("not dumpable: %w", err)
	}
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		return fmt.Errorf("the limit on locked memory: %w", err)
	}
	if limit.Cur == unix.RLIM_INFINITY {
		if err := unix.Mlockall(lockFlags); err != nil {
			return fmt.Errorf("the memory is not locked: %w", err)
		}
		return nil
	}
	zero := unix.Rlimit{Cur: 0, Max: limit.Max}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &zero); err != nil {
		return fmt.Errorf("the limit on locked memory: %w", err)
	}
	err := unix.Mlockall(lockFlags)
	if serr := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &limit); serr != nil && err == nil {
		err = serr
	}
	if err != nil {
		return fmt.Errorf("the memory is not locked: locked memory is limited to %d bytes (RLIMIT_MEMLOCK) and this process has no CAP_IPC_LOCK: %w", limit.Cur, err)
	}
	return nil
}
