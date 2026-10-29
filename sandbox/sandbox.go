// Package sandbox confines the process that calls it - every thread of it -
// for the rest of its life: no new privileges, no memory that becomes
// executable, no file but what the policy names (Landlock), and none of
// the system calls that administer the machine (seccomp). Nothing of it
// can be undone, and threads made later inherit it.
//
// Go runs a program on several threads from its start, and prctl, Landlock
// and seccomp act on the thread that asks: each step is taken on every
// thread (syscall.AllThreadsSyscall, seccomp's TSYNC). A program built with
// cgo cannot do that and gets an error.
//
// It is the second line: a process that parses what arrives from outside
// is started without root, in namespaces of its own, by its parent; this is
// what it then takes from itself.
package sandbox

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Policy is what a confined process keeps.
type Policy struct {
	// ReadBeneath are directories the process may read files and list
	// beneath; nothing else of the file system is reachable. Empty: no file
	// at all.
	ReadBeneath []string
}

// Apply confines this process to the policy. It describes what it did, for
// the log; an error means a step that this kernel has did not take, and the
// process should not go on. A kernel without Landlock, seccomp or the
// memory protection is said in the description, not an error: what is
// there still holds.
func Apply(p Policy) (string, error) {
	var desc []string
	if err := allThreads(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); err != nil {
		return "", fmt.Errorf("no new privileges: %w", err)
	}
	desc = append(desc, "no new privileges")

	// Process-wide: no mapping turns executable, none is both.
	if err := unix.Prctl(unix.PR_SET_MDWE, unix.PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0); err != nil {
		desc = append(desc, "no memory protection ("+err.Error()+")")
	} else {
		desc = append(desc, "no executable memory")
	}

	abi, err := landlock(p.ReadBeneath)
	switch {
	case errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP):
		desc = append(desc, "no Landlock ("+err.Error()+")")
	case err != nil:
		return "", fmt.Errorf("Landlock: %w", err)
	case len(p.ReadBeneath) == 0:
		desc = append(desc, fmt.Sprintf("Landlock ABI %d: no file access", abi))
	default:
		desc = append(desc, fmt.Sprintf("Landlock ABI %d: reads %s alone", abi, strings.Join(p.ReadBeneath, ", ")))
	}

	n, err := seccomp()
	switch {
	case errors.Is(err, errNoFilter):
		desc = append(desc, "no system call filter ("+err.Error()+")")
	case err != nil:
		return "", fmt.Errorf("seccomp: %w", err)
	default:
		desc = append(desc, fmt.Sprintf("%d system calls refused", n))
	}
	return strings.Join(desc, ", "), nil
}

// allThreads makes the system call on every thread of the process.
func allThreads(trap, a1, a2, a3 uintptr) error {
	if _, _, errno := syscall.AllThreadsSyscall(trap, a1, a2, a3); errno != 0 {
		return errno
	}
	return nil
}

// landlock restricts the process to reading beneath the paths, and to
// nothing else of the file system - no TCP bind or connect, no signal or
// abstract socket beyond its own domain, where the kernel knows those. It
// reports the kernel's Landlock ABI.
func landlock(readBeneath []string) (int, error) {
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0, errno
	}
	abi := int(v)
	var attr unix.LandlockRulesetAttr
	size := uintptr(8) // access_fs alone, ABI 1-3
	attr.Access_fs = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM
	if abi >= 2 {
		attr.Access_fs |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		attr.Access_fs |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 4 {
		attr.Access_net = unix.LANDLOCK_ACCESS_NET_BIND_TCP | unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
		size = 16
	}
	if abi >= 5 {
		attr.Access_fs |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	if abi >= 6 {
		attr.Scoped = unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | unix.LANDLOCK_SCOPE_SIGNAL
		size = 24
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), size, 0)
	if errno != 0 {
		return abi, errno
	}
	defer unix.Close(int(fd))
	for _, path := range readBeneath {
		dir, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
		if err != nil {
			return abi, fmt.Errorf("%s: %w", path, err)
		}
		rule := unix.LandlockPathBeneathAttr{
			Allowed_access: unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR,
			Parent_fd:      int32(dir),
		}
		_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, unix.LANDLOCK_RULE_PATH_BENEATH,
			uintptr(unsafe.Pointer(&rule)), 0, 0, 0)
		unix.Close(dir)
		if errno != 0 {
			return abi, fmt.Errorf("%s: %w", path, errno)
		}
	}
	if err := allThreads(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); err != nil {
		return abi, err
	}
	return abi, nil
}

// errNoFilter: no filter for this architecture.
var errNoFilter = errors.New("not built for this architecture")

// seccomp refuses the system calls that administer the machine - mounts,
// modules, the clock, other processes' memory, namespaces, user IDs,
// keyrings, BPF, running a program - with EPERM, so that an unexpected one
// fails the call and not the process; a system call of another
// architecture's ABI ends the process. It reports how many are refused.
// TSYNC puts the filter on every thread.
func seccomp() (int, error) {
	if auditArch == 0 {
		return 0, errNoFilter
	}
	denied := append(append([]uintptr{}, deniedCommon...), deniedArch...)
	const (
		ldAbsW = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeqK   = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		jgeK   = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
		retK   = unix.BPF_RET | unix.BPF_K
		// struct seccomp_data: int nr; __u32 arch; ...
		offNr   = 0
		offArch = 4
	)
	prog := []unix.SockFilter{
		{Code: ldAbsW, K: offArch},
		{Code: jeqK, Jt: 1, Jf: 0, K: auditArch},
		{Code: retK, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: ldAbsW, K: offNr},
	}
	// The last two instructions: allow, refuse. Each check jumps to the
	// refusal on a match.
	checks := len(denied)
	if syscallBit != 0 {
		checks++
	}
	refuse := len(prog) + checks + 1
	jumpTo := func(target int) uint8 { return uint8(target - len(prog) - 1) }
	if syscallBit != 0 {
		prog = append(prog, unix.SockFilter{Code: jgeK, Jt: jumpTo(refuse), Jf: 0, K: syscallBit})
	}
	for _, nr := range denied {
		prog = append(prog, unix.SockFilter{Code: jeqK, Jt: jumpTo(refuse), Jf: 0, K: uint32(nr)})
	}
	prog = append(prog,
		unix.SockFilter{Code: retK, K: unix.SECCOMP_RET_ALLOW},
		unix.SockFilter{Code: retK, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
	)
	if checks > 255 {
		return 0, fmt.Errorf("the filter is too long for its jumps")
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC,
		uintptr(unsafe.Pointer(&fprog))); errno != 0 {
		if errno == unix.ENOSYS || errno == unix.EINVAL {
			return 0, fmt.Errorf("%w: %v", errNoFilter, errno)
		}
		return 0, errno
	}
	return len(denied), nil
}

// deniedCommon are the refused system calls every architecture has.
var deniedCommon = []uintptr{
	// file systems and mounts
	unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT,
	unix.SYS_OPEN_TREE, unix.SYS_MOVE_MOUNT, unix.SYS_FSOPEN, unix.SYS_FSCONFIG,
	unix.SYS_FSMOUNT, unix.SYS_FSPICK, unix.SYS_MOUNT_SETATTR, unix.SYS_SWAPON,
	unix.SYS_SWAPOFF, unix.SYS_QUOTACTL, unix.SYS_ACCT, unix.SYS_MKNODAT,
	unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_NAME_TO_HANDLE_AT, unix.SYS_FANOTIFY_INIT,
	// the machine
	unix.SYS_REBOOT, unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD,
	unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
	unix.SYS_SETTIMEOFDAY, unix.SYS_CLOCK_SETTIME, unix.SYS_CLOCK_ADJTIME, unix.SYS_ADJTIMEX,
	unix.SYS_SETHOSTNAME, unix.SYS_SETDOMAINNAME, unix.SYS_SYSLOG, unix.SYS_VHANGUP,
	// other processes, and the kernel's insides
	unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
	unix.SYS_KCMP, unix.SYS_PIDFD_GETFD, unix.SYS_PERF_EVENT_OPEN, unix.SYS_BPF,
	unix.SYS_USERFAULTFD, unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER,
	unix.SYS_IO_URING_REGISTER, unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY,
	unix.SYS_PERSONALITY, unix.SYS_SCHED_SETSCHEDULER, unix.SYS_SCHED_SETATTR,
	// namespaces and user IDs
	unix.SYS_UNSHARE, unix.SYS_SETNS, unix.SYS_SETUID, unix.SYS_SETGID,
	unix.SYS_SETREUID, unix.SYS_SETREGID, unix.SYS_SETRESUID, unix.SYS_SETRESGID,
	unix.SYS_SETGROUPS, unix.SYS_SETFSUID, unix.SYS_SETFSGID,
	// running a program
	unix.SYS_EXECVE, unix.SYS_EXECVEAT,
}
