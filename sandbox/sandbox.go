// Package sandbox confines the process that calls it - every thread of it -
// for the rest of its life: no new privileges, not dumpable (no other
// process of its uid may trace it or read its memory), no memory that
// becomes executable, no file but what the policy names (Landlock), and no
// system call but those on an allowlist (seccomp). Nothing of it can be
// undone, and threads made later inherit it.
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
	// at all, and no system call that opens one.
	ReadBeneath []string
	// Sockets are the address families the process may make sockets of
	// (unix.AF_BLUETOOTH, say), and bind, connect and ioctl with them.
	// Empty: it makes none, and works on those it was handed.
	Sockets []int
}

// Result is what Apply took from the process.
type Result struct {
	// NoExecMemory: no mapping turns executable (PR_SET_MDWE).
	NoExecMemory bool
	// LandlockABI is the kernel's Landlock version; 0: no Landlock, the
	// file system is as open as the process's uid has it.
	LandlockABI int
	// Seccomp: the system call allowlist is on every thread; Allowed is
	// how many calls it leaves.
	Seccomp bool
	Allowed int

	policy  Policy
	missing []string
}

// Missing says what this kernel did not take, each with its reason; empty
// when the process is confined in full. The process still runs: what is
// there holds, and the caller warns with these.
func (r Result) Missing() []string { return r.missing }

// String describes the result for the log.
func (r Result) String() string {
	desc := []string{"no new privileges", "not dumpable"}
	if r.NoExecMemory {
		desc = append(desc, "no executable memory")
	}
	switch {
	case r.LandlockABI == 0:
	case len(r.policy.ReadBeneath) == 0:
		desc = append(desc, fmt.Sprintf("Landlock ABI %d: no file access", r.LandlockABI))
	default:
		desc = append(desc, fmt.Sprintf("Landlock ABI %d: reads %s alone", r.LandlockABI, strings.Join(r.policy.ReadBeneath, ", ")))
	}
	if r.Seccomp {
		desc = append(desc, fmt.Sprintf("%d system calls allowed", r.Allowed))
	}
	s := strings.Join(desc, ", ")
	if len(r.missing) > 0 {
		s += "; WARNING, not confined in full: " + strings.Join(r.missing, "; ")
	}
	return s
}

// Apply confines this process to the policy and says what it took. An error
// means a step failed for a reason of the process's own, and it should not
// go on. A kernel without Landlock, seccomp or the memory protection, or
// one that refuses the filter, is no error: what is there holds, the result
// names what is missing (Missing), and the caller warns.
func Apply(p Policy) (Result, error) {
	r := Result{policy: p}
	if err := allThreads(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); err != nil {
		return r, fmt.Errorf("no new privileges: %w", err)
	}

	// Process-wide: no ptrace, no /proc/<pid>/mem for others of its uid.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return r, fmt.Errorf("not dumpable: %w", err)
	}

	// Process-wide: no mapping turns executable, none is both.
	if err := unix.Prctl(unix.PR_SET_MDWE, unix.PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0); err != nil {
		r.missing = append(r.missing, "memory may become executable ("+err.Error()+")")
	} else {
		r.NoExecMemory = true
	}

	abi, err := landlock(p.ReadBeneath)
	switch {
	case errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP):
		r.missing = append(r.missing, "no Landlock, files are as open as the uid has them ("+err.Error()+")")
	case err != nil:
		return r, fmt.Errorf("Landlock: %w", err)
	default:
		r.LandlockABI = abi
	}

	n, err := seccomp(p)
	switch {
	case errors.Is(err, errNoFilter), errors.Is(err, errFilterRefused):
		r.missing = append(r.missing, "no system call filter ("+err.Error()+")")
	case err != nil:
		return r, fmt.Errorf("seccomp: %w", err)
	default:
		r.Seccomp, r.Allowed = true, n
	}
	return r, nil
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
	attr.Handled_access_fs = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM
	if abi >= 2 {
		attr.Handled_access_fs |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		attr.Handled_access_fs |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 4 {
		attr.Handled_access_net = unix.LANDLOCK_ACCESS_NET_BIND_TCP | unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
		size = 16
	}
	if abi >= 5 {
		attr.Handled_access_fs |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
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

// errNoFilter: no filter for this architecture, or a kernel without seccomp.
var errNoFilter = errors.New("not built for this architecture")

// errFilterRefused: the kernel has seccomp and did not take the filter.
var errFilterRefused = errors.New("the kernel refused the filter")

// seccomp leaves the process the system calls on its allowlist - what a Go
// program needs to run its threads and to read and write what it holds
// open, with the policy's files and sockets on top - and answers every
// other with ENOSYS, as a kernel without it would: an unexpected one fails
// the call and not the process, and nothing new in a kernel is reachable
// before someone lists it. A system call of another architecture's ABI ends
// the process. Some are allowed by their first argument alone:
//
//   - clone without a namespace (EPERM with one); clone3, whose flags the
//     filter cannot read, is ENOSYS: Go then makes its threads with clone
//   - kill and tgkill to this process alone (the Go runtime signals its
//     own threads)
//   - socket for the policy's address families, socketpair for AF_UNIX
//   - openat without write access or creation
//
// It reports how many calls are allowed. TSYNC puts the filter on every
// thread.
func seccomp(p Policy) (int, error) {
	if auditArch == 0 {
		return 0, errNoFilter
	}
	allowed := append(append([]uintptr{}, allowedCommon...), allowedArch...)
	if len(p.ReadBeneath) > 0 {
		allowed = append(append(allowed, filesCommon...), filesArch...)
	}
	if len(p.Sockets) > 0 {
		allowed = append(allowed, socketsCommon...)
	}
	const (
		ldAbsW = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeqK   = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		jgeK   = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
		jsetK  = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
		retK   = unix.BPF_RET | unix.BPF_K
		// struct seccomp_data: int nr; __u32 arch; __u64 ip; __u64 args[6].
		// An argument's low word: both architectures are little-endian.
		offNr    = 0
		offArch  = 4
		offArg0  = 16
		offArg2  = 32
		newSpace = unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC |
			unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET
		writes = unix.O_WRONLY | unix.O_RDWR | unix.O_CREAT | unix.O_TRUNC | unix.O_APPEND
	)
	var b filter
	b.op(unix.SockFilter{Code: ldAbsW, K: offArch})
	b.jump(jeqK, auditArch, "nr", "kill")
	b.label("nr")
	b.op(unix.SockFilter{Code: ldAbsW, K: offNr})
	if syscallBit != 0 {
		b.jump(jgeK, syscallBit, "nosys", "")
	}
	b.jump(jeqK, unix.SYS_CLONE, "clone", "")
	b.jump(jeqK, unix.SYS_KILL, "self", "")
	b.jump(jeqK, unix.SYS_TGKILL, "self", "")
	b.jump(jeqK, unix.SYS_SOCKETPAIR, "unix", "")
	if len(p.Sockets) > 0 {
		b.jump(jeqK, unix.SYS_SOCKET, "socket", "")
	}
	if len(p.ReadBeneath) > 0 {
		b.jump(jeqK, unix.SYS_OPENAT, "open", "")
	}
	for _, nr := range allowed {
		b.jump(jeqK, uint32(nr), "allow", "")
	}
	b.label("nosys")
	b.op(unix.SockFilter{Code: retK, K: unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)})
	b.label("allow")
	b.op(unix.SockFilter{Code: retK, K: unix.SECCOMP_RET_ALLOW})
	b.label("clone")
	b.op(unix.SockFilter{Code: ldAbsW, K: offArg0})
	b.jump(jsetK, newSpace, "refuse", "allow2")
	b.label("self")
	b.op(unix.SockFilter{Code: ldAbsW, K: offArg0})
	b.jump(jeqK, uint32(unix.Getpid()), "allow2", "refuse")
	b.label("unix")
	b.op(unix.SockFilter{Code: ldAbsW, K: offArg0})
	b.jump(jeqK, unix.AF_UNIX, "allow2", "refuse")
	b.label("open")
	b.op(unix.SockFilter{Code: ldAbsW, K: offArg2})
	b.jump(jsetK, writes, "refuse", "allow2")
	b.label("socket")
	b.op(unix.SockFilter{Code: ldAbsW, K: offArg0})
	for _, family := range p.Sockets {
		b.jump(jeqK, uint32(family), "allow2", "")
	}
	b.label("refuse")
	b.op(unix.SockFilter{Code: retK, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)})
	b.label("allow2")
	b.op(unix.SockFilter{Code: retK, K: unix.SECCOMP_RET_ALLOW})
	b.label("kill")
	b.op(unix.SockFilter{Code: retK, K: unix.SECCOMP_RET_KILL_PROCESS})
	prog, err := b.assemble()
	if err != nil {
		return 0, err
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC,
		uintptr(unsafe.Pointer(&fprog))); errno != 0 {
		switch errno {
		case unix.ENOSYS:
			return 0, fmt.Errorf("%w: %v", errNoFilter, errno)
		case unix.EINVAL:
			return 0, fmt.Errorf("%w: %v", errFilterRefused, errno)
		}
		return 0, errno
	}
	return len(allowed) + 4 + min(len(p.Sockets), 1) + min(len(p.ReadBeneath), 1), nil
}

// filter is a BPF program whose jumps name labels; "" goes on with the
// next instruction.
type filter struct {
	prog   []unix.SockFilter
	jumps  map[int][2]string
	labels map[string]int
}

func (f *filter) op(i unix.SockFilter) { f.prog = append(f.prog, i) }

func (f *filter) label(name string) {
	if f.labels == nil {
		f.labels = map[string]int{}
	}
	f.labels[name] = len(f.prog)
}

func (f *filter) jump(code uint16, k uint32, ifTrue, ifFalse string) {
	if f.jumps == nil {
		f.jumps = map[int][2]string{}
	}
	f.jumps[len(f.prog)] = [2]string{ifTrue, ifFalse}
	f.op(unix.SockFilter{Code: code, K: k})
}

// assemble resolves the labels: BPF jumps forward only, at most 255
// instructions.
func (f *filter) assemble() ([]unix.SockFilter, error) {
	off := func(at int, name string) (uint8, error) {
		if name == "" {
			return 0, nil
		}
		to, ok := f.labels[name]
		if !ok {
			return 0, fmt.Errorf("the filter has no label %q", name)
		}
		d := to - at - 1
		if d < 0 || d > 255 {
			return 0, fmt.Errorf("the filter's jump to %q is out of reach", name)
		}
		return uint8(d), nil
	}
	for at, j := range f.jumps {
		var err error
		if f.prog[at].Jt, err = off(at, j[0]); err != nil {
			return nil, err
		}
		if f.prog[at].Jf, err = off(at, j[1]); err != nil {
			return nil, err
		}
	}
	return f.prog, nil
}
