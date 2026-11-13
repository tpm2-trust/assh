package sandbox

import "golang.org/x/sys/unix"

const auditArch = unix.AUDIT_ARCH_X86_64

// syscallBit marks the x32 ABI's system calls, refused as a whole.
const syscallBit = 0x40000000

// What amd64 has beside the common calls: the ones the newer replaced, which
// the Go runtime and the standard library still make there.
var allowedArch = []uintptr{
	unix.SYS_ARCH_PRCTL, unix.SYS_EPOLL_WAIT, unix.SYS_ACCEPT, unix.SYS_GETTIMEOFDAY, unix.SYS_TIME,
	unix.SYS_POLL, unix.SYS_DUP2, unix.SYS_PIPE,
}

var filesArch = []uintptr{unix.SYS_NEWFSTATAT}
