package sandbox

import "golang.org/x/sys/unix"

const auditArch = unix.AUDIT_ARCH_X86_64

// syscallBit marks the x32 ABI's system calls, refused as a whole.
const syscallBit = 0x40000000

var deniedArch = []uintptr{unix.SYS_IOPL, unix.SYS_IOPERM, unix.SYS_MKNOD, unix.SYS_USELIB, unix.SYS_MODIFY_LDT}
