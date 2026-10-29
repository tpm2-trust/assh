package sandbox

import "golang.org/x/sys/unix"

const auditArch = unix.AUDIT_ARCH_AARCH64

const syscallBit = 0

var deniedArch []uintptr
