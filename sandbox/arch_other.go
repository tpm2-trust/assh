//go:build !amd64 && !arm64

package sandbox

// No filter is built for this architecture: Apply says so.
const auditArch = 0

const syscallBit = 0

var deniedArch []uintptr
