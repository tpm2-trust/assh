//go:build amd64 || arm64

package sandbox

import "golang.org/x/sys/unix"

// allowedCommon is what every confined process keeps, on every architecture:
// the Go runtime's own calls and those on what the process holds open
// already.
var allowedCommon = []uintptr{
	// what is open: descriptors, pipes, sockets handed in or accepted
	unix.SYS_READ, unix.SYS_WRITE, unix.SYS_READV, unix.SYS_WRITEV, unix.SYS_PREAD64, unix.SYS_PWRITE64,
	unix.SYS_CLOSE, unix.SYS_CLOSE_RANGE, unix.SYS_FSTAT, unix.SYS_LSEEK, unix.SYS_FCNTL,
	unix.SYS_DUP, unix.SYS_DUP3, unix.SYS_PIPE2, unix.SYS_EVENTFD2, unix.SYS_SPLICE,
	unix.SYS_ACCEPT4, unix.SYS_RECVFROM, unix.SYS_SENDTO, unix.SYS_RECVMSG, unix.SYS_SENDMSG,
	unix.SYS_SHUTDOWN, unix.SYS_GETSOCKNAME, unix.SYS_GETPEERNAME, unix.SYS_GETSOCKOPT, unix.SYS_SETSOCKOPT,
	unix.SYS_EPOLL_CREATE1, unix.SYS_EPOLL_CTL, unix.SYS_EPOLL_PWAIT, unix.SYS_EPOLL_PWAIT2, unix.SYS_PPOLL,
	// memory
	unix.SYS_MMAP, unix.SYS_MUNMAP, unix.SYS_MPROTECT, unix.SYS_MADVISE, unix.SYS_MREMAP, unix.SYS_BRK,
	unix.SYS_MLOCK, unix.SYS_MUNLOCK,
	// threads, time, signals
	unix.SYS_FUTEX, unix.SYS_SCHED_YIELD, unix.SYS_SCHED_GETAFFINITY, unix.SYS_NANOSLEEP,
	unix.SYS_CLOCK_NANOSLEEP, unix.SYS_CLOCK_GETTIME, unix.SYS_CLOCK_GETRES,
	unix.SYS_RT_SIGACTION, unix.SYS_RT_SIGPROCMASK, unix.SYS_RT_SIGRETURN, unix.SYS_SIGALTSTACK,
	unix.SYS_SET_ROBUST_LIST, unix.SYS_SET_TID_ADDRESS, unix.SYS_RSEQ, unix.SYS_RESTART_SYSCALL,
	unix.SYS_EXIT, unix.SYS_EXIT_GROUP,
	// what the process is
	unix.SYS_GETPID, unix.SYS_GETTID, unix.SYS_GETUID, unix.SYS_GETEUID, unix.SYS_GETGID, unix.SYS_GETEGID,
	unix.SYS_GETRANDOM, unix.SYS_UNAME, unix.SYS_PRCTL, unix.SYS_PRLIMIT64, unix.SYS_GETRLIMIT,
}

// filesCommon come with a policy that reads files (ReadBeneath): Landlock
// says which, the filter that none is opened to be written.
var filesCommon = []uintptr{
	unix.SYS_STATX, unix.SYS_GETDENTS64, unix.SYS_READLINKAT, unix.SYS_FACCESSAT, unix.SYS_FACCESSAT2,
	unix.SYS_GETCWD,
}

// socketsCommon come with a policy that makes sockets (Sockets), of its
// address families alone.
var socketsCommon = []uintptr{
	unix.SYS_BIND, unix.SYS_CONNECT, unix.SYS_LISTEN, unix.SYS_IOCTL,
}
