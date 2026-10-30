package sandbox

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// UIDRange is where a confined process's uid is chosen from: one nobody
// else uses, so that no other process shares it - none may signal it, and
// none would be the one it could reach.
type UIDRange struct{ First, Last uint32 }

// DefaultUIDs lie above every range systemd hands out (DynamicUser
// 61184-65519, containers 524288-1879048191) and below 2^31, so that
// nothing takes them for negative.
var DefaultUIDs = UIDRange{First: 0x7FFE0000, Last: 0x7FFEFFFF}

// DefaultLockDir is where ClaimUID keeps a lock file for each uid it
// hands out.
const DefaultLockDir = "/run/assh/uid"

// ParseUIDRange reads FIRST-LAST.
func ParseUIDRange(s string) (UIDRange, error) {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return UIDRange{}, errors.New("a uid range is FIRST-LAST")
	}
	first, err1 := strconv.ParseUint(strings.TrimSpace(a), 0, 32)
	last, err2 := strconv.ParseUint(strings.TrimSpace(b), 0, 32)
	if err1 != nil || err2 != nil || first == 0 || first > last || last >= 1<<31 {
		return UIDRange{}, fmt.Errorf("%q: a uid range is FIRST-LAST, above 0 and below 2^31", s)
	}
	return UIDRange{First: uint32(first), Last: uint32(last)}, nil
}

func (r UIDRange) String() string { return fmt.Sprintf("%d-%d", r.First, r.Last) }

// UID is a uid claimed for a confined process; its gid is the same number.
type UID struct {
	ID   uint32
	lock *os.File
}

// Release gives the uid back, once the process that ran as it is gone.
func (u *UID) Release() {
	if u != nil && u.lock != nil {
		u.lock.Close()
		u.lock = nil
	}
}

// ClaimUID chooses the first uid of r that no user or group database
// names, that no process runs as, and that no other ClaimUID holds: its
// lock file in dir (DefaultLockDir for "") stays locked until Release.
// dir must be root's and writable by root alone.
func ClaimUID(r UIDRange, dir string) (*UID, error) {
	if dir == "" {
		dir = DefaultLockDir
	}
	if r.First == 0 || r.First > r.Last {
		return nil, fmt.Errorf("an empty uid range %s", r)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := ownDir(dir); err != nil {
		return nil, err
	}
	used, err := processIDs()
	if err != nil {
		return nil, err
	}
	for id := uint64(r.First); id <= uint64(r.Last); id++ {
		if used[uint32(id)] || named(uint32(id)) {
			continue
		}
		f, err := os.OpenFile(filepath.Join(dir, strconv.FormatUint(id, 10)),
			os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
		if err != nil {
			return nil, err
		}
		if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			f.Close()
			if errors.Is(err, unix.EWOULDBLOCK) {
				continue
			}
			return nil, err
		}
		// A process may have come since the scan.
		if now, err := processIDs(); err != nil || now[uint32(id)] {
			f.Close()
			if err != nil {
				return nil, err
			}
			continue
		}
		return &UID{ID: uint32(id), lock: f}, nil
	}
	return nil, fmt.Errorf("no free uid in %s", r)
}

// ownDir refuses a lock directory someone else could plant a lock in.
func ownDir(dir string) error {
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || int(st.Uid) != os.Geteuid() || st.Mode&0o022 != 0 {
		return fmt.Errorf("%s is not a directory that only this user can write", dir)
	}
	return nil
}

// named: a user or group database names the id. A system without a
// database (an initrd) names none; a database that cannot be read names
// every id, to be safe.
func named(id uint32) bool {
	s := strconv.FormatUint(uint64(id), 10)
	_, uerr := user.LookupId(s)
	_, gerr := user.LookupGroupId(s)
	free := func(err error) bool {
		var u user.UnknownUserIdError
		var g user.UnknownGroupIdError
		return errors.As(err, &u) || errors.As(err, &g) || errors.Is(err, fs.ErrNotExist)
	}
	return !free(uerr) || !free(gerr)
}

// processIDs are every uid and gid a process runs with now: real,
// effective, saved and file system.
func processIDs() (map[uint32]bool, error) {
	ids := map[uint32]bool{}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		f, err := os.Open(filepath.Join("/proc", e.Name(), "status"))
		if err != nil {
			continue // gone
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			l := sc.Text()
			if !strings.HasPrefix(l, "Uid:") && !strings.HasPrefix(l, "Gid:") {
				continue
			}
			for _, v := range strings.Fields(l)[1:] {
				if n, err := strconv.ParseUint(v, 10, 32); err == nil {
					ids[uint32(n)] = true
				}
			}
		}
		f.Close()
	}
	return ids, nil
}
