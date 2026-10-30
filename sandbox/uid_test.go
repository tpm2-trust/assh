package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

// Two claims at once get different uids; a released one is handed out
// again.
func TestClaimUID(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "uid")
	r := UIDRange{First: 0x7FFE1000, Last: 0x7FFE1001}
	a, err := ClaimUID(r, dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ClaimUID(r, dir)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == b.ID {
		t.Fatalf("both claims got %d", a.ID)
	}
	if _, err := ClaimUID(r, dir); err == nil {
		t.Fatal("a third claim in a range of two")
	}
	a.Release()
	c, err := ClaimUID(r, dir)
	if err != nil || c.ID != a.ID {
		t.Fatalf("after a release: %v %v, want %d", c, err, a.ID)
	}
	b.Release()
	c.Release()
}

// A uid a process runs as is never handed out: this test's own.
func TestClaimUIDSkipsUsed(t *testing.T) {
	me := uint32(os.Getuid())
	if me == 0 {
		t.Skip("uid 0 is outside every range")
	}
	u, err := ClaimUID(UIDRange{First: me, Last: me + 1}, filepath.Join(t.TempDir(), "uid"))
	if err == nil && u.ID == me {
		t.Fatalf("handed out %d, which this process runs as", me)
	}
	u.Release()
}

// A lock directory others can write is refused: they could hold every uid
// or plant a lock.
func TestClaimUIDDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := ClaimUID(DefaultUIDs, dir); err == nil {
		t.Fatal("a world-writable lock directory was taken")
	}
}

func TestParseUIDRange(t *testing.T) {
	if r, err := ParseUIDRange("0x7FFE0000-0x7FFEFFFF"); err != nil || r != DefaultUIDs {
		t.Fatalf("%v %v", r, err)
	}
	for _, s := range []string{"", "5", "0-10", "10-5", "1-2147483648", "a-b"} {
		if _, err := ParseUIDRange(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}
