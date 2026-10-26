package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tpm2-trust/assh/hostkey"
)

// A file sets what it names; the rest keeps its default.
func TestParse(t *testing.T) {
	c, err := Parse([]byte(`# the CA
ASSH_CA=efi:AsshCA
ASSH_CA_SLOT_0=0,2,7,15
ASSH_CA_SLOT_1="7,15"
ASSH_CA_WINDOW=15
ASSH_CA_REF='my ref'
ASSH_CA_BANK=auto
ASSH_LISTEN=:2222
ASSH_PRINCIPALS=host.example, 192.0.2.1
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.CA != "efi:AsshCA" || c.Window != 15 || c.PolicyRef != "my ref" || c.Listen != ":2222" || c.TPM != "/dev/tpmrm0" || c.KeyID != "assh" || c.Bank != hostkey.Auto {
		t.Fatalf("%+v", c)
	}
	if !slices.Equal(c.Slots[0], []int{0, 2, 7, 15}) || !slices.Equal(c.Slots[1], []int{7, 15}) || !slices.Equal(c.SlotNumbers(), []int{0, 1}) {
		t.Fatalf("slots %v", c.Slots)
	}
	if !slices.Equal(c.Principals, []string{"host.example", "192.0.2.1"}) || !c.Set["ASSH_LISTEN"] || c.Set["ASSH_TPM"] {
		t.Fatalf("%v %v", c.Principals, c.Set)
	}
}

// A line it cannot take is an error that names the line.
func TestParseRefuses(t *testing.T) {
	for _, bad := range []string{
		"ASSH_NOPE=1",
		"no equals sign",
		"ASSH_CA_SLOT_16=0,15",
		"ASSH_CA_SLOT_01=0,15",
		"ASSH_CA_SLOT_0=0,99",
		"ASSH_CA_TYPE=ed25519",
		"ASSH_CA_WINDOW=15\nASSH_CA_SLOT_0=0,7",
		"ASSH_CA=a\nASSH_CA=b",
		"ASSH_AUTHORITY=a.pem\nASSH_AUTHORITY_TPM=yes",
		"ASSH_CA_REF=" + strings.Repeat("x", 33),
		"ASSH_CA=",
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
	if _, err := Parse([]byte("\n\nASSH_NOPE=1")); err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("the line number: %v", err)
	}
}

// Write keeps comments and the order of the file, replaces what it sets,
// drops what it no longer sets, adds the rest; read back it is c.
func TestWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assh.conf")
	c := Default()
	c.CA = "efi:AsshCA"
	c.Slots = map[int][]int{0: {0, 2, 7, 15}, 1: {7, 15}}
	c.Window = 15
	c.KeyID = "my host"
	if err := Write(path, c, "assh's settings"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	want := "# assh's settings\n\nASSH_CA=efi:AsshCA\nASSH_CA_SLOT_0=0,2,7,15\nASSH_CA_SLOT_1=7,15\nASSH_CA_WINDOW=15\nASSH_KEY_ID=\"my host\"\n"
	if string(data) != want {
		t.Fatalf("got\n%s\nwant\n%s", data, want)
	}
	os.WriteFile(path, append(data, []byte("# mine\nASSH_LISTEN=:2222\n")...), 0o644)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	delete(c.Slots, 1)
	c.Slots[0] = []int{0, 7, 15}
	if err := Write(path, c, "unused"); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	want = "# assh's settings\n\nASSH_CA=efi:AsshCA\nASSH_CA_SLOT_0=0,7,15\nASSH_CA_WINDOW=15\nASSH_KEY_ID=\"my host\"\n# mine\nASSH_LISTEN=:2222\n"
	if string(data) != want {
		t.Fatalf("got\n%s\nwant\n%s", data, want)
	}
	if got, err := Load(path); err != nil || got.KeyID != "my host" || len(got.Slots) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	c.Slots[1] = []int{7}
	if err := Write(path, c, ""); err == nil {
		t.Fatal("a slot without the window written")
	}
}

// Match makes the CA's slots the file's, keeps the approvals of the slots
// that stay as they were, and refuses what only a new CA can change.
func TestMatch(t *testing.T) {
	ca := &hostkey.CA{Type: hostkey.P256, Bank: hostkey.SHA256, Window: 15, PolicyRef: []byte("assh"),
		Slots:     []hostkey.Slot{{Number: 0, PCRs: []int{0, 2, 7, 15}}, {Number: 1, PCRs: []int{7, 15}}},
		Approvals: []hostkey.Approval{{Slot: 0}, {Slot: 1}},
	}
	c := Default()
	c.Window = 15
	if changed, err := c.Match(ca); err != nil || changed {
		t.Fatalf("no slots in the file: %v %v", changed, err)
	}
	c.Slots = map[int][]int{0: {0, 2, 7, 15}, 1: {7, 15}}
	if changed, err := c.Match(ca); err != nil || changed || len(ca.Approvals) != 2 {
		t.Fatalf("the same: %v %v", changed, err)
	}
	if d := c; true {
		d.CAType = "rsa2048,p256"
		if changed, err := d.Match(ca); err != nil || changed {
			t.Fatalf("a list that names the CA's type: %v %v", changed, err)
		}
	}
	if d := c; true {
		d.Bank = hostkey.Auto
		if changed, err := d.Match(ca); err != nil || changed {
			t.Fatalf("auto, a CA of any bank: %v %v", changed, err)
		}
	}
	c.Slots = map[int][]int{0: {0, 2, 7, 11, 15}, 1: {7, 15}, 2: {0, 7, 15}}
	if changed, err := c.Match(ca); err != nil || !changed {
		t.Fatalf("changed: %v %v", changed, err)
	}
	if len(ca.Slots) != 3 || !slices.Equal(ca.Slot(0).PCRs, []int{0, 2, 7, 11, 15}) || len(ca.Approvals) != 1 || ca.Approvals[0].Slot != 1 {
		t.Fatalf("slots %v approvals %v", ca.Slots, ca.Approvals)
	}
	c.Slots = map[int][]int{3: {7, 15}}
	if _, err := c.Match(ca); err != nil || len(ca.Slots) != 1 || ca.Slot(3) == nil || len(ca.Approvals) != 0 {
		t.Fatalf("moved: %v %v %v", err, ca.Slots, ca.Approvals)
	}
	c.Slots = map[int][]int{0: {7, 15}, 1: {7, 15}}
	if _, err := c.Match(ca); err == nil || ca.Slot(3) == nil {
		t.Fatalf("two slots on the same PCRs: %v, the CA %v", err, ca.Slots)
	}
	for _, f := range []func(*Config){
		func(c *Config) { c.Window = 0; c.Slots = nil },
		func(c *Config) { c.CAType = hostkey.RSA2048 },
		func(c *Config) { c.Bank = hostkey.SHA1 },
		func(c *Config) { c.PolicyRef = "other" },
	} {
		d := c
		f(&d)
		if _, err := d.Match(ca); err == nil || !strings.Contains(err.Error(), "create the CA again") {
			t.Errorf("%v", err)
		}
	}
}
