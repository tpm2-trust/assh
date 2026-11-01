package hostkey

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/tpm2-trust/assh/internal/swtpmtest"
)

// The CA is closed in the boot that makes it, and by Close: once PCR 15
// moved, the CA signs nothing in an approved state - for a slot that does
// not read PCR 15, and for one approved for PCR 15 as it is after the
// close - until the next boot. The TPM refuses it, past the software's
// check.
func TestClose(t *testing.T) {
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	auth := authority(t)
	// Slot 0 reads PCR 7 alone: nothing of the approval knows PCR 15.
	ca, err := CreateCA(tpm, auth.Public(), CAOptions{Type: P256, Bank: SHA256, PCRs: []int{7}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ca.OpenValue, make([]byte, 32)) {
		t.Fatalf("open value %x, want zero", ca.OpenValue)
	}
	now, _ := ca.ReadPCRs(tpm)
	if err := ca.Approve(auth, 0, now); err != nil {
		t.Fatal(err)
	}
	opts := IssueOptions{Principals: []string{"host.example"}, Open: sw.Opener()}
	// Approved in the boot of its creation, it signs nothing in that boot.
	if open, err := ca.IsOpen(tpm); err != nil || open {
		t.Fatalf("a new CA: open %v, %v", open, err)
	}
	if hk, err := Issue(tpm, ca, opts); err != nil || !errors.Is(hk.Temporary, ErrClosed) {
		t.Fatalf("in the boot of its creation: %v %v", hk, err)
	}
	sw.Reboot(t)
	certified(t, tpm, ca, opts, 0)
	if err := Close(tpm); err != nil {
		t.Fatal(err)
	}
	// systemd-pcrextend's measurement of the word: SHA-256 of it, extended.
	ev := sha256.Sum256([]byte(CloseEvent))
	want := sha256.Sum256(append(make([]byte, 32), ev[:]...))
	if got, _ := ReadPCRs(tpm, SHA256, []int{ClosePCR}); !bytes.Equal(got[ClosePCR], want[:]) {
		t.Fatalf("PCR 15 after Close: %x, want %x", got[ClosePCR], want)
	}
	if open, err := ca.IsOpen(tpm); err != nil || open {
		t.Fatalf("open after Close: %v %v", open, err)
	}
	if hk, err := Issue(tpm, ca, opts); err != nil || !errors.Is(hk.Temporary, ErrClosed) {
		t.Fatalf("after Close: %v %v", hk, err)
	}
	// Past the software's check: the TPM refuses.
	caPub, _ := ca.PublicKey()
	if _, err := (&caSigner{t: tpm, ca: ca, approval: &ca.Approvals[0], pub: caPub}).Sign(rand.Reader, make([]byte, 32), crypto.SHA256); !errors.Is(err, ErrClosed) {
		t.Fatalf("the TPM after Close: %v", err)
	}
	swtpmtest.NoneLeft(t, tpm, "refused signature")

	// A slot that reads PCR 15, approved for what it holds after the close
	// (an edited file, an authority that signs what it is given): the CA's
	// own policy still wants the open value.
	if err := ca.AddSlot(1, []int{7, ClosePCR}); err != nil {
		t.Fatal(err)
	}
	after, _ := ca.ReadPCRs(tpm)
	if err := ca.Approve(auth, 1, after); err != nil {
		t.Fatal(err)
	}
	if a := ca.Approved(after, nil); a == nil {
		t.Fatal("no approval for the closed state")
	}
	for i := range ca.Approvals {
		if _, err := (&caSigner{t: tpm, ca: ca, approval: &ca.Approvals[i], pub: caPub}).Sign(rand.Reader, make([]byte, 32), crypto.SHA256); !errors.Is(err, ErrClosed) {
			t.Fatalf("approval %d after Close: %v", i, err)
		}
	}
	swtpmtest.NoneLeft(t, tpm, "refused signatures")
	if err := Close(tpm); err != nil {
		t.Fatalf("closed twice: %v", err)
	}

	// The next boot opens it again.
	sw.Reboot(t)
	certified(t, tpm, ca, opts, 0)
}

// A close that does not happen is an error, never a silent open CA: a TPM
// that does not answer.
func TestCloseFails(t *testing.T) {
	if err := Close(failingTPM{}); err == nil {
		t.Fatal("Close on a TPM that fails succeeded")
	}
	// A PCR the TPM refuses to extend from here (PCR 15 is resettable on
	// no PC Client TPM; a policy or an auth value could guard it).
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	if err := Close(refusing{tpm}); err == nil || !strings.Contains(err.Error(), "PCR 15") {
		t.Fatalf("a refused extend: %v", err)
	}
}

// failingTPM answers no command.
type failingTPM struct{}

func (failingTPM) Send([]byte) ([]byte, error) { return nil, errors.New("the TPM is gone") }

// refusing answers TPM2_PCR_Event with TPM_RC_LOCALITY, what a TPM says
// to an extend it does not allow.
type refusing struct{ transport.TPM }

func (r refusing) Send(cmd []byte) ([]byte, error) {
	if len(cmd) >= 10 && binary.BigEndian.Uint32(cmd[6:10]) == uint32(tpm2.TPMCCPCREvent) {
		return []byte{0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x09, 0x07}, nil
	}
	return r.TPM.Send(cmd)
}

// A CA of the SHA-1 bank reads PCR 15 there; Close extends every bank.
func TestCloseSHA1(t *testing.T) {
	sw := swtpmtest.StartBanks(t, "sha1")
	tpm := sw.Open(t)
	auth := authority(t)
	ca, err := CreateCA(tpm, auth.Public(), CAOptions{Type: P256, Bank: SHA1, PCRs: []int{7}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ca.OpenValue) != 20 {
		t.Fatalf("open value of %d bytes", len(ca.OpenValue))
	}
	sw.Reboot(t)
	now, _ := ca.ReadPCRs(tpm)
	if err := ca.Approve(auth, 0, now); err != nil {
		t.Fatal(err)
	}
	opts := IssueOptions{Principals: []string{"host.example"}, Open: sw.Opener()}
	certified(t, tpm, ca, opts, 0)
	if err := Close(tpm); err != nil {
		t.Fatal(err)
	}
	if hk, err := Issue(tpm, ca, opts); err != nil || !errors.Is(hk.Temporary, ErrClosed) {
		t.Fatalf("after Close: %v %v", hk, err)
	}
}

// In an approved state the CA signs and does nothing else: Certify with
// its session fails. Its ADMIN role takes no empty password.
func TestCASignsAlone(t *testing.T) {
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	auth := authority(t)
	ca, err := CreateCA(tpm, auth.Public(), CAOptions{Type: P256, Bank: SHA256, PCRs: []int{7}})
	if err != nil {
		t.Fatal(err)
	}
	sw.Reboot(t) // a CA signs from the boot after its creation
	now, _ := ca.ReadPCRs(tpm)
	if err := ca.Approve(auth, 0, now); err != nil {
		t.Fatal(err)
	}
	caPub, _ := ca.PublicKey()
	s := &caSigner{t: tpm, ca: ca, approval: &ca.Approvals[0], pub: caPub}
	key, session, done, err := s.open()
	if err != nil {
		t.Fatal(err)
	}
	null := tpm2.AuthHandle{Handle: tpm2.TPMRHNull, Auth: tpm2.PasswordAuth(nil)}
	named := tpm2.AuthHandle{Handle: key.ObjectHandle, Name: key.Name, Auth: session}
	if _, err := (tpm2.Certify{ObjectHandle: named, SignHandle: null}).Execute(tpm); !errors.Is(err, tpm2.TPMRCPolicyCC) {
		t.Fatalf("Certify with the CA's signing session: %v, want TPM_RC_POLICY_CC", err)
	}
	done()
	key, _, done, err = s.open()
	if err != nil {
		t.Fatal(err)
	}
	admin := tpm2.AuthHandle{Handle: key.ObjectHandle, Name: key.Name, Auth: tpm2.PasswordAuth(nil)}
	if _, err := (tpm2.Certify{ObjectHandle: admin, SignHandle: null}).Execute(tpm); !errors.Is(err, tpm2.TPMRCAuthType) {
		t.Fatalf("the CA's ADMIN role with an empty password: %v, want TPM_RC_AUTH_TYPE (a policy session only)", err)
	}
	done()
	swtpmtest.NoneLeft(t, tpm, "Certify")
}

// A CA whose authority is made once may be open at what events make PCR
// 15 (an initrd that measures into it first), and is left open in the boot
// that makes it until Close; from the next boot on it signs once PCR 15
// holds that value again. Every other CA refuses it: its approvals come
// later, in a running system.
func TestOpenEvents(t *testing.T) {
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	opts := IssueOptions{Principals: []string{"host.example"}, Open: sw.Opener()}
	swtpmtest.Extend(t, tpm, ClosePCR, "combination:a")
	now, err := ReadPCRs(tpm, SHA256, []int{7})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := CreateOnceCA(tpm, CAOptions{Type: P256, Bank: SHA256, PCRs: []int{7}, OpenEvents: []string{"combination:a"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if open, err := ca.IsOpen(tpm); err != nil || !open {
		t.Fatalf("a CA open at the events: open %v, %v", open, err)
	}
	certified(t, tpm, ca, opts, 0)
	if err := Close(tpm); err != nil {
		t.Fatal(err)
	}
	if hk, err := Issue(tpm, ca, opts); err != nil || !errors.Is(hk.Temporary, ErrClosed) {
		t.Fatalf("after Close: %v %v", hk, err)
	}
	// The next boot: closed until the same measurement comes again; another
	// one closes it.
	sw.Reboot(t)
	if hk, err := Issue(tpm, ca, opts); err != nil || !errors.Is(hk.Temporary, ErrClosed) {
		t.Fatalf("PCR 15 at zero: %v %v", hk, err)
	}
	swtpmtest.Extend(t, tpm, ClosePCR, "combination:a")
	certified(t, tpm, ca, opts, 0)
	sw.Reboot(t)
	swtpmtest.Extend(t, tpm, ClosePCR, "combination:b")
	if hk, err := Issue(tpm, ca, opts); err != nil || !errors.Is(hk.Temporary, ErrClosed) {
		t.Fatalf("another measurement: %v %v", hk, err)
	}

	o := CAOptions{Type: P256, Bank: SHA256, PCRs: []int{7}, OpenEvents: []string{"combination:a"}}
	if _, err := CreateCA(tpm, authority(t).Public(), o); !errors.Is(err, errOpenEvents) {
		t.Fatalf("CreateCA open at events: %v", err)
	}
	if _, err := CreatePINCA(tpm, PINCAOptions{CAOptions: o, PIN: func() ([]byte, error) { return []byte("123456"), nil }}); !errors.Is(err, errOpenEvents) {
		t.Fatalf("CreatePINCA open at events: %v", err)
	}
	swtpmtest.NoneLeft(t, tpm, "TestOpenEvents")
}

// A file whose open value is not the one in the CA key's policy, or does
// not fit the bank, is refused.
func TestOpenValueInPolicy(t *testing.T) {
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	ca, err := CreateCA(tpm, authority(t).Public(), CAOptions{Type: P256, Bank: SHA256, PCRs: []int{7}})
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*CA){
		"another open value": func(c *CA) { c.OpenValue = bytes.Repeat([]byte{1}, 32) },
		"no open value":      func(c *CA) { c.OpenValue = nil },
		"a SHA-1 size":       func(c *CA) { c.OpenValue = make([]byte, 20) },
	} {
		c := *ca
		edit(&c)
		b, _ := c.Marshal()
		if _, err := ParseCA(b); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	b, _ := ca.Marshal()
	if _, err := ParseCA(b); err != nil {
		t.Fatal(err)
	}
	_ = tpm2.TPMAlgSHA256
}

// The close's record in systemd's measurement log: in systemd-pcrextend's
// format, and its digests are what the extend put into every bank.
func TestCloseMeasureLog(t *testing.T) {
	dir := t.TempDir()
	measureLogDir = dir
	t.Cleanup(func() { measureLogDir = "/run/log/systemd" })
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)
	path := filepath.Join(dir, measureLogName)

	for range 2 {
		if err := Close(tpm); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSticky != 0 || st.Mode().Perm() != 0o600 {
		t.Fatalf("the log's mode after the close: %v", st.Mode())
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d records, want one per extend:\n%s", len(lines), data)
	}
	replay := map[string][]byte{}
	for _, line := range lines {
		if !strings.HasPrefix(line, "\x1e{\"pcr\":15,\"digests\":[{\"hashAlg\":\"") ||
			!regexp.MustCompile(`"content_type":"systemd","content":\{"string":"assh-close","bootId":"[0-9a-f]{32}","timestamp":[0-9]+,"eventType":"phase"\}\}$`).MatchString(line) {
			t.Fatalf("not systemd-pcrextend's record: %q", line)
		}
		var r measureRecord
		if err := json.Unmarshal([]byte(line[1:]), &r); err != nil {
			t.Fatal(err)
		}
		for _, d := range r.Digests {
			var h crypto.Hash
			for _, b := range measureBanks {
				if b.name == d.HashAlg {
					h = b.hash
				}
			}
			if h == 0 {
				t.Fatalf("bank %q", d.HashAlg)
			}
			digest, err := hex.DecodeString(d.Digest)
			if err != nil {
				t.Fatal(err)
			}
			if replay[d.HashAlg] == nil {
				replay[d.HashAlg] = make([]byte, h.Size())
			}
			next := h.New()
			next.Write(replay[d.HashAlg])
			next.Write(digest)
			replay[d.HashAlg] = next.Sum(nil)
		}
	}
	// The log replayed is the register, bank by bank.
	for alg, b := range measureBanks {
		want, ok := replay[b.name]
		if !ok {
			continue
		}
		got, err := tpm2.PCRRead{PCRSelectionIn: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash: alg, PCRSelect: tpm2.PCClientCompatible.PCRs(ClosePCR),
		}}}}.Execute(tpm)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.PCRValues.Digests[0].Buffer, want) {
			t.Fatalf("%s: the log replays to %x, the register holds %x", b.name, want, got.PCRValues.Digests[0].Buffer)
		}
	}
	if replay["sha256"] == nil {
		t.Fatal("no sha256 digest in the record")
	}
}

// No directory: the close happens, nothing is made. An extend that fails
// leaves no record and no sticky bit. A log that cannot be written is not the
// close's failure.
func TestCloseMeasureLogAbsentOrBroken(t *testing.T) {
	t.Cleanup(func() { measureLogDir = "/run/log/systemd" })
	sw := swtpmtest.Start(t)
	tpm := sw.Open(t)

	dir := t.TempDir()
	measureLogDir = filepath.Join(dir, "absent")
	if err := Close(tpm); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(measureLogDir); !os.IsNotExist(err) {
		t.Fatalf("the directory was made: %v", err)
	}

	measureLogDir = dir
	if err := Close(refusing{tpm}); err == nil {
		t.Fatal("a refused extend closed")
	}
	st, err := os.Stat(filepath.Join(dir, measureLogName))
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 0 || st.Mode()&os.ModeSticky != 0 {
		t.Fatalf("after a refused extend: size %d, mode %v", st.Size(), st.Mode())
	}

	// A symlink where the log should be is not followed.
	link := t.TempDir()
	measureLogDir = link
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(link, measureLogName)); err != nil {
		t.Fatal(err)
	}
	if err := Close(tpm); err != nil {
		t.Fatalf("the log's trouble failed the close: %v", err)
	}
	if st, err := os.Stat(target); err != nil || st.Size() != 0 {
		t.Fatalf("the symlink was followed: %v %v", st, err)
	}
}

// The bytes of systemd-pcrextend's record (systemd 262, captured against a
// software TPM with --tpm2-device=swtpm:), field for field.
func TestMeasureRecordKeyOrder(t *testing.T) {
	line, err := measureRecord{
		PCR:         15,
		Digests:     []measureDigest{{HashAlg: "sha256", Digest: "00"}},
		ContentType: "systemd",
		Content:     measureContent{String: "assh-close", BootID: "ab", Timestamp: 1, EventType: "phase"},
	}.marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := "\x1e{\"pcr\":15,\"digests\":[{\"hashAlg\":\"sha256\",\"digest\":\"00\"}],\"content_type\":\"systemd\",\"content\":{\"string\":\"assh-close\",\"bootId\":\"ab\",\"timestamp\":1,\"eventType\":\"phase\"}}\n"
	if string(line) != want {
		t.Fatalf("%q", line)
	}
}
