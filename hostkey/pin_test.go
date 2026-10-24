package hostkey

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/tpm2-trust/assh/internal/swtpmtest"
)

var testPIN = []byte("pin-7GQ2xw")

func pinOf(b []byte) PIN {
	return func() ([]byte, error) { return append([]byte(nil), b...), nil }
}

// pinCA starts a TPM with a lockout authorization and the brief's DA
// parameters (3 tries, 30 minutes) and makes a CA with a PIN in it.
func pinCA(t *testing.T) (*swtpmtest.SWTPM, transport.TPM, *CA) {
	t.Helper()
	sw := swtpmtest.Start(t)
	sw.SetLockout(t, 3, 1800, 1800)
	tpm := sw.Open(t)
	ca, err := CreatePINCA(tpm, PINCAOptions{Type: P256, Bank: SHA256, PCRs: []int{7, 15}, PolicyRef: []byte("assh test"), PIN: pinOf(testPIN)})
	if err != nil {
		t.Fatal(err)
	}
	swtpmtest.NoneLeft(t, tpm, "CreatePINCA")
	return sw, tpm, ca
}

func approveNow(t *testing.T, tpm transport.TPM, ca *CA, pin []byte) error {
	t.Helper()
	now, err := ca.ReadPCRs(tpm)
	if err != nil {
		t.Fatal(err)
	}
	a, err := ca.TPMAuthority(tpm, pinOf(pin))
	if err != nil {
		t.Fatal(err)
	}
	err = ca.Approve(a, now)
	swtpmtest.NoneLeft(t, tpm, "Approve")
	return err
}

func issue(t *testing.T, sw *swtpmtest.SWTPM, tpm transport.TPM, ca *CA) (*HostKey, error) {
	t.Helper()
	hk, err := Issue(tpm, ca, IssueOptions{Principals: []string{"host.example"}, Open: sw.Opener()})
	swtpmtest.NoneLeft(t, tpm, "Issue")
	return hk, err
}

// The authority in the TPM approves with the PIN; the CA signs with no PIN.
// A file round trip keeps it all; a wrong PIN is refused and changes
// nothing.
func TestPINAuthority(t *testing.T) {
	bare := swtpmtest.Start(t).Open(t)
	o := PINCAOptions{Type: P256, Bank: SHA256, PCRs: []int{7, 15}, PIN: pinOf(testPIN)}
	if _, err := CreatePINCA(bare, o); err == nil || !strings.Contains(err.Error(), "no lockout authorization") {
		t.Fatalf("created without a lockout authorization: %v", err)
	}
	swtpmtest.NoneLeft(t, bare, "refused CreatePINCA")

	sw, tpm, ca := pinCA(t)
	if ca.FileGeneration() != 1 {
		t.Fatalf("generation %d", ca.FileGeneration())
	}
	if _, err := CreatePINCA(tpm, o); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("created over the handles in use: %v", err)
	}
	if _, err := issue(t, sw, tpm, ca); !isMismatch(err, true) {
		t.Fatalf("issue without an approval: %v", err)
	}
	if err := approveNow(t, tpm, ca, []byte("wrong-pin")); !errors.Is(err, ErrWrongPIN) {
		t.Fatalf("approve with a wrong PIN: %v", err)
	}
	if len(ca.Approvals) != 0 {
		t.Fatal("a wrong PIN added an approval")
	}
	if err := approveNow(t, tpm, ca, testPIN); err != nil {
		t.Fatal(err)
	}
	b, err := ca.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, testPIN) {
		t.Fatal("the PIN is in the file")
	}
	if ca, err = ParseCA(b); err != nil {
		t.Fatal(err)
	}
	hk, err := issue(t, sw, tpm, ca)
	if err != nil {
		t.Fatal(err)
	}
	checkTrusted(t, ca, hk)

	// The CA's policy names the authority as it is in the TPM.
	p, _ := createPrimary(tpm, tpm2.TPMRHOwner)
	a, err := loadKey(tpm, p, ca.AuthorityTPM.Public, ca.AuthorityTPM.Private)
	flush(tpm, p.handle)
	if err != nil {
		t.Fatal(err)
	}
	flush(tpm, a.ObjectHandle)
	name, _ := ca.authorityName()
	caPub, _ := tpm2.Unmarshal[tpm2.TPMTPublic](ca.Public)
	if !bytes.Equal(name.Buffer, a.Name.Buffer) || !bytes.Equal(caPub.AuthPolicy.Buffer, caPolicyFor(a.Name, ca.PolicyRef)) {
		t.Fatal("the CA's policy does not name the authority's key")
	}

	// Copied to another TPM, nothing works.
	other := swtpmtest.Start(t)
	other.SetLockout(t, 3, 1800, 1800)
	otpm := other.Open(t)
	if err := approveNow(t, otpm, ca, testPIN); err == nil {
		t.Fatal("approved on another TPM")
	}
	if _, err := issue(t, other, otpm, ca); err == nil {
		t.Fatal("issued on another TPM")
	}
}

// The digest the TPM reaches before PolicyAuthorize is the approved policy
// the authority signs.
func TestApprovedPolicyDigest(t *testing.T) {
	_, tpm, ca := pinCA(t)
	now, err := ca.ReadPCRs(tpm)
	if err != nil {
		t.Fatal(err)
	}
	want, err := ca.approvedPolicy(now, ca.FileGeneration())
	if err != nil {
		t.Fatal(err)
	}
	s, done, err := policySession(tpm)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	if _, err := (tpm2.PolicyPCR{PolicySession: s.Handle(), Pcrs: ca.pcrSelection()}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	g, _ := ca.counter()
	if _, err := (tpm2.PolicyNV{
		AuthHandle:    tpm2.AuthHandle{Handle: g.NVIndex, Name: nvName(g), Auth: tpm2.PasswordAuth(nil)},
		NVIndex:       tpm2.NamedHandle{Handle: g.NVIndex, Name: nvName(g)},
		PolicySession: s.Handle(),
		OperandB:      tpm2.TPM2BOperand{Buffer: binary.BigEndian.AppendUint64(nil, ca.FileGeneration())},
		Operation:     tpm2.TPMEOEq,
	}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	got, err := tpm2.PolicyGetDigest{PolicySession: s.Handle()}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.PolicyDigest.Buffer, want) {
		t.Fatalf("the TPM's digest %x, the calculator's %x", got.PolicyDigest.Buffer, want)
	}
}

// Three wrong PINs lock the TPM out: the right PIN is refused too, through
// the authority and through the counter, while Issue keeps working. After a
// reset the PIN works again. Guesses through the counter count alike.
func TestPINLockout(t *testing.T) {
	sw, tpm, ca := pinCA(t)
	if err := approveNow(t, tpm, ca, testPIN); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := approveNow(t, tpm, ca, []byte("wrong-pin")); !errors.Is(err, ErrWrongPIN) {
			t.Fatalf("wrong PIN %d: %v", i, err)
		}
	}
	if err := approveNow(t, tpm, ca, testPIN); !errors.Is(err, ErrLockedOut) {
		t.Fatalf("the right PIN in a lockout: %v", err)
	}
	if err := ca.NextGeneration(tpm, pinOf(testPIN)); !errors.Is(err, ErrLockedOut) {
		t.Fatalf("the counter in a lockout: %v", err)
	}
	swtpmtest.NoneLeft(t, tpm, "NextGeneration")
	hk, err := issue(t, sw, tpm, ca)
	if err != nil {
		t.Fatalf("issue in a lockout: %v", err)
	}
	checkTrusted(t, ca, hk)
	sw.ResetLockout(t)
	if err := approveNow(t, tpm, ca, testPIN); err != nil {
		t.Fatal(err)
	}

	// Through the counter.
	for i := 0; i < 3; i++ {
		if err := ca.NextGeneration(tpm, pinOf([]byte("wrong-pin"))); !errors.Is(err, ErrWrongPIN) {
			t.Fatalf("wrong PIN %d on the counter: %v", i, err)
		}
	}
	if err := approveNow(t, tpm, ca, testPIN); !errors.Is(err, ErrLockedOut) {
		t.Fatalf("the right PIN after 3 wrong ones on the counter: %v", err)
	}
	if g, err := ca.Generation(tpm); err != nil || g != 1 {
		t.Fatalf("wrong PINs moved the counter: %d %v", g, err)
	}
}

// A move: the counter's next generation revokes every approval before it,
// in the TPM, also one put back into the file by hand.
func TestMove(t *testing.T) {
	sw, tpm, ca := pinCA(t)
	if err := approveNow(t, tpm, ca, testPIN); err != nil {
		t.Fatal(err)
	}
	if _, err := issue(t, sw, tpm, ca); err != nil {
		t.Fatal(err)
	}
	old := ca.Approvals[0]
	if err := ca.NextGeneration(tpm, pinOf(testPIN)); err != nil {
		t.Fatal(err)
	}
	if ca.FileGeneration() != 2 {
		t.Fatalf("generation %d", ca.FileGeneration())
	}
	var m *MismatchError
	if _, err := issue(t, sw, tpm, ca); !errors.As(err, &m) || !m.Revoked || m.Generation != 1 || m.Counter != 2 {
		t.Fatalf("issue with a revoked approval: %v", err)
	}
	// Past the software's check: the TPM refuses the old approval.
	caPub, _ := ca.PublicKey()
	_, err := (&caSigner{t: tpm, ca: ca, approval: &old, pub: caPub}).Sign(rand.Reader, make([]byte, 32), crypto.SHA256)
	if err == nil {
		t.Fatal("the TPM signed with a revoked approval")
	}
	swtpmtest.NoneLeft(t, tpm, "refused signature")

	// The new state Y: PCR 15 moves on, approved at generation 2.
	if err := Close(tpm, 15, "combination Y"); err != nil {
		t.Fatal(err)
	}
	if err := approveNow(t, tpm, ca, testPIN); err != nil {
		t.Fatal(err)
	}
	hk, err := issue(t, sw, tpm, ca)
	if err != nil {
		t.Fatal(err)
	}
	checkTrusted(t, ca, hk)
	// The old approval re-added to a file that has lost the new ones.
	ca.Approvals = []Approval{old}
	b, _ := ca.Marshal()
	if again, err := ParseCA(b); err != nil {
		t.Fatal(err)
	} else if _, err := issue(t, sw, tpm, again); err == nil {
		t.Fatal("issued with an old approval")
	}
}

// Root undefines the counter and defines it again alike: until it is
// incremented its Name differs and the CA signs nothing; root cannot
// increment it without the PIN; the owner's next generation lands above the
// old value with the old Name. A counter with other attributes needs
// RedefineCounter.
func TestCounterClone(t *testing.T) {
	sw, tpm, ca := pinCA(t)
	if err := approveNow(t, tpm, ca, testPIN); err != nil {
		t.Fatal(err)
	}
	g, _ := ca.counter()
	if err := undefine(tpm, g.NVIndex); err != nil {
		t.Fatal(err)
	}
	clone := g
	clone.Attributes.Written = false
	if _, err := (tpm2.NVDefineSpace{AuthHandle: tpm2.TPMRHOwner, PublicInfo: tpm2.New2B(clone)}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	var gone *counterGoneError
	if _, err := issue(t, sw, tpm, ca); !errors.As(err, &gone) {
		t.Fatalf("issue with a clone of the counter: %v", err)
	}
	// Without the PIN the clone cannot be incremented.
	s, done, _ := policySession(tpm)
	tpm2.PolicyCommandCode{PolicySession: s.Handle(), Code: tpm2.TPMCCNVIncrement}.Execute(tpm)
	if _, err := (tpm2.NVIncrement{
		AuthHandle: tpm2.AuthHandle{Handle: clone.NVIndex, Name: nvName(clone), Auth: s},
		NVIndex:    tpm2.NamedHandle{Handle: clone.NVIndex, Name: nvName(clone)},
	}).Execute(tpm); err == nil {
		t.Fatal("the clone was incremented without the PIN")
	}
	done()
	if err := ca.NextGeneration(tpm, pinOf(testPIN)); err != nil {
		t.Fatal(err)
	}
	if ca.FileGeneration() <= 1 {
		t.Fatalf("the clone's generation %d", ca.FileGeneration())
	}
	if _, err := issue(t, sw, tpm, ca); !isRevoked(err) {
		t.Fatalf("issue with the approval of generation 1: %v", err)
	}
	if err := approveNow(t, tpm, ca, testPIN); err != nil {
		t.Fatal(err)
	}
	if _, err := issue(t, sw, tpm, ca); err != nil {
		t.Fatal(err)
	}

	// Another counter at the handle: refused; RedefineCounter, with the
	// PIN, puts the CA's back.
	before := ca.FileGeneration()
	undefine(tpm, g.NVIndex)
	other := clone
	other.Attributes.NoDA = false
	tpm2.NVDefineSpace{AuthHandle: tpm2.TPMRHOwner, PublicInfo: tpm2.New2B(other)}.Execute(tpm)
	if err := ca.NextGeneration(tpm, pinOf(testPIN)); !errors.As(err, &gone) {
		t.Fatalf("next generation of another counter: %v", err)
	}
	if err := ca.RedefineCounter(tpm, pinOf([]byte("wrong-pin"))); !errors.Is(err, ErrWrongPIN) {
		t.Fatalf("redefine with a wrong PIN: %v", err)
	}
	if _, name, _ := readNVPublic(tpm, g.NVIndex); !bytes.Equal(name.Buffer, nvName(other).Buffer) {
		t.Fatal("a wrong PIN removed what was at the counter's handle")
	}
	if err := ca.RedefineCounter(tpm, pinOf(testPIN)); err != nil {
		t.Fatal(err)
	}
	swtpmtest.NoneLeft(t, tpm, "RedefineCounter")
	if ca.FileGeneration() <= before {
		t.Fatalf("generation %d after %d", ca.FileGeneration(), before)
	}
	if err := approveNow(t, tpm, ca, testPIN); err != nil {
		t.Fatal(err)
	}
	if _, err := issue(t, sw, tpm, ca); err != nil {
		t.Fatal(err)
	}
}

func isRevoked(err error) bool {
	var m *MismatchError
	return errors.As(err, &m) && m.Revoked
}

// Root undefines the PIN index and defines it again alike with a PIN of its
// own: the clone has the Name of the CA's, but never its value, so it opens
// neither the authority nor the counter - not even past the software's
// checks. The PIN index gone, the CA still signs with its approvals.
func TestPINIndexClone(t *testing.T) {
	sw, tpm, ca := pinCA(t)
	if err := approveNow(t, tpm, ca, testPIN); err != nil {
		t.Fatal(err)
	}
	pPub, k, _ := ca.pinIndex()
	if err := undefine(tpm, pPub.NVIndex); err != nil {
		t.Fatal(err)
	}
	unwritten := pinIndexPublic(pPub.NVIndex)
	evil := []byte("attacker-pin")
	if _, err := (tpm2.NVDefineSpace{AuthHandle: tpm2.TPMRHOwner, Auth: tpm2.TPM2BAuth{Buffer: evil}, PublicInfo: tpm2.New2B(unwritten)}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	if err := incrementPINIndex(tpm, unwritten); err != nil {
		t.Fatal(err)
	}
	_, name, _ := readNVPublic(tpm, pPub.NVIndex)
	v, _ := readCount(tpm, pPub.NVIndex, name, tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)})
	if !bytes.Equal(name.Buffer, nvName(pPub).Buffer) || v <= k {
		t.Fatalf("the clone: same Name %v, value %d (the CA's %d)", bytes.Equal(name.Buffer, nvName(pPub).Buffer), v, k)
	}
	if err := approveNow(t, tpm, ca, evil); err == nil || !strings.Contains(err.Error(), "not the CA's") {
		t.Fatalf("approve through the clone: %v", err)
	}
	// Past the software's check.
	p, _ := createPrimary(tpm, tpm2.TPMRHOwner)
	err := checkGate(tpm, p, pPub, k, evil)
	flush(tpm, p.handle)
	if !errors.Is(err, tpm2.TPMRCPolicy) {
		t.Fatalf("the clone's gate: %v", err)
	}
	swtpmtest.NoneLeft(t, tpm, "the clone's gate")
	if _, err := issue(t, sw, tpm, ca); err != nil {
		t.Fatalf("issue without the PIN index: %v", err)
	}
}

// What the TPM takes as a PIN, byte for byte; and what it would not take
// as it is meant.
func TestPINs(t *testing.T) {
	for _, bad := range [][]byte{[]byte("12345"), bytes.Repeat([]byte("x"), 33), []byte("123456\x00"), []byte("abc\x00\x00\x00")} {
		if err := CheckPIN(bad); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
	sw := swtpmtest.Start(t)
	sw.SetLockout(t, 100, 1800, 1800)
	tpm := sw.Open(t)
	for i, pin := range [][]byte{
		[]byte("123456"),
		bytes.Repeat([]byte("7"), 32),
		[]byte("ab\x00cdef"),
		[]byte("€uro99"),
		bytes.Repeat([]byte{0xff}, 8),
		append(make([]byte, 7), 1),
	} {
		ca, err := CreatePINCA(tpm, PINCAOptions{
			Type: P256, Bank: SHA256, PCRs: []int{7}, PIN: pinOf(pin),
			PINHandle: tpm2.TPMHandle(0x01802a00 + 2*i), CounterHandle: tpm2.TPMHandle(0x01802a01 + 2*i),
		})
		if err != nil {
			t.Fatalf("%q: %v", pin, err)
		}
		if err := ca.NextGeneration(tpm, pinOf(pin)); err != nil {
			t.Errorf("%q: next generation: %v", pin, err)
		}
		if err := approveNow(t, tpm, ca, pin); err != nil {
			t.Errorf("%q: approve: %v", pin, err)
		}
		if _, err := issue(t, sw, tpm, ca); err != nil {
			t.Errorf("%q: issue: %v", pin, err)
		}
	}
	if _, err := CreatePINCA(tpm, PINCAOptions{Type: P256, Bank: SHA256, PCRs: []int{7}, PIN: pinOf([]byte("12345"))}); err == nil {
		t.Error("created with a PIN of 5 bytes")
	}
}

// No byte of the PIN crosses the bus: everything that proves it runs in a
// salted session, and what carries it is encrypted.
func TestPINNotOnTheBus(t *testing.T) {
	sw := swtpmtest.Start(t)
	sw.SetLockout(t, 3, 1800, 1800)
	rec := &swtpmtest.Recorder{TPM: sw.Open(t)}
	ca, err := CreatePINCA(rec, PINCAOptions{Type: P256, Bank: SHA256, PCRs: []int{7}, PIN: pinOf(testPIN)})
	if err != nil {
		t.Fatal(err)
	}
	if err := approveNow(t, rec, ca, testPIN); err != nil {
		t.Fatal(err)
	}
	if err := ca.NextGeneration(rec, pinOf(testPIN)); err != nil {
		t.Fatal(err)
	}
	if err := ca.RedefineCounter(rec, pinOf(testPIN)); err != nil {
		t.Fatal(err)
	}
	approveNow(t, rec, ca, []byte("wrong-pin"))
	if bytes.Contains(rec.Bytes, testPIN) || bytes.Contains(rec.Bytes, []byte("wrong-pin")) {
		t.Fatal("a PIN crossed the bus")
	}
	if len(rec.Bytes) < 1000 {
		t.Fatalf("recorded %d bytes only", len(rec.Bytes))
	}
}

// A file edited by hand cannot weaken the authority, and an old format is
// refused.
func TestPINCAFileChecked(t *testing.T) {
	_, tpm, ca := pinCA(t)
	if err := approveNow(t, tpm, ca, testPIN); err != nil {
		t.Fatal(err)
	}
	edit := func(change func(*CA)) error {
		b, _ := ca.Marshal()
		c, _ := ParseCA(b)
		change(c)
		b, _ = json.Marshal(c)
		_, err := ParseCA(b)
		return err
	}
	if err := edit(func(*CA) {}); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*CA){
		"counter NO_DA off": func(c *CA) {
			g, _ := c.counter()
			g.Attributes.NoDA = false
			c.Counter.Public = tpm2.Marshal(g)
		},
		"PIN index NO_DA": func(c *CA) {
			p, _, _ := c.pinIndex()
			p.Attributes.NoDA = true
			c.AuthorityTPM.PIN = tpm2.Marshal(p)
		},
		"another PIN value": func(c *CA) { c.AuthorityTPM.PINValue++ },
		"no counter":        func(c *CA) { c.Counter = nil },
		"approval of generation 0": func(c *CA) {
			c.Approvals[0].Generation = 0
		},
		"another authority": func(c *CA) { c.Authority = append([]byte(nil), c.Authority[:len(c.Authority)-1]...) },
	} {
		if err := edit(change); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	b, _ := ca.Marshal()
	b = bytes.Replace(b, []byte(`"version": 2`), []byte(`"version": 1`), 1)
	if _, err := ParseCA(b); err == nil || !strings.Contains(err.Error(), "create the CA again") {
		t.Fatalf("version 1: %v", err)
	}
}
