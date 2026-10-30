package hostkey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tpm2-trust/assh/persist"
)

// An authority in the TPM: three objects, nothing secret outside it.
//
//	P  the PIN index: an NV counter whose authorization value is the PIN.
//	   It is incremented once, when it is made, and holds that value k for
//	   good: its policy allows TPM2_NV_Increment only while it is unwritten,
//	   and TPM2_NV_ChangeAuth with the PIN (a PIN change, in place).
//	A  the authority key, ECDSA P-256, used through a policy alone:
//	   PolicySecret(P) ; PolicyNV(P == k) ; PolicyCommandCode(Sign).
//	G  the counter: an NV counter incremented through
//	   PolicyCommandCode(NV_Increment) ; PolicySecret(P) ; PolicyNV(P == k).
//	   Every approval names a value of G; incrementing it revokes the
//	   approvals of the values before.
//
// A clone of P - undefined and defined again alike, with another PIN - has
// P's Name but never the value k: the TPM sets a counter's first value
// above any value a counter of that Name has had (TPM 2.0 Part 1,
// 37.2.6.3). So nothing but P opens A or G, and nothing opens them without
// the PIN. P is the only object here the dictionary attack protection
// guards; wrong PINs count, and lock it out. A, G, the CA and the host key
// are noDA, so a lockout never stops Issue.

// Default NV handles of an authority in the TPM, in the owner's range.
const (
	DefaultCounterHandle tpm2.TPMHandle = 0x01802912
	DefaultPINHandle     tpm2.TPMHandle = 0x01802913
)

// A PIN is what a TPM takes as an authorization value: any bytes, at most
// as many as the SHA-256 digest that names P, and here at least six.
const (
	MinPIN = 6
	MaxPIN = 32
)

var (
	// ErrWrongPIN is a PIN the TPM refused; it counted as a failure.
	ErrWrongPIN = errors.New("wrong PIN")
	// ErrLockedOut is the TPM refusing every PIN for a while: too many
	// wrong ones.
	ErrLockedOut = errors.New("the TPM is locked out after too many wrong PINs: wait, or reset it with the lockout authorization")
)

// PIN gives the PIN when the TPM needs it.
type PIN func() ([]byte, error)

// CheckPIN makes sure the TPM takes pin as it is: MinPIN to MaxPIN bytes,
// the last not zero (the TPM drops trailing zero bytes, so "123456\x00"
// would be "123456", and "abc\x00\x00\x00" a PIN of three bytes).
func CheckPIN(pin []byte) error {
	switch {
	case len(pin) < MinPIN:
		return fmt.Errorf("a PIN of %d bytes: at least %d", len(pin), MinPIN)
	case len(pin) > MaxPIN:
		return fmt.Errorf("a PIN of %d bytes: at most %d", len(pin), MaxPIN)
	case pin[len(pin)-1] == 0:
		return errors.New("a PIN that ends in a zero byte (the TPM would drop it)")
	}
	return nil
}

// TPMAuthority is an authority key made in this TPM, A, and the PIN index
// that opens it, P. Nothing in it is a secret: A's private part is wrapped
// by this TPM and opens nothing without P.
type TPMAuthority struct {
	Public   []byte `json:"public"`    // A's TPMT_PUBLIC
	Private  []byte `json:"private"`   // A's TPM2B_PRIVATE buffer
	PIN      []byte `json:"pin"`       // P's TPMS_NV_PUBLIC, written
	PINValue uint64 `json:"pin_value"` // k, the value P holds for good
}

// Counter is the NV counter whose value every approval names.
type Counter struct {
	Public     []byte `json:"public"`     // G's TPMS_NV_PUBLIC, written
	Generation uint64 `json:"generation"` // the value this file was last at
}

// PINCAOptions are what CreatePINCA takes: the CA's, and the PIN's.
type PINCAOptions struct {
	CAOptions
	// The NV handles of P and G; default DefaultPINHandle and
	// DefaultCounterHandle.
	PINHandle, CounterHandle tpm2.TPMHandle
	// PIN is asked once.
	PIN PIN
}

func ownerNVHandle(h tpm2.TPMHandle) error {
	if h < 0x01800000 || h > 0x01BFFFFF {
		return fmt.Errorf("NV handle 0x%08X is not in the owner's range (0x01800000-0x01BFFFFF)", uint32(h))
	}
	return nil
}

func nvName(pub tpm2.TPMSNVPublic) tpm2.TPM2BName {
	n, _ := tpm2.NVName(&pub)
	return *n
}

func written(pub tpm2.TPMSNVPublic) tpm2.TPMSNVPublic {
	pub.Attributes.Written = true
	return pub
}

func policyDigest(update ...func(*tpm2.PolicyCalculator) error) []byte {
	calc, _ := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	for _, u := range update {
		if err := u(calc); err != nil {
			panic(err) // the commands here never fail to update
		}
	}
	return calc.Hash().Digest
}

// PINIndexBranches are the branches of the PIN index's PolicyOR: its one
// increment (PolicyCommandCode(NV_Increment) ; PolicyNvWritten(NO)), and a
// PIN change (PolicyCommandCode(NV_ChangeAuth) ; PolicyAuthValue).
func PINIndexBranches() tpm2.TPMLDigest {
	inc := policyDigest(
		tpm2.PolicyCommandCode{Code: tpm2.TPMCCNVIncrement}.Update,
		tpm2.PolicyNVWritten{WrittenSet: false}.Update)
	change := policyDigest(
		tpm2.PolicyCommandCode{Code: tpm2.TPMCCNVChangeAuth}.Update,
		tpm2.PolicyAuthValue{}.Update)
	return tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{{Buffer: inc}, {Buffer: change}}}
}

// pinIndexPublic is P as it is defined, unwritten.
func pinIndexPublic(h tpm2.TPMHandle) tpm2.TPMSNVPublic {
	return tpm2.TPMSNVPublic{
		NVIndex: h,
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			NT:          tpm2.TPMNTCounter,
			PolicyWrite: true,
			AuthRead:    true, // PolicySecret(P) proves its authorization value
			OwnerRead:   true, // PolicyNV(P == k) reads it without the PIN
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: policyDigest(tpm2.PolicyOr{PHashList: PINIndexBranches()}.Update)},
		DataSize:   8,
	}
}

// pinGate is PolicySecret(P) ; PolicyNV(P == k), for a calculator.
func pinGate(p tpm2.TPMSNVPublic, k uint64) []func(*tpm2.PolicyCalculator) error {
	n := nvName(p)
	return []func(*tpm2.PolicyCalculator) error{
		tpm2.PolicySecret{AuthHandle: tpm2.NamedHandle{Handle: p.NVIndex, Name: n}}.Update,
		tpm2.PolicyNV{
			NVIndex:   tpm2.NamedHandle{Handle: p.NVIndex, Name: n},
			OperandB:  tpm2.TPM2BOperand{Buffer: binary.BigEndian.AppendUint64(nil, k)},
			Operation: tpm2.TPMEOEq,
		}.Update,
	}
}

// authorityPolicy is A's policy: the gate, then Sign.
func authorityPolicy(p tpm2.TPMSNVPublic, k uint64) []byte {
	return policyDigest(append(pinGate(p, k), tpm2.PolicyCommandCode{Code: tpm2.TPMCCSign}.Update)...)
}

// counterPublic is G as it is defined, unwritten. It is NO_DA and read
// with its empty authorization value, so Issue reads it during a lockout;
// it holds no secret.
func counterPublic(h tpm2.TPMHandle, p tpm2.TPMSNVPublic, k uint64) tpm2.TPMSNVPublic {
	update := append([]func(*tpm2.PolicyCalculator) error{tpm2.PolicyCommandCode{Code: tpm2.TPMCCNVIncrement}.Update}, pinGate(p, k)...)
	return tpm2.TPMSNVPublic{
		NVIndex: h,
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			NT:          tpm2.TPMNTCounter,
			PolicyWrite: true,
			AuthRead:    true,
			NoDA:        true,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: policyDigest(update...)},
		DataSize:   8,
	}
}

// salted is an HMAC session that proves auth without sending it, salted
// with p so that its HMACs tell an observer of the bus nothing about auth,
// and encrypting the command's first parameter.
func salted(p *primary, auth []byte) tpm2.Session {
	return tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(auth),
		tpm2.Salted(p.handle, p.public), tpm2.AESEncryption(128, tpm2.EncryptIn))
}

// pinError names what the TPM says about a PIN.
func pinError(err error) error {
	switch {
	case errors.Is(err, tpm2.TPMRCLockout):
		return ErrLockedOut
	case errors.Is(err, tpm2.TPMRCAuthFail), errors.Is(err, tpm2.TPMRCBadAuth):
		return ErrWrongPIN
	}
	return err
}

func readCount(t transport.TPM, h tpm2.TPMHandle, name tpm2.TPM2BName, auth tpm2.AuthHandle) (uint64, error) {
	rsp, err := tpm2.NVRead{AuthHandle: auth, NVIndex: tpm2.NamedHandle{Handle: h, Name: name}, Size: 8}.Execute(t)
	if err != nil {
		return 0, err
	}
	if len(rsp.Data.Buffer) != 8 {
		return 0, fmt.Errorf("NV index 0x%08X: %d bytes, a counter has 8", uint32(h), len(rsp.Data.Buffer))
	}
	return binary.BigEndian.Uint64(rsp.Data.Buffer), nil
}

// LockoutAuthSet is whether the TPM's lockout hierarchy has an
// authorization value. Without one any process may reset the dictionary
// attack lockout, and a PIN stops nobody who can use the TPM.
func LockoutAuthSet(t transport.TPM) (bool, error) {
	rsp, err := tpm2.GetCapability{Capability: tpm2.TPMCapTPMProperties, Property: uint32(tpm2.TPMPTPermanent), PropertyCount: 1}.Execute(t)
	if err != nil {
		return false, err
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return false, err
	}
	if len(props.TPMProperty) != 1 || props.TPMProperty[0].Property != tpm2.TPMPTPermanent {
		return false, errors.New("the TPM does not report TPM_PT_PERMANENT")
	}
	return props.TPMProperty[0].Value&(1<<2) != 0, nil // lockoutAuthSet
}

// CreatePINCA makes a CA whose authority is in this TPM, opened by a PIN:
// P and G at their handles, A, and the CA. It refuses a TPM without a
// lockout authorization, and handles already in use; on a failure it
// removes what it made. The CA has no approval yet; its counter is at
// generation 1.
func CreatePINCA(t transport.TPM, o PINCAOptions) (ca *CA, err error) {
	if o.PINHandle == 0 {
		o.PINHandle = DefaultPINHandle
	}
	if o.CounterHandle == 0 {
		o.CounterHandle = DefaultCounterHandle
	}
	wHandle := windowHandle(o.WindowHandle)
	for _, h := range []tpm2.TPMHandle{o.PINHandle, o.CounterHandle, wHandle} {
		if err := ownerNVHandle(h); err != nil {
			return nil, err
		}
	}
	if o.PINHandle == o.CounterHandle || o.PINHandle == wHandle || o.CounterHandle == wHandle {
		return nil, errors.New("the PIN index, the counter and the window index need three handles")
	}
	ca, err = newCA(t, o.CAOptions)
	if err != nil {
		return nil, err
	}
	if o.PIN == nil {
		return nil, errors.New("no PIN")
	}
	if set, err := LockoutAuthSet(t); err != nil {
		return nil, err
	} else if !set {
		return nil, errors.New("the TPM has no lockout authorization: anyone could reset its dictionary attack lockout and try PINs without end; set one first")
	}
	for _, h := range []tpm2.TPMHandle{o.PINHandle, o.CounterHandle, wHandle} {
		if _, _, err := persist.ReadNVPublic(t, h); err == nil {
			return nil, fmt.Errorf("NV handle 0x%08X is in use", uint32(h))
		}
	}
	pin, err := o.PIN()
	if err != nil {
		return nil, err
	}
	defer clear(pin)
	if err := CheckPIN(pin); err != nil {
		return nil, err
	}

	p, err := createPrimary(t, tpm2.TPMRHOwner)
	if err != nil {
		return nil, err
	}
	defer flush(t, p.handle)

	var defined []tpm2.TPMSNVPublic
	defer func() {
		if err != nil {
			for _, pub := range defined {
				persist.RemoveNV(t, pub.NVIndex, persist.Defined(pub))
			}
		}
	}()
	pPub := pinIndexPublic(o.PINHandle)
	if _, err := (tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: salted(p, nil)},
		Auth:       tpm2.TPM2BAuth{Buffer: pin},
		PublicInfo: tpm2.New2B(pPub),
	}).Execute(t); err != nil {
		return nil, fmt.Errorf("defining the PIN index at 0x%08X: %w", uint32(o.PINHandle), err)
	}
	defined = append(defined, pPub)
	if err := incrementPINIndex(t, pPub); err != nil {
		return nil, fmt.Errorf("writing the PIN index: %w", err)
	}
	pPub = written(pPub)
	k, err := readCount(t, pPub.NVIndex, nvName(pPub), tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)})
	if err != nil {
		return nil, fmt.Errorf("reading the PIN index: %w", err)
	}

	aTmpl, _ := keyTemplate(P256, authorityPolicy(pPub, k))
	a, err := createKey(t, p, aTmpl, nil)
	if err != nil {
		return nil, fmt.Errorf("creating the authority in the TPM: %w", err)
	}
	aPub, err := a.OutPublic.Contents()
	if err != nil {
		return nil, err
	}
	auth := &TPMAuthority{Public: tpm2.Marshal(aPub), Private: a.OutPrivate.Buffer, PIN: tpm2.Marshal(pPub), PINValue: k}
	authorityKey, err := tpm2.Pub(*aPub)
	if err != nil {
		return nil, err
	}
	authorityDER, err := x509.MarshalPKIXPublicKey(authorityKey)
	if err != nil {
		return nil, err
	}

	gPub := counterPublic(o.CounterHandle, pPub, k)
	if _, err := (tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		PublicInfo: tpm2.New2B(gPub),
	}).Execute(t); err != nil {
		return nil, fmt.Errorf("defining the counter at 0x%08X: %w", uint32(o.CounterHandle), err)
	}
	defined = append(defined, gPub)

	ca.Authority, ca.AuthorityTPM = authorityDER, auth
	ca.Counter = &Counter{Public: tpm2.Marshal(written(gPub))}
	if err := ca.incrementCounter(t, p, gPub, pin); err != nil {
		return nil, fmt.Errorf("the counter's first increment: %w", err)
	}
	if err := ca.Sync(t); err != nil {
		return nil, err
	}
	if ca.Window, err = defineWindow(t, wHandle); err != nil {
		return nil, err
	}
	defined = append(defined, windowPublic(wHandle))

	if err := ca.makeKey(t, p); err != nil {
		return nil, err
	}
	return ca, nil
}

// incrementPINIndex is P's one increment, which needs no PIN.
func incrementPINIndex(t transport.TPM, pub tpm2.TPMSNVPublic) error {
	s, done, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return err
	}
	defer done()
	h := s.Handle()
	if _, err := (tpm2.PolicyCommandCode{PolicySession: h, Code: tpm2.TPMCCNVIncrement}).Execute(t); err != nil {
		return err
	}
	if _, err := (tpm2.PolicyNVWritten{PolicySession: h, WrittenSet: false}).Execute(t); err != nil {
		return err
	}
	if _, err := (tpm2.PolicyOr{PolicySession: h, PHashList: PINIndexBranches()}).Execute(t); err != nil {
		return err
	}
	name := nvName(pub)
	_, err = tpm2.NVIncrement{
		AuthHandle: tpm2.AuthHandle{Handle: pub.NVIndex, Name: name, Auth: s},
		NVIndex:    tpm2.NamedHandle{Handle: pub.NVIndex, Name: name},
	}.Execute(t)
	return err
}

// pinIndex is P as the file has it, and k.
func (f *CA) pinIndex() (tpm2.TPMSNVPublic, uint64, error) {
	if f.AuthorityTPM == nil {
		return tpm2.TPMSNVPublic{}, 0, errors.New("the CA's authority is not in the TPM")
	}
	pub, err := tpm2.Unmarshal[tpm2.TPMSNVPublic](f.AuthorityTPM.PIN)
	if err != nil {
		return tpm2.TPMSNVPublic{}, 0, fmt.Errorf("the PIN index: %w", err)
	}
	return *pub, f.AuthorityTPM.PINValue, nil
}

// CheckPINIndex makes sure the TPM holds the CA's PIN index, with the
// value it was written with, and gives its public area: what to check
// before anyone types a PIN into it.
func (f *CA) CheckPINIndex(t transport.TPM) (tpm2.TPMSNVPublic, error) {
	pub, _, err := f.checkPINIndex(t)
	return pub, err
}

func (f *CA) checkPINIndex(t transport.TPM) (tpm2.TPMSNVPublic, uint64, error) {
	pub, k, err := f.pinIndex()
	if err != nil {
		return pub, k, err
	}
	gone := fmt.Errorf("the PIN index at 0x%08X is not the CA's (deleted or replaced): no approval can be made any more; create the CA again", uint32(pub.NVIndex))
	_, name, err := persist.ReadNVPublic(t, pub.NVIndex)
	if err != nil || !bytes.Equal(name.Buffer, nvName(pub).Buffer) {
		return pub, k, gone
	}
	v, err := readCount(t, pub.NVIndex, name, tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)})
	if err != nil || v != k {
		return pub, k, gone
	}
	return pub, k, nil
}

// runGate runs PolicySecret(P) ; PolicyNV(P == k) in the policy session h.
func runGate(t transport.TPM, h tpm2.TPMHandle, p *primary, pub tpm2.TPMSNVPublic, k uint64, pin []byte) error {
	name := nvName(pub)
	if _, err := (tpm2.PolicySecret{
		AuthHandle:    tpm2.AuthHandle{Handle: pub.NVIndex, Name: name, Auth: salted(p, pin)},
		PolicySession: h,
	}).Execute(t); err != nil {
		return pinError(err)
	}
	_, err := tpm2.PolicyNV{
		AuthHandle:    tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:       tpm2.NamedHandle{Handle: pub.NVIndex, Name: name},
		PolicySession: h,
		OperandB:      tpm2.TPM2BOperand{Buffer: binary.BigEndian.AppendUint64(nil, k)},
		Operation:     tpm2.TPMEOEq,
	}.Execute(t)
	return err
}

// askPIN has pin give the PIN, and checks it.
func askPIN(pin PIN) ([]byte, error) {
	if pin == nil {
		return nil, errors.New("no PIN")
	}
	b, err := pin()
	if err != nil {
		return nil, err
	}
	if err := CheckPIN(b); err != nil {
		clear(b)
		return nil, err
	}
	return b, nil
}

// TPMAuthority is the CA's authority in the TPM as a crypto.Signer, for
// Approve. Each signature asks pin for the PIN.
func (f *CA) TPMAuthority(t transport.TPM, pin PIN) (crypto.Signer, error) {
	if f.AuthorityTPM == nil {
		return nil, errors.New("the CA's authority is not in the TPM")
	}
	pub, err := f.authorityKey()
	if err != nil {
		return nil, err
	}
	return &tpmAuthority{t: t, f: f, pin: pin, pub: pub}, nil
}

type tpmAuthority struct {
	t   transport.TPM
	f   *CA
	pin PIN
	pub crypto.PublicKey
}

func (a *tpmAuthority) Public() crypto.PublicKey { return a.pub }

// Sign signs a SHA-256 digest with A: ECDSA, ASN.1 DER.
func (a *tpmAuthority) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("the authority signs SHA-256 digests, not %v", opts.HashFunc())
	}
	t, f := a.t, a.f
	pPub, k, err := f.checkPINIndex(t)
	if err != nil {
		return nil, err
	}
	pin, err := askPIN(a.pin)
	if err != nil {
		return nil, err
	}
	defer clear(pin)
	p, err := createPrimary(t, tpm2.TPMRHOwner)
	if err != nil {
		return nil, err
	}
	defer flush(t, p.handle)
	key, err := loadKey(t, p, f.AuthorityTPM.Public, f.AuthorityTPM.Private)
	if err != nil {
		return nil, fmt.Errorf("the authority does not load in this TPM: %w", err)
	}
	defer flush(t, key.ObjectHandle)
	s, done, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, err
	}
	defer done()
	if err := runGate(t, s.Handle(), p, pPub, k, pin); err != nil {
		return nil, err
	}
	if _, err := (tpm2.PolicyCommandCode{PolicySession: s.Handle(), Code: tpm2.TPMCCSign}).Execute(t); err != nil {
		return nil, err
	}
	return sign(t, key, s, a.pub, digest, opts)
}

// counter is G as the file has it.
func (f *CA) counter() (tpm2.TPMSNVPublic, error) {
	if f.Counter == nil {
		return tpm2.TPMSNVPublic{}, errors.New("the CA has no counter")
	}
	pub, err := tpm2.Unmarshal[tpm2.TPMSNVPublic](f.Counter.Public)
	if err != nil {
		return tpm2.TPMSNVPublic{}, fmt.Errorf("the counter: %w", err)
	}
	return *pub, nil
}

// counterGoneError is a counter that is not the CA's: deleted, or
// replaced by another index.
type counterGoneError struct{ handle tpm2.TPMHandle }

func (e *counterGoneError) Error() string {
	return fmt.Sprintf("the counter at 0x%08X is not the CA's (deleted or replaced): the CA signs nothing until it is defined again (redefine the counter, with the PIN)", uint32(e.handle))
}

// Generation is the counter's value in the TPM: the generation whose
// approvals the CA signs with. It needs no PIN.
func (f *CA) Generation(t transport.TPM) (uint64, error) {
	pub, err := f.counter()
	if err != nil {
		return 0, err
	}
	_, name, err := persist.ReadNVPublic(t, pub.NVIndex)
	if err != nil || !bytes.Equal(name.Buffer, nvName(pub).Buffer) {
		return 0, &counterGoneError{pub.NVIndex}
	}
	return readCount(t, pub.NVIndex, name, tpm2.AuthHandle{Handle: pub.NVIndex, Name: name, Auth: tpm2.PasswordAuth(nil)})
}

// Sync sets the file's generation to the TPM's.
func (f *CA) Sync(t transport.TPM) error {
	g, err := f.Generation(t)
	if err != nil {
		return err
	}
	if g < f.Counter.Generation {
		return fmt.Errorf("the counter is at %d, below the file's %d: not the CA's counter", g, f.Counter.Generation)
	}
	f.Counter.Generation = g
	return nil
}

// incrementCounter increments G (as the TPM holds it now: written, or
// defined again and not yet) through P with pin.
func (f *CA) incrementCounter(t transport.TPM, p *primary, now tpm2.TPMSNVPublic, pin []byte) error {
	pPub, k, err := f.pinIndex()
	if err != nil {
		return err
	}
	s, done, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return err
	}
	defer done()
	if _, err := (tpm2.PolicyCommandCode{PolicySession: s.Handle(), Code: tpm2.TPMCCNVIncrement}).Execute(t); err != nil {
		return err
	}
	if err := runGate(t, s.Handle(), p, pPub, k, pin); err != nil {
		return err
	}
	name := nvName(now)
	_, err = tpm2.NVIncrement{
		AuthHandle: tpm2.AuthHandle{Handle: now.NVIndex, Name: name, Auth: s},
		NVIndex:    tpm2.NamedHandle{Handle: now.NVIndex, Name: name},
	}.Execute(t)
	return err
}

// NextGeneration increments the counter with the PIN: the CA no longer
// signs with an approval of the generations before, and the file is at
// the new one. A counter that was defined again alike and not yet
// incremented (by an attacker, or RedefineCounter) is incremented too: its
// value lands above every value the counter had.
func (f *CA) NextGeneration(t transport.TPM, pin PIN) error {
	gPub, err := f.counter()
	if err != nil {
		return err
	}
	if _, _, err := f.checkPINIndex(t); err != nil {
		return err
	}
	now, name, err := persist.ReadNVPublic(t, gPub.NVIndex)
	unwritten := gPub
	unwritten.Attributes.Written = false
	switch {
	case err != nil:
		return &counterGoneError{gPub.NVIndex}
	case bytes.Equal(name.Buffer, nvName(gPub).Buffer):
	case bytes.Equal(name.Buffer, nvName(unwritten).Buffer):
	default:
		return &counterGoneError{gPub.NVIndex}
	}
	b, err := askPIN(pin)
	if err != nil {
		return err
	}
	defer clear(b)
	p, err := createPrimary(t, tpm2.TPMRHOwner)
	if err != nil {
		return err
	}
	defer flush(t, p.handle)
	if err := f.incrementCounter(t, p, *now, b); err != nil {
		return err
	}
	return f.Sync(t)
}

// RedefineCounter defines the counter again at its handle, in place of
// whatever is there, and increments it with the PIN: the way back after
// the counter was deleted or replaced. Its Name is the old one; its value
// lands above every value it had, so no old approval works again. The PIN
// is checked before anything is removed.
func (f *CA) RedefineCounter(t transport.TPM, pin PIN) error {
	gPub, err := f.counter()
	if err != nil {
		return err
	}
	pPub, k, err := f.checkPINIndex(t)
	if err != nil {
		return err
	}
	b, err := askPIN(pin)
	if err != nil {
		return err
	}
	defer clear(b)
	p, err := createPrimary(t, tpm2.TPMRHOwner)
	if err != nil {
		return err
	}
	defer flush(t, p.handle)
	if err := checkGate(t, p, pPub, k, b); err != nil {
		return err
	}
	// Whatever is at the counter's handle goes, of any shape: the handle
	// is the CA's, and replacing what an attacker put there is what this
	// is for - with the PIN proven above, never without.
	if _, err := persist.RemoveNV(t, gPub.NVIndex, func(*tpm2.TPMSNVPublic, tpm2.TPM2BName) bool { return true }); err != nil {
		return fmt.Errorf("removing what is at 0x%08X: %w", uint32(gPub.NVIndex), err)
	}
	unwritten := gPub
	unwritten.Attributes.Written = false
	if _, err := (tpm2.NVDefineSpace{AuthHandle: tpm2.TPMRHOwner, PublicInfo: tpm2.New2B(unwritten)}).Execute(t); err != nil {
		return fmt.Errorf("defining the counter at 0x%08X: %w", uint32(gPub.NVIndex), err)
	}
	if err := f.incrementCounter(t, p, unwritten, b); err != nil {
		return err
	}
	return f.Sync(t)
}

// checkGate proves the PIN to P and nothing else: a wrong one counts.
func checkGate(t transport.TPM, p *primary, pub tpm2.TPMSNVPublic, k uint64, pin []byte) error {
	s, done, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return err
	}
	defer done()
	return runGate(t, s.Handle(), p, pub, k, pin)
}

// checkTPMAuthority makes sure the file's A, P and G are what CreatePINCA
// makes, so that a file edited by hand cannot choose weaker ones.
func (f *CA) checkTPMAuthority() error {
	if f.AuthorityTPM == nil {
		if f.Counter != nil {
			return errors.New("a counter without an authority in the TPM")
		}
		for _, a := range f.Approvals {
			if a.Generation != 0 {
				return errors.New("an approval of a generation, and no counter")
			}
		}
		return nil
	}
	pPub, k, err := f.pinIndex()
	if err != nil {
		return err
	}
	if err := ownerNVHandle(pPub.NVIndex); err != nil {
		return err
	}
	if !bytes.Equal(tpm2.Marshal(pPub), tpm2.Marshal(written(pinIndexPublic(pPub.NVIndex)))) {
		return errors.New("the PIN index is not one this CA makes")
	}
	aPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](f.AuthorityTPM.Public)
	if err != nil {
		return fmt.Errorf("the authority's public part: %w", err)
	}
	want, _ := keyTemplate(P256, authorityPolicy(pPub, k))
	want.Unique = aPub.Unique
	if !bytes.Equal(tpm2.Marshal(aPub), tpm2.Marshal(&want)) {
		return errors.New("the authority's key is not one this CA makes")
	}
	key, err := tpm2.Pub(*aPub)
	if err != nil {
		return fmt.Errorf("the authority's public part: %w", err)
	}
	ek, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("the authority is not an ECDSA key")
	}
	der, err := x509.MarshalPKIXPublicKey(ek)
	if err != nil || !bytes.Equal(der, f.Authority) {
		return errors.New("the authority's public key is not the TPM key's")
	}
	gPub, err := f.counter()
	if err != nil {
		return err
	}
	if err := ownerNVHandle(gPub.NVIndex); err != nil {
		return err
	}
	if gPub.NVIndex == pPub.NVIndex || !bytes.Equal(tpm2.Marshal(gPub), tpm2.Marshal(written(counterPublic(gPub.NVIndex, pPub, k)))) {
		return errors.New("the counter is not one this CA makes")
	}
	if f.Counter.Generation == 0 {
		return errors.New("a counter at generation 0")
	}
	for _, a := range f.Approvals {
		if a.Generation == 0 {
			return errors.New("an approval without a generation")
		}
	}
	return nil
}
