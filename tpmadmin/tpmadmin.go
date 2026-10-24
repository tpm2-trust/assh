// Package tpmadmin changes what the TPM itself holds for an authority with
// a PIN: the PIN, the dictionary attack parameters, the lockout
// authorization.
//
// It needs TPM2_NV_ChangeAuth and TPM2_DictionaryAttackLockReset, which
// go-tpm has only in the fork assh's go.mod names. A program that uses
// hostkey without this package builds with go-tpm as released.
//
// The dictionary attack parameters are the TPM's, not assh's: every
// object in the TPM that is not noDA shares them and the failure count -
// a volume unlocked with a TPM PIN, say.
package tpmadmin

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/tpm2-trust/assh/hostkey"
)

// DAState is the TPM's dictionary attack protection as it stands.
type DAState struct {
	Failures        uint32 // the authorization failures counted now
	MaxTries        uint32 // the failures that lock the TPM out
	Recovery        uint32 // seconds after which one failure is forgotten
	LockoutRecovery uint32 // seconds after a failed lockout authorization before the next try
	LockoutAuthSet  bool   // whether the lockout hierarchy has an authorization value
	InLockout       bool   // whether the TPM refuses every authorization of a DA-protected object now
}

// ReadDA reads the dictionary attack state. It needs no authorization.
func ReadDA(t transport.TPM) (DAState, error) {
	var s DAState
	props := map[tpm2.TPMPT]*uint32{
		tpm2.TPMPTLockoutCounter:  &s.Failures,
		tpm2.TPMPTMaxAuthFail:     &s.MaxTries,
		tpm2.TPMPTLockoutInterval: &s.Recovery,
		tpm2.TPMPTLockoutRecovery: &s.LockoutRecovery,
	}
	var permanent uint32
	props[tpm2.TPMPTPermanent] = &permanent
	for p, v := range props {
		rsp, err := tpm2.GetCapability{Capability: tpm2.TPMCapTPMProperties, Property: uint32(p), PropertyCount: 1}.Execute(t)
		if err != nil {
			return s, err
		}
		got, err := rsp.CapabilityData.Data.TPMProperties()
		if err != nil {
			return s, err
		}
		if len(got.TPMProperty) != 1 || got.TPMProperty[0].Property != p {
			return s, fmt.Errorf("the TPM does not report property 0x%08X", uint32(p))
		}
		*v = got.TPMProperty[0].Value
	}
	s.LockoutAuthSet = permanent&(1<<2) != 0
	s.InLockout = permanent&(1<<9) != 0
	return s, nil
}

// saltKey is a key to salt a session with, under the NULL hierarchy (no
// authorization needed); the caller flushes it.
func saltKey(t transport.TPM) (tpm2.TPMHandle, tpm2.TPMTPublic, error) {
	rsp, err := tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHNull, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}.Execute(t)
	if err != nil {
		return 0, tpm2.TPMTPublic{}, fmt.Errorf("the TPM's salt key: %w", err)
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(t)
		return 0, tpm2.TPMTPublic{}, err
	}
	return rsp.ObjectHandle, *pub, nil
}

// withLockout runs cmd with the lockout authorization proved in a salted
// HMAC session; with encrypt, the session encrypts the command's first
// parameter (a TPM2B: a new authorization value). Neither crosses the bus
// in the clear.
func withLockout(t transport.TPM, auth []byte, encrypt bool, cmd func(tpm2.AuthHandle) error) error {
	h, pub, err := saltKey(t)
	if err != nil {
		return err
	}
	defer tpm2.FlushContext{FlushHandle: h}.Execute(t)
	opts := []tpm2.AuthOption{tpm2.Auth(auth), tpm2.Salted(h, pub)}
	if encrypt {
		opts = append(opts, tpm2.AESEncryption(128, tpm2.EncryptIn))
	}
	err = cmd(tpm2.AuthHandle{Handle: tpm2.TPMRHLockout, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16, opts...)})
	switch {
	case errors.Is(err, tpm2.TPMRCLockout):
		return fmt.Errorf("the lockout authorization is locked after a wrong one: wait for the lockout recovery time: %w", err)
	case errors.Is(err, tpm2.TPMRCAuthFail), errors.Is(err, tpm2.TPMRCBadAuth):
		return fmt.Errorf("wrong lockout authorization: %w", err)
	}
	return err
}

// SetDA sets the dictionary attack parameters, for the whole TPM: after
// maxTries failures it refuses every DA-protected authorization; one
// failure is forgotten every recovery seconds; after a wrong lockout
// authorization the next try waits lockoutRecovery seconds.
func SetDA(t transport.TPM, lockoutAuth []byte, maxTries, recovery, lockoutRecovery uint32) error {
	return withLockout(t, lockoutAuth, false, func(a tpm2.AuthHandle) error {
		_, err := tpm2.DictionaryAttackParameters{
			AuthHandle:      a,
			MaxTries:        maxTries,
			RecoveryTime:    recovery,
			LockoutRecovery: lockoutRecovery,
		}.Execute(t)
		return err
	})
}

// ResetDA forgets every counted failure and ends a lockout.
func ResetDA(t transport.TPM, lockoutAuth []byte) error {
	return withLockout(t, lockoutAuth, false, func(a tpm2.AuthHandle) error {
		_, err := tpm2.DictionaryAttackLockReset{LockHandle: a}.Execute(t)
		return err
	})
}

// SetLockoutAuth changes the lockout authorization from old to new. Keep
// new off the machine: with it, anyone can reset the lockout, set the
// parameters and clear the TPM (which destroys every CA in it).
func SetLockoutAuth(t transport.TPM, old, new []byte) error {
	if len(new) == 0 {
		return errors.New("an empty lockout authorization protects nothing")
	}
	return withLockout(t, old, true, func(a tpm2.AuthHandle) error {
		_, err := tpm2.HierarchyChangeAuth{AuthHandle: a, NewAuth: tpm2.TPM2BAuth{Buffer: new}}.Execute(t)
		return err
	})
}

// ChangePIN changes the PIN of a CA's authority in the TPM, in place
// (TPM2_NV_ChangeAuth on the PIN index): the old PIN opens nothing
// afterwards, and the CA, its approvals and the file stay as they are. A
// wrong old PIN counts as a failure.
func ChangePIN(t transport.TPM, ca *hostkey.CA, old, new hostkey.PIN) error {
	p, err := ca.CheckPINIndex(t)
	if err != nil {
		return err
	}
	o, err := old()
	if err != nil {
		return err
	}
	defer clear(o)
	if err := hostkey.CheckPIN(o); err != nil {
		return err
	}
	n, err := new()
	if err != nil {
		return err
	}
	defer clear(n)
	if err := hostkey.CheckPIN(n); err != nil {
		return fmt.Errorf("the new PIN: %w", err)
	}
	name, err := tpm2.NVName(&p)
	if err != nil {
		return err
	}
	h, pub, err := saltKey(t)
	if err != nil {
		return err
	}
	defer tpm2.FlushContext{FlushHandle: h}.Execute(t)
	// The old PIN goes into the session's HMACs (PolicyAuthValue), the new
	// one is the encrypted parameter.
	s, done, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16, tpm2.Auth(o),
		tpm2.Salted(h, pub), tpm2.AESEncryption(128, tpm2.EncryptIn))
	if err != nil {
		return err
	}
	defer done()
	if _, err := (tpm2.PolicyCommandCode{PolicySession: s.Handle(), Code: tpm2.TPMCCNVChangeAuth}).Execute(t); err != nil {
		return err
	}
	if _, err := (tpm2.PolicyAuthValue{PolicySession: s.Handle()}).Execute(t); err != nil {
		return err
	}
	if _, err := (tpm2.PolicyOr{PolicySession: s.Handle(), PHashList: hostkey.PINIndexBranches()}).Execute(t); err != nil {
		return err
	}
	_, err = tpm2.NVChangeAuth{
		NVIndex: tpm2.AuthHandle{Handle: p.NVIndex, Name: *name, Auth: s},
		NewAuth: tpm2.TPM2BAuth{Buffer: n},
	}.Execute(t)
	switch {
	case errors.Is(err, tpm2.TPMRCLockout):
		return hostkey.ErrLockedOut
	case errors.Is(err, tpm2.TPMRCAuthFail), errors.Is(err, tpm2.TPMRCBadAuth):
		return hostkey.ErrWrongPIN
	}
	return err
}
