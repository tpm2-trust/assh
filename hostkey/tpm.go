package hostkey

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"
)

// primaryTemplate is the storage key the keys here are children of: the
// TCG's ECC P-256 storage root template, created again on every use and
// never persisted. Under the owner hierarchy it is the same in every boot
// (the CA); under the NULL hierarchy it changes with every reboot (the
// host keys).
func primaryTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{
				Algorithm: tpm2.TPMAlgAES,
				KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
				Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
			},
			Scheme:  tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
			CurveID: tpm2.TPMECCNistP256,
		}),
	}
}

type primary struct {
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
	public tpm2.TPMTPublic
}

func createPrimary(t transport.TPM, hierarchy tpm2.TPMHandle) (*primary, error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: hierarchy,
		InPublic:      tpm2.New2B(primaryTemplate()),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("the TPM's storage key: %w", err)
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		flush(t, rsp.ObjectHandle)
		return nil, err
	}
	return &primary{handle: rsp.ObjectHandle, name: rsp.Name, public: *pub}, nil
}

func flush(t transport.TPM, h tpm2.TPMHandle) {
	tpm2.FlushContext{FlushHandle: h}.Execute(t)
}

// keyTemplate is a signing key made in the TPM and never exported. The CA
// is used through its policy alone; a host key with its authorization
// value (noDA: 32 random bytes are no guess worth locking the TPM over).
func keyTemplate(typ Type, policy []byte) (tpm2.TPMTPublic, error) {
	attrs := tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		SignEncrypt:         true,
	}
	if policy == nil {
		attrs.UserWithAuth = true
		attrs.NoDA = true
	}
	t := tpm2.TPMTPublic{NameAlg: tpm2.TPMAlgSHA256, ObjectAttributes: attrs, AuthPolicy: tpm2.TPM2BDigest{Buffer: policy}}
	switch typ {
	case P256:
		t.Type = tpm2.TPMAlgECC
		t.Parameters = tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme:  tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
			CurveID: tpm2.TPMECCNistP256,
		})
	case RSA2048:
		t.Type = tpm2.TPMAlgRSA
		t.Parameters = tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Scheme:  tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},
			KeyBits: 2048,
		})
	default:
		return tpm2.TPMTPublic{}, fmt.Errorf("unknown key type %q", typ)
	}
	return t, nil
}

// createKey makes a key under p, with auth as its authorization value. The
// value goes to the TPM in a salted session with its parameters encrypted,
// so nothing on the bus reads it.
func createKey(t transport.TPM, p *primary, tmpl tpm2.TPMTPublic, auth []byte) (*tpm2.CreateResponse, error) {
	return tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: p.handle, Name: p.name,
			Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Salted(p.handle, p.public), tpm2.AESEncryption(128, tpm2.EncryptIn))},
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			UserAuth: tpm2.TPM2BAuth{Buffer: auth},
		}},
		InPublic: tpm2.New2B(tmpl),
	}.Execute(t)
}

// CreateCA makes a new CA in the TPM, bound to pcrs in bank: it signs while
// they hold values authority approved. policyRef ties the authority's
// signatures to this CA's use ("assh boot", say): an approval made for a CA
// with another reference does not let this one sign. The CA has no
// approval yet: Approve adds them.
func CreateCA(t transport.TPM, typ Type, bank Bank, pcrs []int, authority crypto.PublicKey, policyRef []byte) (*CA, error) {
	if len(pcrs) == 0 {
		return nil, errors.New("the CA is bound to no PCR")
	}
	pcrs = append([]int(nil), pcrs...)
	sort.Ints(pcrs)
	if len(policyRef) > 32 {
		return nil, errors.New("a policy reference of more than 32 bytes")
	}
	policy, err := caPolicy(authority, policyRef)
	if err != nil {
		return nil, err
	}
	tmpl, err := keyTemplate(typ, policy)
	if err != nil {
		return nil, err
	}
	authorityDER, err := x509.MarshalPKIXPublicKey(authority)
	if err != nil {
		return nil, err
	}
	// The TPM must be able to check the authority's signatures later.
	at, _ := authorityTemplate(authority)
	ext, err := tpm2.LoadExternal{InPublic: tpm2.New2B(at), Hierarchy: tpm2.TPMRHOwner}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("this TPM does not take the authority's key: %w", err)
	}
	flush(t, ext.ObjectHandle)

	p, err := createPrimary(t, tpm2.TPMRHOwner)
	if err != nil {
		return nil, err
	}
	defer flush(t, p.handle)
	key, err := createKey(t, p, tmpl, nil)
	if err != nil {
		return nil, fmt.Errorf("creating the %s CA in the TPM: %w", typ, err)
	}
	pub, err := key.OutPublic.Contents()
	if err != nil {
		return nil, err
	}
	return &CA{
		Version: fileVersion, Type: typ, Bank: bank, PCRs: pcrs,
		Public: tpm2.Marshal(pub), Private: key.OutPrivate.Buffer,
		Authority: authorityDER, PolicyRef: append([]byte(nil), policyRef...),
	}, nil
}

// ReadPCRs reads the CA's PCRs as the TPM holds them now.
func (f *CA) ReadPCRs(t transport.TPM) (map[int][]byte, error) {
	return ReadPCRs(t, f.Bank, f.PCRs)
}

// ReadPCRs reads PCRs of a bank, one at a time (a TPM answers only so
// many in one read).
func ReadPCRs(t transport.TPM, bank Bank, pcrs []int) (map[int][]byte, error) {
	out := map[int][]byte{}
	for _, i := range pcrs {
		rsp, err := tpm2.PCRRead{PCRSelectionIn: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash: bank.alg(), PCRSelect: pcrBitmap([]int{i}),
		}}}}.Execute(t)
		if err != nil {
			return nil, fmt.Errorf("reading PCR %d: %w", i, err)
		}
		if len(rsp.PCRValues.Digests) != 1 {
			return nil, fmt.Errorf("the TPM has no %s bank for PCR %d", bank, i)
		}
		out[i] = rsp.PCRValues.Digests[0].Buffer
	}
	return out, nil
}

// MismatchError is a CA that may not sign: no approval for what the PCRs
// hold.
type MismatchError struct {
	Changed []int // the PCRs that differ from the closest approval; all of them without one
	None    bool  // there is no approval at all
}

func (e *MismatchError) Error() string {
	if e.None {
		return "the CA has no approved PCR state"
	}
	return PCRList(e.Changed) + " not as approved"
}

// mismatch names the PCRs that differ from the closest approval.
func (f *CA) mismatch(now map[int][]byte) error {
	if len(f.Approvals) == 0 {
		return &MismatchError{None: true, Changed: f.PCRs}
	}
	var best []int
	for _, a := range f.Approvals {
		var changed []int
		for _, i := range f.PCRs {
			if !bytes.Equal(a.PCRs[i], now[i]) {
				changed = append(changed, i)
			}
		}
		if best == nil || len(changed) < len(best) {
			best = changed
		}
	}
	return &MismatchError{Changed: best}
}

// caSigner signs with the CA through the approval of the PCR values the
// TPM holds: a crypto.Signer for one certificate.
type caSigner struct {
	t        transport.TPM
	ca       *CA
	approval *Approval
	pub      crypto.PublicKey
}

func (s *caSigner) Public() crypto.PublicKey { return s.pub }

func (s *caSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	f, t := s.ca, s.t
	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](s.approval.Signature)
	if err != nil {
		return nil, fmt.Errorf("the approval's signature: %w", err)
	}
	approved, err := f.approvedPolicy(s.approval.PCRs)
	if err != nil {
		return nil, err
	}
	adigest, err := f.ApprovalDigest(s.approval.PCRs)
	if err != nil {
		return nil, err
	}
	authority, err := f.authorityKey()
	if err != nil {
		return nil, err
	}
	at, _ := authorityTemplate(authority)
	p, err := createPrimary(t, tpm2.TPMRHOwner)
	if err != nil {
		return nil, err
	}
	defer flush(t, p.handle)
	key, err := loadKey(t, p, f.Public, f.Private)
	if err != nil {
		return nil, fmt.Errorf("the CA does not load in this TPM: %w", err)
	}
	defer flush(t, key.ObjectHandle)
	// The ticket must come from a key in a real hierarchy: PolicyAuthorize
	// refuses the NULL ticket of a NULL-hierarchy key.
	ext, err := tpm2.LoadExternal{InPublic: tpm2.New2B(at), Hierarchy: tpm2.TPMRHOwner}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("loading the authority's key: %w", err)
	}
	defer flush(t, ext.ObjectHandle)
	ticket, err := tpm2.VerifySignature{
		KeyHandle: ext.ObjectHandle,
		Digest:    tpm2.TPM2BDigest{Buffer: adigest},
		Signature: *sig,
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("the TPM does not accept the approval's signature: %w", err)
	}
	session := tpm2.Policy(tpm2.TPMAlgSHA256, 16, func(tpm transport.TPM, h tpm2.TPMISHPolicy, _ tpm2.TPM2BNonce) error {
		if _, err := (tpm2.PolicyPCR{PolicySession: h, Pcrs: f.pcrSelection()}).Execute(tpm); err != nil {
			return err
		}
		_, err := tpm2.PolicyAuthorize{
			PolicySession:  h,
			ApprovedPolicy: tpm2.TPM2BDigest{Buffer: approved},
			PolicyRef:      tpm2.TPM2BDigest{Buffer: f.PolicyRef},
			KeySign:        ext.Name,
			CheckTicket:    ticket.Validation,
		}.Execute(tpm)
		return err
	})
	out, err := sign(t, key, session, s.pub, digest, opts)
	if err != nil {
		// The PCRs moved between the read and the signature.
		if again, rerr := f.ReadPCRs(t); rerr == nil && f.Approved(again) == nil {
			return nil, f.mismatch(again)
		}
		return nil, fmt.Errorf("the CA's signature: %w", err)
	}
	return out, nil
}

func loadKey(t transport.TPM, p *primary, public, private []byte) (*tpm2.LoadResponse, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](public)
	if err != nil {
		return nil, err
	}
	return tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: p.handle, Name: p.name, Auth: tpm2.PasswordAuth(nil)},
		InPublic:     tpm2.New2B(*pub),
		InPrivate:    tpm2.TPM2BPrivate{Buffer: private},
	}.Execute(t)
}

// IssueOptions shape the host key Issue makes.
type IssueOptions struct {
	// Type of the host key; default P-256.
	Type Type
	// Principals are the host names the certificate is valid for, as a
	// client names the host; "*" is any (the client's known_hosts pattern
	// still chooses the hosts). OpenSSH refuses a host certificate
	// without one; default "*".
	Principals []string
	// KeyID names the certificate in the client's logs.
	KeyID string
	// Open opens the TPM for each of the host key's signatures.
	Open func() (transport.TPMCloser, error)
}

// HostKey is a host key of this boot and its certificate.
type HostKey struct {
	Signer *Signer          // the key in the TPM
	Cert   *ssh.Certificate // the CA's certificate for it
	ssh    ssh.Signer       // both, as the server presents them
}

// SSH is the host key as an SSH server presents it: the certificate, and
// the key that signs the key exchange.
func (h *HostKey) SSH() ssh.Signer { return h.ssh }

// Fingerprint is the host key's own fingerprint.
func (h *HostKey) Fingerprint() string { return ssh.FingerprintSHA256(h.Cert.Key) }

// Issue makes this boot's host key in the TPM and has the CA certify it:
// only while the PCRs hold an approved state (else a *MismatchError). The
// key lives under the TPM's NULL hierarchy: it works until the next
// reboot, from any PCR state, and never after.
func Issue(t transport.TPM, ca *CA, o IssueOptions) (*HostKey, error) {
	if o.Type == "" {
		o.Type = P256
	}
	if len(o.Principals) == 0 {
		o.Principals = []string{"*"}
	}
	if o.Open == nil {
		return nil, errors.New("no way to open the TPM for the host key")
	}
	now, err := ca.ReadPCRs(t)
	if err != nil {
		return nil, err
	}
	a := ca.Approved(now)
	if a == nil {
		return nil, ca.mismatch(now)
	}
	caPub, err := ca.PublicKey()
	if err != nil {
		return nil, err
	}
	caSSH, err := SSHSigner(&caSigner{t: t, ca: ca, approval: a, pub: caPub})
	if err != nil {
		return nil, err
	}

	tmpl, err := keyTemplate(o.Type, nil)
	if err != nil {
		return nil, err
	}
	auth := make([]byte, 32)
	if _, err := rand.Read(auth); err != nil {
		return nil, err
	}
	p, err := createPrimary(t, tpm2.TPMRHNull)
	if err != nil {
		return nil, err
	}
	key, err := createKey(t, p, tmpl, auth)
	flush(t, p.handle)
	if err != nil {
		return nil, fmt.Errorf("creating the host key in the TPM: %w", err)
	}
	pub, err := key.OutPublic.Contents()
	if err != nil {
		return nil, err
	}
	signer, err := newSigner(tpm2.Marshal(pub), key.OutPrivate.Buffer, auth, o.Open)
	if err != nil {
		return nil, err
	}
	hostSSH, err := SSHSigner(signer)
	if err != nil {
		return nil, err
	}
	serial := make([]byte, 8)
	rand.Read(serial)
	cert := &ssh.Certificate{
		Key:             hostSSH.PublicKey(),
		Serial:          binary.BigEndian.Uint64(serial),
		CertType:        ssh.HostCert,
		KeyId:           o.KeyID,
		ValidPrincipals: o.Principals,
		// The key dies with the boot; the certificate needs no end, and
		// no clock is trusted for its start.
		ValidAfter:  0,
		ValidBefore: ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, caSSH); err != nil {
		var m *MismatchError
		if errors.As(err, &m) {
			return nil, m
		}
		return nil, err
	}
	certSigner, err := ssh.NewCertSigner(cert, hostSSH)
	if err != nil {
		return nil, err
	}
	return &HostKey{Signer: signer, Cert: cert, ssh: certSigner}, nil
}

// Close extends pcr with event in every bank (TPM2_PCR_Event): what is
// approved for the value it held cannot be signed by the CA again until
// the next boot. A server calls it right after its Issue.
func Close(t transport.TPM, pcr int, event string) error {
	if pcr < 0 || pcr > 23 {
		return fmt.Errorf("not a PCR index: %d", pcr)
	}
	if pcr == 16 || pcr == 23 {
		// Resettable from locality 0: a reset reopens the window.
		return fmt.Errorf("PCR %d can be reset by any process: it closes nothing", pcr)
	}
	_, err := tpm2.PCREvent{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(pcr), Auth: tpm2.PasswordAuth(nil)},
		EventData: tpm2.TPM2BEvent{Buffer: []byte(event)},
	}.Execute(t)
	if err != nil {
		return fmt.Errorf("extending PCR %d: %w", pcr, err)
	}
	return nil
}

// Describe is the CA in a few lines, for a person.
func (f *CA) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s CA held in the TPM, %s\n", f.Type, f.Fingerprint())
	fmt.Fprintf(&b, "signs while %s (%s) hold an approved state; %d approved\n", PCRList(f.PCRs), f.Bank, len(f.Approvals))
	return b.String()
}
