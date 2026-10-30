// Package hostkey gives an SSH server a host key that lives in the TPM and
// a certificate for it, made fresh at every boot.
//
// The long-term key is a certificate authority (CA): ECDSA P-256 or
// RSA-2048, created inside the TPM, never exported - the CA file holds
// only the TPM's wrapped copy, which loads in this TPM alone. Its use has
// no password: its policy is a PCR state an authority key approved
// (TPM2_PolicyAuthorize over a PolicyPCR). The authority signs an approval
// for every state the CA may sign in - after a firmware update, say - so
// the CA and the clients' trust in it stay the same for its whole life.
// The CA's policy names no PCR, so it has up to 16 slots, each a PCR
// selection with approvals of its own; Issue takes the first slot, from 0
// up, approved for the PCRs as they are. What follows the PolicyAuthorize
// in the CA's policy is its own, beyond any approval: it signs and does
// nothing else, and only while its window is open (window.go).
//
// The authority is a key elsewhere (a file, a token: CreateCA), whose
// private key never comes to the TPM, or a key made in this TPM and opened
// by a PIN alone, with no PCR condition (CreatePINCA). The second comes
// with a counter in the TPM that every approval names: incrementing it
// (NextGeneration) revokes every approval made before. Either way an
// approval is a signature, kept in the CA file, that the TPM checks each
// time the CA signs. The CA file may be an EFI variable ("efi:NAME",
// efivar.go).
//
// At its start a server asks for a host key (Issue): the TPM makes a new
// one under its NULL hierarchy, whose seed changes at every reboot, and
// the CA certifies it - while the PCRs hold a state approved in a slot.
// When none is, the key is temporary: not certified, so a client that
// trusts the CA asks before it takes it. The host key signs every key
// exchange of this boot, whatever the PCRs hold later; at the next reboot
// it is gone for good. Once the window is closed - the CA's window index
// read-locked right after the Issue (Close), which the CA's own policy
// reads - the CA signs nothing until the next boot, whatever an approval
// says, so a server started later, or any other process, gets no
// certificate.
//
// Nothing here is a secret outside the TPM, and no secret ever leaves it.
// So a cleared TPM, or another one, loses the CA: there is no backup of it,
// and a new CA means a new known_hosts line on every client.
// Clients trust the CA, not a key: a known_hosts line
//
//	@cert-authority <hosts> <the CA's public key>
package hostkey

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/tpm2-trust/assh/persist"
	"golang.org/x/crypto/ssh"
)

// Type is the kind of key in the TPM.
type Type string

const (
	P256    Type = "p256"    // ECDSA on NIST P-256, ssh's ecdsa-sha2-nistp256
	RSA2048 Type = "rsa2048" // RSA with 2048 bits, ssh's rsa-sha2-256
)

// ParseType reads a type as a person writes it, or a list of them in order
// of preference ("rsa2048,p256"): a key is made with the first the TPM
// accepts (ResolveType).
func ParseType(s string) (Type, error) {
	var out []string
	for _, p := range strings.Split(s, ",") {
		var t Type
		switch strings.ToLower(strings.TrimSpace(p)) {
		case "p256", "p-256", "ecdsa", "nistp256":
			t = P256
		case "rsa2048", "rsa-2048", "rsa":
			t = RSA2048
		default:
			return "", fmt.Errorf("unknown key type %q (p256 or rsa2048, or a list of them)", p)
		}
		if !slices.Contains(out, string(t)) {
			out = append(out, string(t))
		}
	}
	return Type(strings.Join(out, ",")), nil
}

// Choices are the types of t, a list's in order.
func (t Type) Choices() []Type {
	var out []Type
	for _, p := range strings.Split(string(t), ",") {
		out = append(out, Type(p))
	}
	return out
}

// Bank is a PCR bank the CA's policy reads.
type Bank string

const (
	SHA256 Bank = "sha256"
	SHA1   Bank = "sha1"
	// Auto is SHA-256 where the TPM has it active, else SHA-1 where the TPM
	// allows it (ResolveBank); a CA is made with the bank it resolves to.
	Auto Bank = "auto"
)

// ParseBank reads a bank name.
func ParseBank(s string) (Bank, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "sha256", "":
		return SHA256, nil
	case "sha1":
		return SHA1, nil
	case "auto":
		return Auto, nil
	}
	return "", fmt.Errorf("unknown PCR bank %q (sha256, sha1 or auto)", s)
}

func (b Bank) alg() tpm2.TPMAlgID {
	if b == SHA1 {
		return tpm2.TPMAlgSHA1
	}
	return tpm2.TPMAlgSHA256
}

func (b Bank) size() int {
	if b == SHA1 {
		return 20
	}
	return 32
}

// fileVersion is the one format read; another is an error that says to
// create the CA again.
const fileVersion = 4

// MaxSlots is how many slots a CA has room for: 0 to MaxSlots-1.
const MaxSlots = 16

// CA is the certificate authority: the TPM's wrapped copy of its key, the
// authority that approves the PCR states it signs in, its slots and their
// approvals. Nothing in it is a secret outside this TPM.
type CA struct {
	Version int  `json:"version"`
	Type    Type `json:"type"`
	// Bank is the PCR bank every slot reads.
	Bank Bank `json:"bank"`
	// Slots are the PCR selections approvals are made for, in the order
	// Issue scans them: the lowest number first.
	Slots []Slot `json:"slots"`
	// Window is W, the NV index whose read lock closes the CA for the
	// rest of the boot (Close); the CA's own policy reads it.
	Window *Window `json:"window"`

	Public  []byte `json:"public"`  // the CA key's TPMT_PUBLIC
	Private []byte `json:"private"` // its TPM2B_PRIVATE buffer

	Authority []byte `json:"authority"`  // the authority's public key, PKIX DER
	PolicyRef []byte `json:"policy_ref"` // what its signatures are bound to

	// AuthorityTPM is the authority when it is a key in this TPM, opened
	// by a PIN; nil for a key elsewhere.
	AuthorityTPM *TPMAuthority `json:"authority_tpm,omitempty"`
	// Counter is the counter every approval names; with AuthorityTPM only.
	Counter *Counter `json:"counter,omitempty"`

	Approvals []Approval `json:"approvals,omitempty"`
}

// Slot is a PCR selection the authority approves states of. The CA's
// policy names no PCR, so a slot needs no key of its own: it is worth
// nothing until the authority approves a state in it.
type Slot struct {
	Number int     `json:"slot"`
	PCRs   []int   `json:"pcrs"`
	Signed *Signed `json:"signed,omitempty"` // PCRs a key elsewhere signs, besides the approved ones
}

// Approval is a PCR state of a slot the authority signed: the CA signs
// while the slot's PCRs hold these values - and, with a counter, while it
// holds Generation.
type Approval struct {
	Slot       int            `json:"slot"`
	PCRs       map[int][]byte `json:"pcrs"`
	Generation uint64         `json:"generation,omitempty"` // the counter's value; 0 without one
	Signature  []byte         `json:"signature"`            // TPMT_SIGNATURE over ApprovalDigest
}

// Equal is whether b is the same approval: the same slot, values and
// generation, signed alike.
func (a Approval) Equal(b *Approval) bool {
	if b == nil || a.Slot != b.Slot || len(a.PCRs) != len(b.PCRs) || a.Generation != b.Generation || string(a.Signature) != string(b.Signature) {
		return false
	}
	for i, v := range a.PCRs {
		if string(b.PCRs[i]) != string(v) {
			return false
		}
	}
	return true
}

// LoadCA reads a CA file, or the EFI variable "efi:NAME".
func LoadCA(path string) (*CA, error) {
	var data []byte
	var err error
	if persist.IsVar(path) {
		data, err = persist.ReadVar(path)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	f, err := ParseCA(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// ParseCA reads a CA file's contents.
func ParseCA(data []byte) (*CA, error) {
	var f CA
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("not a CA file: %w", err)
	}
	if f.Version != fileVersion {
		return nil, fmt.Errorf("a CA file of version %d, not %d: create the CA again", f.Version, fileVersion)
	}
	if f.Type != P256 && f.Type != RSA2048 {
		return nil, fmt.Errorf("unknown key type %q", f.Type)
	}
	if f.Bank != SHA256 && f.Bank != SHA1 {
		return nil, fmt.Errorf("unknown PCR bank %q", f.Bank)
	}
	if err := f.checkSlots(); err != nil {
		return nil, err
	}
	if _, err := f.PublicKey(); err != nil {
		return nil, err
	}
	if err := f.checkTPMAuthority(); err != nil {
		return nil, err
	}
	if _, err := f.authorityKey(); err != nil {
		return nil, err
	}
	// The key's policy is what the file says the CA is: its authority, its
	// ref, its window.
	policy, err := f.caPolicy()
	if err != nil {
		return nil, err
	}
	if pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](f.Public); err != nil || !bytes.Equal(pub.AuthPolicy.Buffer, policy) {
		return nil, errors.New("the CA's key does not carry the policy of the authority, reference and window the file names")
	}
	return &f, nil
}

// Marshal is the file's contents.
func (f *CA) Marshal() ([]byte, error) {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Save writes the file, readable by its owner alone, in place of what is
// at path: written beside it and renamed, so a reader never sees half. An
// EFI variable ("efi:NAME") is written compact, in one piece.
func (f *CA) Save(path string) error {
	if persist.IsVar(path) {
		b, err := json.Marshal(f)
		if err != nil {
			return err
		}
		return persist.WriteVar(path, b)
	}
	b, err := f.Marshal()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Only is a copy with the approvals keep says yes to: what a boot image
// carries of the CA, say.
func (f *CA) Only(keep func(Approval) bool) *CA {
	c := *f
	c.Approvals = nil
	for _, a := range f.Approvals {
		if keep(a) {
			c.Approvals = append(c.Approvals, a)
		}
	}
	return &c
}

// PublicKey is the CA's public key (*ecdsa.PublicKey or *rsa.PublicKey).
func (f *CA) PublicKey() (crypto.PublicKey, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](f.Public)
	if err != nil {
		return nil, fmt.Errorf("the CA's public part: %w", err)
	}
	k, err := tpm2.Pub(*pub)
	if err != nil {
		return nil, fmt.Errorf("the CA's public part: %w", err)
	}
	return k, nil
}

// SSHPublicKey is the CA as ssh names it.
func (f *CA) SSHPublicKey() (ssh.PublicKey, error) {
	k, err := f.PublicKey()
	if err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(k)
}

// Fingerprint is the CA's SHA256 fingerprint as ssh prints it.
func (f *CA) Fingerprint() string {
	k, err := f.SSHPublicKey()
	if err != nil {
		return "?"
	}
	return ssh.FingerprintSHA256(k)
}

// AuthorizedKey is the CA's public key in OpenSSH's one-line format, for
// a .pub file.
func (f *CA) AuthorizedKey() ([]byte, error) {
	k, err := f.SSHPublicKey()
	if err != nil {
		return nil, err
	}
	return ssh.MarshalAuthorizedKey(k), nil
}

// KnownHosts is the known_hosts line that makes a client trust the CA's
// certificates for hosts (a pattern: "*", "host.example,192.0.2.10").
func (f *CA) KnownHosts(hosts string) (string, error) {
	k, err := f.AuthorizedKey()
	if err != nil {
		return "", err
	}
	return "@cert-authority " + hosts + " " + strings.TrimSpace(string(k)), nil
}

// FileGeneration is the generation the file is at: the one Approve signs for.
// 0 without a counter. The TPM's counter decides what the CA signs
// (Generation, Sync).
func (f *CA) FileGeneration() uint64 {
	if f.Counter == nil {
		return 0
	}
	return f.Counter.Generation
}

// Approved is the approval that lets the CA sign when the PCRs hold
// values, at the file's generation: the first slot's that has one, nil
// when there is none. A slot with signed PCRs counts only where sigs has
// the signature of their values.
func (f *CA) Approved(values map[int][]byte, sigs PCRSignatures) *Approval {
	return f.approvedAt(values, f.FileGeneration(), sigs)
}

// approvedAt scans the slots from the lowest number up.
func (f *CA) approvedAt(values map[int][]byte, gen uint64, sigs PCRSignatures) *Approval {
	for _, s := range f.Slots {
		if !f.signedMet(&s, values, sigs) {
			continue
		}
		for i := range f.Approvals {
			a := &f.Approvals[i]
			if a.Slot == s.Number && a.Generation == gen && sameValues(s.PCRs, a.PCRs, values) {
				return a
			}
		}
	}
	return nil
}

func sameValues(pcrs []int, a, b map[int][]byte) bool {
	for _, i := range pcrs {
		if string(a[i]) != string(b[i]) || len(a[i]) == 0 {
			return false
		}
	}
	return true
}

// Slot is slot n, nil when the CA has none of that number.
func (f *CA) Slot(n int) *Slot {
	for i := range f.Slots {
		if f.Slots[i].Number == n {
			return &f.Slots[i]
		}
	}
	return nil
}

// PCRs are the PCRs any slot reads, in index order: what a server records
// of a boot, for an approval in any slot.
func (f *CA) PCRs() []int {
	seen := map[int]bool{}
	var out []int
	for _, s := range f.Slots {
		pcrs := s.PCRs
		if s.Signed != nil {
			pcrs = append(slices.Clone(pcrs), s.Signed.PCRs...)
		}
		for _, p := range pcrs {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Ints(out)
	return out
}

// SetSigned gives slot n PCRs a key elsewhere signs (nil: none). Its
// approvals go: they named the key.
func (f *CA) SetSigned(n int, s *Signed) error {
	i := slices.IndexFunc(f.Slots, func(x Slot) bool { return x.Number == n })
	if i < 0 {
		return fmt.Errorf("no slot %d", n)
	}
	if s != nil && slices.ContainsFunc(s.PCRs, func(p int) bool { return slices.Contains(f.Slots[i].PCRs, p) }) {
		return fmt.Errorf("slot %d reads %s itself: a PCR is approved or signed, not both", n, PCRList(f.Slots[i].PCRs))
	}
	f.Slots[i].Signed = s
	f.Approvals = slices.DeleteFunc(f.Approvals, func(a Approval) bool { return a.Slot == n })
	return nil
}

// AddSlot gives the CA slot n, reading pcrs. It needs no authority: the
// slot lets the CA sign nothing until the authority approves a state in
// it. pcrs must differ from every other slot's.
func (f *CA) AddSlot(n int, pcrs []int) error {
	if f.Slot(n) != nil {
		return fmt.Errorf("slot %d is in use", n)
	}
	s, err := newSlot(n, pcrs)
	if err != nil {
		return err
	}
	for _, o := range f.Slots {
		if slices.Equal(o.PCRs, s.PCRs) {
			return fmt.Errorf("slot %d reads %s already", o.Number, PCRList(s.PCRs))
		}
	}
	f.Slots = append(f.Slots, s)
	sort.Slice(f.Slots, func(i, j int) bool { return f.Slots[i].Number < f.Slots[j].Number })
	return nil
}

func newSlot(n int, pcrs []int) (Slot, error) {
	if n < 0 || n >= MaxSlots {
		return Slot{}, fmt.Errorf("slot %d: the slots are 0 to %d", n, MaxSlots-1)
	}
	pcrs = slices.Clone(pcrs)
	sort.Ints(pcrs)
	if err := checkSelection(pcrs); err != nil {
		return Slot{}, fmt.Errorf("slot %d: %w", n, err)
	}
	return Slot{Number: n, PCRs: pcrs}, nil
}

// checkSelection makes sure pcrs are PCRs, each once, in order.
func checkSelection(pcrs []int) error {
	if len(pcrs) == 0 {
		return errors.New("no PCR")
	}
	for i, p := range pcrs {
		if p < 0 || p > 23 || (i > 0 && pcrs[i-1] >= p) {
			return fmt.Errorf("not a PCR selection: %v", pcrs)
		}
	}
	return nil
}

// checkSlots makes sure the file's slots and approvals fit together.
func (f *CA) checkSlots() error {
	if _, err := f.window(); err != nil {
		return err
	}
	if len(f.Slots) == 0 {
		return errors.New("the CA has no slot")
	}
	for i, s := range f.Slots {
		if i > 0 && f.Slots[i-1].Number >= s.Number {
			return errors.New("the slots are not in order")
		}
		if err := checkSelection(s.PCRs); err != nil {
			return fmt.Errorf("slot %d: %w", s.Number, err)
		}
		if _, err := newSlot(s.Number, s.PCRs); err != nil {
			return err
		}
		if s.Signed != nil {
			if _, err := s.Signed.key(); err != nil {
				return fmt.Errorf("slot %d: %w", s.Number, err)
			}
			if checkSelection(s.Signed.PCRs) != nil || slices.ContainsFunc(s.Signed.PCRs, func(p int) bool { return slices.Contains(s.PCRs, p) }) {
				return fmt.Errorf("slot %d: its signed PCRs are no selection apart from its approved ones", s.Number)
			}
		}
	}
	for _, a := range f.Approvals {
		s := f.Slot(a.Slot)
		if s == nil {
			return fmt.Errorf("an approval for slot %d, which the CA does not have", a.Slot)
		}
		if err := f.checkValues(s, a.PCRs); err != nil || len(a.PCRs) != len(s.PCRs) {
			return fmt.Errorf("an approval for slot %d with other PCRs than the slot's", a.Slot)
		}
	}
	return nil
}

// checkValues makes sure values has one value of the bank's size for each
// of the slot's PCRs; values for other PCRs are no part of it.
func (f *CA) checkValues(s *Slot, values map[int][]byte) error {
	for _, i := range s.PCRs {
		v, ok := values[i]
		if !ok {
			return fmt.Errorf("no value for PCR %d (slot %d reads %s)", i, s.Number, PCRList(s.PCRs))
		}
		if len(v) != f.Bank.size() {
			return fmt.Errorf("PCR %d: %d bytes, a %s value has %d", i, len(v), f.Bank, f.Bank.size())
		}
	}
	return nil
}

// Numbers is "0,7,15", as assh.conf and the flags write PCRs and slots.
func Numbers(n []int) string {
	s := make([]string, len(n))
	for i, v := range n {
		s[i] = strconv.Itoa(v)
	}
	return strings.Join(s, ",")
}

// PCRList is "PCR 0, 7 and 15".
func PCRList(pcrs []int) string {
	s := strings.Split(Numbers(pcrs), ",")
	switch len(pcrs) {
	case 0:
		return "no PCR"
	case 1:
		return "PCR " + s[0]
	}
	return "PCR " + strings.Join(s[:len(s)-1], ", ") + " and " + s[len(s)-1]
}

// ParsePCRs reads "0,7,15".
func ParsePCRs(s string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(part, "%d", &n); err != nil || n < 0 || n > 23 || fmt.Sprint(n) != part {
			return nil, fmt.Errorf("not a PCR index: %q", part)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no PCR given")
	}
	sort.Ints(out)
	return out, nil
}
