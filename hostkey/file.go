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
//
// At its start a server asks for a host key (Issue): the TPM makes a new
// one under its NULL hierarchy, whose seed changes at every reboot, and
// the CA certifies it - while the PCRs hold an approved state. The host
// key then signs every key exchange of this boot, whatever the PCRs hold
// later; at the next reboot it is gone for good. Once the window is closed
// - a PCR extended right after the Issue (Close), or the boot moving on -
// the CA signs nothing until the next boot, so a server started later, or
// any other process, gets no certificate.
//
// Nothing here is a secret outside the TPM, and no secret ever leaves it.
// Clients trust the CA, not a key: a known_hosts line
//
//	@cert-authority <hosts> <the CA's public key>
package hostkey

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"golang.org/x/crypto/ssh"
)

// Type is the kind of key in the TPM.
type Type string

const (
	P256    Type = "p256"    // ECDSA on NIST P-256, ssh's ecdsa-sha2-nistp256
	RSA2048 Type = "rsa2048" // RSA with 2048 bits, ssh's rsa-sha2-256
)

// ParseType reads a type as a person writes it.
func ParseType(s string) (Type, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "p256", "p-256", "ecdsa", "nistp256":
		return P256, nil
	case "rsa2048", "rsa-2048", "rsa":
		return RSA2048, nil
	}
	return "", fmt.Errorf("unknown key type %q (p256 or rsa2048)", s)
}

// Bank is a PCR bank the CA's policy reads.
type Bank string

const (
	SHA256 Bank = "sha256"
	SHA1   Bank = "sha1"
)

// ParseBank reads a bank name.
func ParseBank(s string) (Bank, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "sha256", "":
		return SHA256, nil
	case "sha1":
		return SHA1, nil
	}
	return "", fmt.Errorf("unknown PCR bank %q (sha256 or sha1)", s)
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
const fileVersion = 1

// CA is the certificate authority: the TPM's wrapped copy of its key, the
// authority that approves the PCR states it signs in, and its approvals.
// Nothing in it is a secret outside this TPM.
type CA struct {
	Version int  `json:"version"`
	Type    Type `json:"type"`
	// The PCRs the CA is bound to, in one bank: every approval gives
	// values for exactly these.
	Bank Bank  `json:"bank"`
	PCRs []int `json:"pcrs"`

	Public  []byte `json:"public"`  // the CA key's TPMT_PUBLIC
	Private []byte `json:"private"` // its TPM2B_PRIVATE buffer

	Authority []byte `json:"authority"`  // the authority's public key, PKIX DER
	PolicyRef []byte `json:"policy_ref"` // what its signatures are bound to

	Approvals []Approval `json:"approvals,omitempty"`
}

// Approval is a PCR state the authority signed: the CA signs while the
// PCRs hold these values.
type Approval struct {
	PCRs      map[int][]byte `json:"pcrs"`
	Signature []byte         `json:"signature"` // TPMT_SIGNATURE over ApprovalDigest
}

// Equal is whether b is the same approval: the same values, signed alike.
func (a Approval) Equal(b *Approval) bool {
	if b == nil || len(a.PCRs) != len(b.PCRs) || string(a.Signature) != string(b.Signature) {
		return false
	}
	for i, v := range a.PCRs {
		if string(b.PCRs[i]) != string(v) {
			return false
		}
	}
	return true
}

// LoadCA reads a CA file.
func LoadCA(path string) (*CA, error) {
	data, err := os.ReadFile(path)
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
	if len(f.PCRs) == 0 {
		return nil, errors.New("the CA is bound to no PCR")
	}
	if _, err := f.PublicKey(); err != nil {
		return nil, err
	}
	if _, err := f.authorityKey(); err != nil {
		return nil, err
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
// at path: written beside it and renamed, so a reader never sees half.
func (f *CA) Save(path string) error {
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

// Approved is the approval for exactly these values, nil when there is
// none.
func (f *CA) Approved(values map[int][]byte) *Approval {
	for i := range f.Approvals {
		if sameValues(f.PCRs, f.Approvals[i].PCRs, values) {
			return &f.Approvals[i]
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

// checkValues makes sure values has one value of the bank's size for each
// of the CA's PCRs, and nothing else.
func (f *CA) checkValues(values map[int][]byte) error {
	if len(values) != len(f.PCRs) {
		return fmt.Errorf("values for %d PCRs, the CA is bound to %s", len(values), PCRList(f.PCRs))
	}
	for _, i := range f.PCRs {
		v, ok := values[i]
		if !ok {
			return fmt.Errorf("no value for PCR %d", i)
		}
		if len(v) != f.Bank.size() {
			return fmt.Errorf("PCR %d: %d bytes, a %s value has %d", i, len(v), f.Bank, f.Bank.size())
		}
	}
	return nil
}

// PCRList is "0, 7 and 15".
func PCRList(pcrs []int) string {
	s := make([]string, len(pcrs))
	for i, p := range pcrs {
		s[i] = fmt.Sprint(p)
	}
	if len(s) == 1 {
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
