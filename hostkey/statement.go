package hostkey

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Statement is an approval as a person reads it before it is signed: what
// the CA will sign in. The digest the authority signs follows from it
// alone (Digest), so that a signer elsewhere computes it from what it
// shows rather than signing bytes it cannot read. Neither the CA file nor
// assh.conf is trusted: whoever approves reads this.
type Statement struct {
	CA         string            `json:"ca"`        // the CA's fingerprint
	Authority  string            `json:"authority"` // the authority's fingerprint
	Ref        string            `json:"ref"`       // the policy reference, hex
	Bank       Bank              `json:"bank"`
	Slot       int               `json:"slot"`
	PCRs       map[string]string `json:"pcrs"` // index: value, hex
	Signed     *Signed           `json:"signed,omitempty"`
	Generation uint64            `json:"generation,omitempty"`
	Counter    []byte            `json:"counter,omitempty"` // the counter's public area, with a counter
}

// Statement is what approving values in slot at the file's generation
// says.
func (f *CA) Statement(slot int, values map[int][]byte) (*Statement, error) {
	s := f.Slot(slot)
	if s == nil {
		return nil, fmt.Errorf("no slot %d", slot)
	}
	if err := f.checkValues(s, values); err != nil {
		return nil, err
	}
	st := &Statement{
		CA:         f.Fingerprint(),
		Authority:  fingerprintOf(f),
		Ref:        hex.EncodeToString(f.PolicyRef),
		Bank:       f.Bank,
		Slot:       slot,
		PCRs:       map[string]string{},
		Signed:     s.Signed,
		Generation: f.FileGeneration(),
	}
	for _, i := range s.PCRs {
		st.PCRs[strconv.Itoa(i)] = hex.EncodeToString(values[i])
	}
	if f.Counter != nil {
		st.Counter = f.Counter.Public
	}
	return st, nil
}

func fingerprintOf(f *CA) string {
	k, err := f.authorityKey()
	if err != nil {
		return "?"
	}
	sk, err := ssh.NewPublicKey(k)
	if err != nil {
		return "?"
	}
	return ssh.FingerprintSHA256(sk)
}

// values are the statement's PCRs, and their indices in order.
func (s *Statement) values() (map[int][]byte, []int, error) {
	out := map[int][]byte{}
	var pcrs []int
	for k, v := range s.PCRs {
		i, err := strconv.Atoi(k)
		if err != nil || strconv.Itoa(i) != k {
			return nil, nil, fmt.Errorf("PCR %q", k)
		}
		b, err := hex.DecodeString(v)
		if err != nil || len(b) != s.Bank.size() {
			return nil, nil, fmt.Errorf("PCR %d: not a %s value", i, s.Bank)
		}
		out[i] = b
		pcrs = append(pcrs, i)
	}
	sort.Ints(pcrs)
	return out, pcrs, nil
}

// Digest is what the authority signs for the statement: computed from it
// alone, as ApprovalDigest computes it from the CA.
func (s *Statement) Digest() ([]byte, error) {
	if s.Bank != SHA256 && s.Bank != SHA1 {
		return nil, fmt.Errorf("unknown PCR bank %q", s.Bank)
	}
	ref, err := hex.DecodeString(s.Ref)
	if err != nil {
		return nil, errors.New("the policy reference is not hex")
	}
	values, pcrs, err := s.values()
	if err != nil {
		return nil, err
	}
	slot, err := newSlot(s.Slot, pcrs)
	if err != nil {
		return nil, err
	}
	f := &CA{Bank: s.Bank, PolicyRef: ref, Slots: []Slot{slot}}
	if s.Signed != nil {
		if _, err := s.Signed.key(); err != nil {
			return nil, err
		}
		f.Slots[0].Signed = s.Signed
	}
	if s.Counter != nil {
		f.Counter = &Counter{Public: s.Counter}
	}
	return f.approvalDigestAt(&f.Slots[0], values, s.Generation)
}

// String is the statement for a person.
func (s *Statement) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "CA %s, authority %s, reference %q\n", s.CA, s.Authority, refText(s.Ref))
	fmt.Fprintf(&b, "slot %d: the CA signs while these PCRs (%s) hold:\n", s.Slot, s.Bank)
	_, pcrs, _ := s.values()
	for _, i := range pcrs {
		fmt.Fprintf(&b, "  PCR %2d  %s\n", i, s.PCRs[strconv.Itoa(i)])
	}
	if s.Signed != nil {
		fp := "?"
		if k, err := s.Signed.key(); err == nil {
			if sk, err := ssh.NewPublicKey(k); err == nil {
				fp = ssh.FingerprintSHA256(sk)
			}
		}
		fmt.Fprintf(&b, "  and PCR %s as the key %s signs them\n", PCRList(s.Signed.PCRs), fp)
	}
	if s.Counter != nil {
		fmt.Fprintf(&b, "  while the counter is at generation %d\n", s.Generation)
	}
	return b.String()
}

func refText(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		return h
	}
	return string(b)
}

// ParseStatement reads a statement as Marshal writes it.
func ParseStatement(data []byte) (*Statement, error) {
	var s Statement
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("not a statement: %w", err)
	}
	if _, err := s.Digest(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Marshal is the statement's file.
func (s *Statement) Marshal() ([]byte, error) {
	b, err := json.MarshalIndent(s, "", "  ")
	return append(b, '\n'), err
}
