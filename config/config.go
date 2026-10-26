// Package config is assh.conf: every setting of assh in one file, KEY=VALUE
// lines (ASSH_*), so that a command needs no more than --config. The CA
// (where it is kept, its key, its slots and their PCRs, the window), the
// host key and the server. A flag given on the command line wins over the
// file. Projects that use assh as a library read the same file through this
// package and take the settings they use.
//
// Nothing in it is secret, and nothing in it is trusted: the CA's slots
// come from the CA file, which the TPM checks; the file only says what the
// CA should look like (Match).
package config

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/tpm2-trust/assh/hostkey"
)

// DefaultPath is where the assh command looks when no --config is given.
const DefaultPath = "/etc/assh/assh.conf"

// Config is the file. A key the file leaves out has its default.
type Config struct {
	TPM string // ASSH_TPM

	CA         string        // ASSH_CA: the CA file, or efi:NAME
	CAType     hostkey.Type  // ASSH_CA_TYPE
	Bank       hostkey.Bank  // ASSH_CA_BANK
	Slots      map[int][]int // ASSH_CA_SLOT_<N>: each slot's PCRs
	Window     int           // ASSH_CA_WINDOW: 0 none
	PolicyRef  string        // ASSH_CA_REF
	Authority  string        // ASSH_AUTHORITY: the authority's public key (PEM), a key elsewhere
	AuthTPM    bool          // ASSH_AUTHORITY_TPM: the authority in the TPM, opened by a PIN
	PINHandle  uint32        // ASSH_PIN_HANDLE
	CounterHdl uint32        // ASSH_COUNTER_HANDLE

	HostKeyType hostkey.Type // ASSH_HOSTKEY_TYPE
	Principals  []string     // ASSH_PRINCIPALS: comma-separated; * any
	KeyID       string       // ASSH_KEY_ID
	ClosePCR    int          // ASSH_CLOSE_PCR: -1 the CA's window
	State       string       // ASSH_STATE: "" the command's own

	Listen         string // ASSH_LISTEN
	AuthorizedKeys string // ASSH_AUTHORIZED_KEYS
	User           string // ASSH_USER
	Socket         string // ASSH_SOCKET

	AgentDir string // ASSH_AGENT_DIR
	AgentUID int    // ASSH_AGENT_UID

	// Set are the keys the file sets, so that a program can refuse those
	// it has no use for.
	Set map[string]bool
}

// Default is a file without lines.
func Default() Config {
	return Config{
		TPM:         "/dev/tpmrm0",
		CAType:      hostkey.P256,
		Bank:        hostkey.SHA256,
		Slots:       map[int][]int{},
		PolicyRef:   "assh",
		PINHandle:   uint32(hostkey.DefaultPINHandle),
		CounterHdl:  uint32(hostkey.DefaultCounterHandle),
		HostKeyType: hostkey.P256,
		Principals:  []string{"*"},
		KeyID:       "assh",
		ClosePCR:    -1,
		Listen:      ":22",
		AgentDir:    "/run/assh",
		Set:         map[string]bool{},
	}
}

// Load reads the file at path; an error os.IsNotExist knows when there is
// none.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Default(), err
	}
	c, err := Parse(data)
	if err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Parse reads the file's contents: the first line it refuses is the error.
func Parse(data []byte) (Config, error) {
	c := Default()
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return c, fmt.Errorf("line %d: expected KEY=VALUE", n)
		}
		key = strings.TrimSpace(key)
		val = unquote(strings.TrimSpace(val))
		if c.Set[key] {
			return c, fmt.Errorf("line %d: %s is set twice", n, key)
		}
		if err := c.set(key, val); err != nil {
			return c, fmt.Errorf("line %d: %s: %w", n, key, err)
		}
		c.Set[key] = true
	}
	if err := sc.Err(); err != nil {
		return c, err
	}
	return c, c.check()
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// slotKey is the key of slot n.
func slotKey(n int) string { return "ASSH_CA_SLOT_" + strconv.Itoa(n) }

func (c *Config) set(key, val string) error {
	var err error
	if s, ok := strings.CutPrefix(key, "ASSH_CA_SLOT_"); ok {
		n, aerr := strconv.Atoi(s)
		if aerr != nil || n < 0 || n >= hostkey.MaxSlots || strconv.Itoa(n) != s {
			return fmt.Errorf("the slots are ASSH_CA_SLOT_0 to ASSH_CA_SLOT_%d", hostkey.MaxSlots-1)
		}
		p, perr := hostkey.ParsePCRs(val)
		if perr != nil {
			return perr
		}
		c.Slots[n] = p
		return nil
	}
	switch key {
	case "ASSH_TPM":
		c.TPM, err = nonEmpty(val)
	case "ASSH_CA":
		c.CA, err = nonEmpty(val)
	case "ASSH_CA_TYPE":
		c.CAType, err = hostkey.ParseType(val)
	case "ASSH_CA_BANK":
		c.Bank, err = hostkey.ParseBank(val)
	case "ASSH_CA_WINDOW":
		c.Window, err = pcr(val, 0)
	case "ASSH_CA_REF":
		if len(val) > 32 {
			return errors.New("at most 32 bytes")
		}
		c.PolicyRef = val
	case "ASSH_AUTHORITY":
		c.Authority, err = nonEmpty(val)
	case "ASSH_AUTHORITY_TPM":
		c.AuthTPM, err = yesNo(val)
	case "ASSH_PIN_HANDLE":
		c.PINHandle, err = handle(val)
	case "ASSH_COUNTER_HANDLE":
		c.CounterHdl, err = handle(val)
	case "ASSH_HOSTKEY_TYPE":
		c.HostKeyType, err = hostkey.ParseType(val)
	case "ASSH_PRINCIPALS":
		c.Principals = SplitList(val)
		if len(c.Principals) == 0 {
			return errors.New("names the certificate is valid for, comma-separated, or *")
		}
	case "ASSH_KEY_ID":
		c.KeyID, err = nonEmpty(val)
	case "ASSH_CLOSE_PCR":
		c.ClosePCR, err = pcr(val, -1)
	case "ASSH_STATE":
		c.State = val
	case "ASSH_LISTEN":
		c.Listen, err = nonEmpty(val)
	case "ASSH_AUTHORIZED_KEYS":
		c.AuthorizedKeys, err = nonEmpty(val)
	case "ASSH_USER":
		c.User = val
	case "ASSH_SOCKET":
		c.Socket = val
	case "ASSH_AGENT_DIR":
		c.AgentDir, err = nonEmpty(val)
	case "ASSH_AGENT_UID":
		c.AgentUID, err = strconv.Atoi(val)
		if err == nil && c.AgentUID < 0 {
			err = errors.New("a user id")
		}
	default:
		return errors.New("unknown key")
	}
	return err
}

// check is what one line cannot tell: the slots fit the window.
func (c *Config) check() error {
	if c.Window != 0 {
		for _, n := range c.SlotNumbers() {
			if !slices.Contains(c.Slots[n], c.Window) {
				return fmt.Errorf("%s does not read PCR %d, ASSH_CA_WINDOW: the window would not close it", slotKey(n), c.Window)
			}
		}
	}
	if c.Authority != "" && c.AuthTPM {
		return errors.New("ASSH_AUTHORITY and ASSH_AUTHORITY_TPM=yes: the authority is one of them")
	}
	return nil
}

func nonEmpty(v string) (string, error) {
	if v == "" {
		return "", errors.New("empty")
	}
	return v, nil
}

func yesNo(v string) (bool, error) {
	switch v {
	case "yes":
		return true, nil
	case "no", "":
		return false, nil
	}
	return false, fmt.Errorf("yes or no, not %q", v)
}

func pcr(v string, none int) (int, error) {
	p, err := strconv.Atoi(v)
	if err != nil || p < none || p > 23 {
		return 0, fmt.Errorf("a PCR number, not %q", v)
	}
	return p, nil
}

func handle(v string) (uint32, error) {
	h, err := strconv.ParseUint(v, 0, 32)
	if err != nil {
		return 0, fmt.Errorf("an NV handle, not %q", v)
	}
	return uint32(h), nil
}

// SplitList splits a comma-separated list, leaving out empty items.
func SplitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// SlotNumbers are the file's slots, in order.
func (c Config) SlotNumbers() []int {
	var out []int
	for n := range c.Slots {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

// Lines are the file's lines for c: every key that differs from its
// default, and the CA and its slots always, in a fixed order.
func (c Config) Lines() [][2]string {
	d := Default()
	var out [][2]string
	add := func(key, val, def string, always bool) {
		if always || val != def {
			out = append(out, [2]string{key, val})
		}
	}
	add("ASSH_TPM", c.TPM, d.TPM, false)
	add("ASSH_CA", c.CA, "", true)
	add("ASSH_CA_TYPE", string(c.CAType), string(d.CAType), false)
	add("ASSH_CA_BANK", string(c.Bank), string(d.Bank), false)
	for _, n := range c.SlotNumbers() {
		add(slotKey(n), pcrs(c.Slots[n]), "", true)
	}
	add("ASSH_CA_WINDOW", strconv.Itoa(c.Window), "0", false)
	add("ASSH_CA_REF", c.PolicyRef, d.PolicyRef, false)
	add("ASSH_AUTHORITY", c.Authority, "", false)
	add("ASSH_AUTHORITY_TPM", map[bool]string{true: "yes", false: "no"}[c.AuthTPM], "no", false)
	add("ASSH_PIN_HANDLE", fmt.Sprintf("0x%08X", c.PINHandle), fmt.Sprintf("0x%08X", d.PINHandle), false)
	add("ASSH_COUNTER_HANDLE", fmt.Sprintf("0x%08X", c.CounterHdl), fmt.Sprintf("0x%08X", d.CounterHdl), false)
	add("ASSH_HOSTKEY_TYPE", string(c.HostKeyType), string(d.HostKeyType), false)
	add("ASSH_PRINCIPALS", strings.Join(c.Principals, ","), "*", false)
	add("ASSH_KEY_ID", c.KeyID, d.KeyID, false)
	add("ASSH_CLOSE_PCR", strconv.Itoa(c.ClosePCR), "-1", false)
	add("ASSH_STATE", c.State, "", false)
	add("ASSH_LISTEN", c.Listen, d.Listen, false)
	add("ASSH_AUTHORIZED_KEYS", c.AuthorizedKeys, "", false)
	add("ASSH_USER", c.User, "", false)
	add("ASSH_SOCKET", c.Socket, "", false)
	add("ASSH_AGENT_DIR", c.AgentDir, d.AgentDir, false)
	add("ASSH_AGENT_UID", strconv.Itoa(c.AgentUID), "0", false)
	return out
}

func pcrs(p []int) string {
	s := make([]string, len(p))
	for i, v := range p {
		s[i] = strconv.Itoa(v)
	}
	return strings.Join(s, ",")
}

// Format is the file for c alone, with header (comment lines) above the
// lines.
func Format(c Config, header string) []byte {
	var lines []string
	if header != "" {
		for _, l := range strings.Split(strings.TrimRight(header, "\n"), "\n") {
			lines = append(lines, strings.TrimRight("# "+l, " "))
		}
		lines = append(lines, "")
	}
	for _, kv := range c.Lines() {
		lines = append(lines, kv[0]+"="+quote(kv[1]))
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// Write writes c to path and keeps the rest of the file: a line of a key
// c sets is replaced, one of a key it no longer sets (a slot taken away, a
// default) is dropped, the others are added at the end; comments stay. A
// missing file is created with header above the lines.
func Write(path string, c Config, header string) error {
	if err := c.check(); err != nil {
		return err
	}
	want := map[string]string{}
	var order []string
	for _, kv := range c.Lines() {
		want[kv[0]] = quote(kv[1])
		order = append(order, kv[0])
	}
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(data) == 0 {
		return os.WriteFile(path, Format(c, header), 0o644)
	}
	var lines []string
	done := map[string]bool{}
	for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		key, _, ok := strings.Cut(strings.TrimSpace(l), "=")
		key = strings.TrimSpace(key)
		if !ok || strings.HasPrefix(key, "#") || !strings.HasPrefix(key, "ASSH_") {
			lines = append(lines, l)
			continue
		}
		if v, ok := want[key]; ok && !done[key] {
			lines = append(lines, key+"="+v)
			done[key] = true
		}
	}
	for _, k := range order {
		if !done[k] {
			lines = append(lines, k+"="+want[k])
		}
	}
	out := []byte(strings.Join(lines, "\n") + "\n")
	if bytes.Equal(out, data) {
		return nil
	}
	return os.WriteFile(path, out, 0o644)
}

func quote(v string) string {
	if strings.ContainsAny(v, " \t#\"'") {
		return `"` + v + `"`
	}
	return v
}

// Match makes the CA's slots the file's: a slot the file adds is added, one
// it leaves out is taken away with its approvals, one whose PCRs changed is
// replaced (its approvals go). The file's window, key type, bank and policy
// ref are the CA's for good: a difference is an error that says to create
// the CA again. changed says whether the CA is different now; a file
// without slots changes nothing.
func (c Config) Match(ca *hostkey.CA) (changed bool, err error) {
	switch {
	case c.Window != ca.Window:
		return false, fmt.Errorf("ASSH_CA_WINDOW is %d, the CA's window %d: a window is the CA's for good, create the CA again", c.Window, ca.Window)
	case !slices.Contains(c.CAType.Choices(), ca.Type):
		return false, fmt.Errorf("ASSH_CA_TYPE is %s, the CA's key %s: create the CA again", c.CAType, ca.Type)
	case c.Bank != hostkey.Auto && c.Bank != ca.Bank:
		return false, fmt.Errorf("ASSH_CA_BANK is %s, the CA's bank %s: create the CA again", c.Bank, ca.Bank)
	case c.PolicyRef != string(ca.PolicyRef):
		return false, fmt.Errorf("ASSH_CA_REF is %q, the CA's %q: create the CA again", c.PolicyRef, ca.PolicyRef)
	}
	if len(c.Slots) == 0 {
		return false, nil
	}
	old, oldApprovals := ca.Slots, ca.Approvals
	ca.Slots = nil
	for _, n := range c.SlotNumbers() {
		if err := ca.AddSlot(n, c.Slots[n]); err != nil {
			ca.Slots = old
			return false, err
		}
	}
	ca.Approvals = slices.DeleteFunc(slices.Clone(oldApprovals), func(a hostkey.Approval) bool {
		i := slices.IndexFunc(old, func(s hostkey.Slot) bool { return s.Number == a.Slot })
		n := ca.Slot(a.Slot)
		return i < 0 || n == nil || !slices.Equal(old[i].PCRs, n.PCRs)
	})
	return !slices.EqualFunc(old, ca.Slots, func(a, b hostkey.Slot) bool {
		return a.Number == b.Number && slices.Equal(a.PCRs, b.PCRs)
	}), nil
}
