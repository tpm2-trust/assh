// Command assh is an SSH server whose host key lives in the TPM, and an
// agent that lends such a key to OpenSSH's sshd. See README.md.
package main

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/tpm2-trust/assh/config"
	"github.com/tpm2-trust/assh/hostkey"
	"github.com/tpm2-trust/assh/tpmadmin"
)

const usage = `assh - an SSH host key in the TPM

  assh ca create   --out FILE (--authority PUB.pem | --authority-tpm)
                   [--type p256|rsa2048] [--pcrs 0,7] [--window N] [--bank sha256|sha1|auto] [--ref TEXT]
                   [--pin-handle 0x01802913] [--counter-handle 0x01802912] [--pin-fd N]
  assh ca slot     --ca FILE (--add N --pcrs 0,7 | --remove N)
  assh ca sync     --ca FILE
  assh ca show     --ca FILE
  assh ca approve  --ca FILE [--slot N[,N...]] [--values FILE]
                   authority in the TPM: [--next-generation] [--redefine-counter] [--pin-fd N]
                   [--events PCR:EVENT ...]: that PCR as from zero with these events
                   key elsewhere: (--authority-key KEY.pem | --signature FILE | --digest FILE)
  assh ca pin      --ca FILE [--pin-fd N] [--new-pin-fd N]
  assh ca remove   --ca FILE    the CA and its PIN index and counter in the TPM
  assh tpm sha1    [--allow | --forbid]
  assh tpm da      [--max-tries 3 --recovery 1800 --lockout-recovery 1800] [--reset]
                   [--lockout-auth-fd N | --ask-lockout-auth]
                   [--new-lockout-auth | --new-lockout-auth-fd N]
  assh serve       --ca FILE --authorized-keys FILE (-- COMMAND ... | --socket PATH)
                   [--listen :22] [--user NAME] [HOST KEY OPTIONS]
  assh agent       --ca FILE [--dir /run/assh] [--uid 0] [HOST KEY OPTIONS]

Host key options: [--key-type p256|rsa2048] [--principals '*'] [--key-id TEXT]
                  [--close-pcr N] [--state FILE]

Every command takes --config FILE, assh.conf (default ` + config.DefaultPath + ` when it
is there): KEY=VALUE lines that set what the flags set - ASSH_CA,
ASSH_CA_SLOT_<N>=PCRs, ASSH_CA_WINDOW, ASSH_LISTEN, ASSH_AUTHORIZED_KEYS
and the rest (README) - so that 'assh agent --config FILE' is all a
service needs; a flag given wins over the file. 'ca create' makes every
slot the file names, 'ca sync' makes an existing CA's slots the file's.
Every command takes --tpm PATH (default /dev/tpmrm0). A CA FILE may be an
EFI variable instead, efi:NAME (efivarfs, vendor GUID ` + hostkey.VarGUID + `):
where nothing else survives a reboot, or outside the boot image a slot
measures.

The CA is created in the TPM and never leaves it. It has up to 16 slots,
each a PCR selection ('ca create --pcrs' is slot 0, 'ca slot' adds more),
and signs while the PCRs hold a state the authority approved in a slot
('ca approve --slot'); the slots are tried from 0 up. With a window
('--window N') every slot reads PCR N, and extending it closes the CA for
the rest of the boot. The authority is a key elsewhere, or a key in the
TPM opened by a PIN; then
every approval names a generation of a counter in the TPM, and
'ca approve --next-generation' revokes every approval made before. A PIN or
a lockout authorization is read from the terminal or a file descriptor
(--pin-fd), never from the command line or the environment. 'serve'
and 'agent' make a host key in the TPM at their start - gone at the next
reboot - and have the CA certify it; then they close the CA's window (or
--close-pcr), so the CA signs nothing more until the next boot. When no
slot is approved for the boot, the key is temporary: not certified, its
fingerprint logged to compare. A CA of bank auto reads SHA-256 where the
TPM has that bank active, else SHA-1, but only while the TPM allows it
('tpm sha1 --allow', an NV index the owner defines). Clients trust the CA:

  @cert-authority <hosts> <the contents of the CA's .pub file>
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "ca":
		err = caCommand(os.Args[2:])
	case "tpm":
		err = tpmCommand(os.Args[2:])
	case "serve":
		err = serveCommand(os.Args[2:])
	case "agent":
		err = agentCommand(os.Args[2:])
	case childArg:
		err = childMain()
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "assh:", err)
		os.Exit(1)
	}
}

func openTPM(path string) func() (transport.TPMCloser, error) {
	return func() (transport.TPMCloser, error) {
		t, err := transport.OpenTPM(path)
		if err != nil {
			return nil, fmt.Errorf("opening the TPM at %s: %w", path, err)
		}
		return t, nil
	}
}

// commandConfig is assh.conf for a command's arguments: the file --config
// names, else config.DefaultPath when it is there, else the defaults. The
// flags take their defaults from it, so that a flag given wins.
func commandConfig(fs *flag.FlagSet, args []string) (config.Config, error) {
	path, named := config.DefaultPath, false
	for i, a := range args {
		if a == "--" {
			break
		}
		name, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != "config" {
			continue
		}
		if !hasVal {
			if i+1 >= len(args) {
				return config.Default(), errors.New("--config needs a file")
			}
			val = args[i+1]
		}
		path, named = val, true
	}
	fs.String("config", path, "assh.conf: the settings the flags set; a flag given wins over it")
	if path == "" {
		return config.Default(), nil
	}
	c, err := config.Load(path)
	if os.IsNotExist(err) && !named {
		return config.Default(), nil
	}
	return c, err
}

func caCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("ca needs create, slot, sync, show, approve, pin or remove")
	}
	fs := flag.NewFlagSet("ca "+args[0], flag.ExitOnError)
	cfg, err := commandConfig(fs, args[1:])
	if err != nil {
		return err
	}
	tpmPath := fs.String("tpm", cfg.TPM, "the TPM")
	switch args[0] {
	case "create":
		out := fs.String("out", cfg.CA, "the CA file to write (its public key goes beside it, .pub), or efi:NAME")
		authPath := fs.String("authority", cfg.Authority, "the authority's public key (PEM), a key elsewhere: it approves the PCR states")
		authTPM := fs.Bool("authority-tpm", cfg.AuthTPM, "make the authority in the TPM, opened by a PIN, with a counter that revokes old approvals")
		pinHandle := fs.String("pin-handle", fmt.Sprintf("0x%08X", cfg.PINHandle), "the NV handle of the PIN index (--authority-tpm)")
		counterHandle := fs.String("counter-handle", fmt.Sprintf("0x%08X", cfg.CounterHdl), "the NV handle of the counter (--authority-tpm)")
		pinFd := fs.Int("pin-fd", -1, "read the new PIN from this file descriptor (every byte); default: ask the terminal twice")
		typ := fs.String("type", string(cfg.CAType), "the CA's key: p256 or rsa2048, or a list in order of preference (rsa2048,p256: the first the TPM takes)")
		slot0 := "0,7"
		if p, ok := cfg.Slots[0]; ok {
			slot0 = numbers(p)
		}
		pcrs := fs.String("pcrs", slot0, "slot 0's PCRs (the other slots of assh.conf are made too; 'ca slot' adds more)")
		window := fs.Int("window", cfg.Window, "the PCR whose extension closes the CA for the rest of the boot; every slot reads it (0: none)")
		bank := fs.String("bank", string(cfg.Bank), "their bank: sha256, sha1, or auto (sha256 where the TPM has it, else sha1 where 'tpm sha1 --allow' allows it)")
		ref := fs.String("ref", cfg.PolicyRef, "what the authority's approvals are bound to (at most 32 bytes)")
		fs.Parse(args[1:])
		if *out == "" || (*authPath == "") == !*authTPM {
			return errors.New("ca create needs --out, and --authority or --authority-tpm")
		}
		t, err := hostkey.ParseType(*typ)
		if err != nil {
			return err
		}
		b, err := hostkey.ParseBank(*bank)
		if err != nil {
			return err
		}
		p, err := hostkey.ParsePCRs(*pcrs)
		if err != nil {
			return err
		}
		tpm, err := openTPM(*tpmPath)()
		if err != nil {
			return err
		}
		defer tpm.Close()
		opts := hostkey.CAOptions{Type: t, Bank: b, PCRs: p, Window: *window, PolicyRef: []byte(*ref)}
		var ca *hostkey.CA
		if *authTPM {
			ph, err := parseHandle(*pinHandle)
			if err != nil {
				return err
			}
			ch, err := parseHandle(*counterHandle)
			if err != nil {
				return err
			}
			pin := &pinSource{fd: *pinFd, prompt: "new PIN", confirm: true}
			defer pin.wipe()
			ca, err = hostkey.CreatePINCA(tpm, hostkey.PINCAOptions{
				CAOptions: opts, PINHandle: ph, CounterHandle: ch, PIN: pin.get,
			})
			if err != nil {
				return err
			}
		} else {
			auth, err := readPublicKey(*authPath)
			if err != nil {
				return err
			}
			if ca, err = hostkey.CreateCA(tpm, auth, opts); err != nil {
				return err
			}
		}
		for _, n := range cfg.SlotNumbers() {
			if n == 0 {
				continue
			}
			if err := ca.AddSlot(n, cfg.Slots[n]); err != nil {
				return fmt.Errorf("assh.conf's slot %d: %w", n, err)
			}
		}
		if err := ca.Save(*out); err != nil {
			return err
		}
		if !hostkey.IsVar(*out) {
			pub, _ := ca.AuthorizedKey()
			if err := os.WriteFile(*out+".pub", pub, 0o644); err != nil {
				return err
			}
		}
		fmt.Print(ca.Describe())
		line, _ := ca.KnownHosts("*")
		fmt.Printf("Clients trust it with this known_hosts line (narrow the * to the host's names):\n  %s\n", line)
		fmt.Printf("Approve the PCR state it may sign in: assh ca approve --ca %s ...\n", *out)
		return nil
	case "slot":
		caPath := fs.String("ca", cfg.CA, "the CA file")
		add := fs.Int("add", -1, "add this slot (0 to 15), reading --pcrs")
		remove := fs.Int("remove", -1, "remove this slot and its approvals")
		pcrs := fs.String("pcrs", "", "the new slot's PCRs")
		fs.Parse(args[1:])
		if (*add < 0) == (*remove < 0) {
			return errors.New("ca slot needs --add N --pcrs ..., or --remove N")
		}
		ca, err := hostkey.LoadCA(*caPath)
		if err != nil {
			return err
		}
		if *add >= 0 {
			p, err := hostkey.ParsePCRs(*pcrs)
			if err != nil {
				return err
			}
			if err := ca.AddSlot(*add, p); err != nil {
				return err
			}
		} else if err := ca.RemoveSlot(*remove); err != nil {
			return err
		}
		if err := ca.Save(*caPath); err != nil {
			return err
		}
		fmt.Print(ca.Describe())
		if *add >= 0 {
			fmt.Printf("Slot %d lets the CA sign nothing until a state in it is approved: assh ca approve --ca %s --slot %d ...\n", *add, *caPath, *add)
		}
		return nil
	case "sync":
		caPath := fs.String("ca", cfg.CA, "the CA file")
		fs.Parse(args[1:])
		if len(cfg.Slots) == 0 {
			return errors.New("ca sync makes the CA's slots those of assh.conf (ASSH_CA_SLOT_<N>), and it names none")
		}
		ca, err := hostkey.LoadCA(*caPath)
		if err != nil {
			return err
		}
		changed, err := cfg.Match(ca)
		if err != nil {
			return err
		}
		if changed {
			if err := ca.Save(*caPath); err != nil {
				return err
			}
		}
		fmt.Print(ca.Describe())
		if !changed {
			fmt.Println("The CA's slots are assh.conf's already.")
		}
		return nil
	case "show":
		caPath := fs.String("ca", cfg.CA, "the CA file")
		fs.Parse(args[1:])
		ca, err := hostkey.LoadCA(*caPath)
		if err != nil {
			return err
		}
		fmt.Print(ca.Describe())
		if line, err := ca.KnownHosts("*"); err == nil {
			fmt.Printf("Clients trust it with this known_hosts line (narrow the * to the host's names):\n  %s\n", line)
		}
		tpm, err := openTPM(*tpmPath)()
		if err != nil {
			listApprovals(ca, ca.FileGeneration())
			return nil
		}
		defer tpm.Close()
		gen := ca.FileGeneration()
		if ca.Counter != nil {
			if g, err := ca.Generation(tpm); err != nil {
				fmt.Println(err)
			} else {
				gen = g
				fmt.Printf("The counter is at generation %d in the TPM.\n", g)
			}
			if _, err := ca.CheckPINIndex(tpm); err != nil {
				fmt.Println(err)
			}
		}
		listApprovals(ca, gen)
		if now, err := ca.ReadPCRs(tpm); err == nil {
			if a := ca.Approved(now); a != nil && a.Generation == gen {
				fmt.Printf("The PCRs hold a state approved in slot %d now: the CA signs.\n", a.Slot)
			} else {
				fmt.Println("The PCRs hold no approved state now: the CA signs nothing.")
			}
		}
		if ca.AuthorityTPM != nil {
			printDA(tpm)
		}
		return nil
	case "approve":
		caPath := fs.String("ca", cfg.CA, "the CA file, which gets the approval")
		slotList := fs.String("slot", slotsDefault(cfg), "the slots the approval is for, 0,1 say: one PIN for all (default: assh.conf's slots, else 0)")
		keyPath := fs.String("authority-key", "", "the authority's private key (PEM): signs here")
		sigPath := fs.String("signature", "", "the authority's signature over the digest, made elsewhere (PKCS #1 v1.5 or ECDSA DER, as openssl pkeyutl -sign makes it)")
		digestPath := fs.String("digest", "", "write the digest to sign to this file, and approve nothing")
		valuesPath := fs.String("values", "", "the PCR values to approve, as 'serve' or 'agent' recorded them (--state); default: what the TPM holds now")
		var events eventList
		fs.Var(&events, "events", "PCR:EVENT - that PCR's value is approved as from zero, extended with each such EVENT in order (TPM2_PCR_Event): a state known before it is booted; repeatable")
		next := fs.Bool("next-generation", false, "increment the counter first: every approval made before stops working (authority in the TPM)")
		redefine := fs.Bool("redefine-counter", false, "define the counter again first, in place of what is at its handle: after it was deleted or replaced (authority in the TPM)")
		pinFd := fs.Int("pin-fd", -1, "read the PIN from this file descriptor (every byte); default: ask the terminal")
		fs.Parse(args[1:])
		ca, err := hostkey.LoadCA(*caPath)
		if err != nil {
			return err
		}
		slots, err := parseSlots(ca, *slotList)
		if err != nil {
			return err
		}
		values, err := approveValues(ca, *valuesPath, *tpmPath)
		if err != nil {
			return err
		}
		if err := events.apply(ca, values); err != nil {
			return err
		}
		if ca.AuthorityTPM != nil {
			if *keyPath != "" || *sigPath != "" || *digestPath != "" {
				return errors.New("the CA's authority is in the TPM: it signs with the PIN, not with --authority-key, --signature or --digest")
			}
			return approveInTPM(ca, *caPath, *tpmPath, slots, values, *next, *redefine, *pinFd)
		}
		if *next || *redefine {
			return errors.New("the CA's authority is a key elsewhere: it has no counter, and its approvals are never revoked")
		}
		if len(slots) > 1 && (*digestPath != "" || *sigPath != "") {
			return errors.New("--digest and --signature are for one slot: a digest and a signature each")
		}
		slot := slots[0]
		switch {
		case *digestPath != "":
			d, err := ca.ApprovalDigest(slot, values)
			if err != nil {
				return err
			}
			if err := os.WriteFile(*digestPath, d, 0o644); err != nil {
				return err
			}
			fmt.Printf("Sign %s (SHA-256 digest %s) with the authority, then: assh ca approve --ca %s --slot %d --signature SIG", *digestPath, hex.EncodeToString(d), *caPath, slot)
			if *valuesPath != "" {
				fmt.Printf(" --values %s", *valuesPath)
			}
			fmt.Println()
			fmt.Printf("  openssl pkeyutl -sign -inkey AUTHORITY.key -pkeyopt digest:sha256 -in %s -out SIG\n", *digestPath)
			return nil
		case *sigPath != "":
			sig, err := os.ReadFile(*sigPath)
			if err != nil {
				return err
			}
			if err := ca.AddApproval(slot, values, sig); err != nil {
				return err
			}
		case *keyPath != "":
			key, err := readPrivateKey(*keyPath)
			if err != nil {
				return err
			}
			for _, n := range slots {
				if err := ca.Approve(key, n, values); err != nil {
					return err
				}
			}
		default:
			return errors.New("ca approve needs --authority-key, --signature or --digest")
		}
		if err := ca.Save(*caPath); err != nil {
			return err
		}
		fmt.Printf("Approved in %s: %d state(s) in %s\n", slotsText(slots), len(ca.Approvals), *caPath)
		return nil
	case "remove":
		caPath := fs.String("ca", cfg.CA, "the CA file, or efi:NAME")
		pinHandle := fs.String("pin-handle", fmt.Sprintf("0x%08X", cfg.PINHandle), "with no CA file: the PIN index to remove, if it has the shape of aSSH's")
		counterHandle := fs.String("counter-handle", fmt.Sprintf("0x%08X", cfg.CounterHdl), "with no CA file: the counter to remove, if it has the shape of aSSH's")
		fs.Parse(args[1:])
		var handles []tpm2.TPMHandle
		for _, s := range []string{*pinHandle, *counterHandle} {
			h, err := parseHandle(s)
			if err != nil {
				return err
			}
			handles = append(handles, h)
		}
		tpm, err := openTPM(*tpmPath)()
		if err != nil {
			return err
		}
		defer tpm.Close()
		removed, err := hostkey.RemoveCA(tpm, *caPath, handles)
		for _, r := range removed {
			fmt.Println("removed", r)
		}
		if err != nil {
			return err
		}
		if len(removed) == 0 {
			fmt.Println("nothing to remove: no CA at", *caPath)
		}
		return nil
	case "pin":
		caPath := fs.String("ca", cfg.CA, "the CA file")
		pinFd := fs.Int("pin-fd", -1, "read the PIN from this file descriptor (every byte); default: ask the terminal")
		newPinFd := fs.Int("new-pin-fd", -1, "read the new PIN from this file descriptor; default: ask the terminal twice")
		fs.Parse(args[1:])
		ca, err := hostkey.LoadCA(*caPath)
		if err != nil {
			return err
		}
		if ca.AuthorityTPM == nil {
			return errors.New("the CA's authority is a key elsewhere: it has no PIN")
		}
		tpm, err := openTPM(*tpmPath)()
		if err != nil {
			return err
		}
		defer tpm.Close()
		old := &pinSource{fd: *pinFd, prompt: "PIN"}
		defer old.wipe()
		next := &pinSource{fd: *newPinFd, prompt: "new PIN", confirm: true}
		defer next.wipe()
		if err := tpmadmin.ChangePIN(tpm, ca, old.get, next.get); err != nil {
			return err
		}
		fmt.Println("The PIN is changed. The CA, its approvals and its file stay as they are.")
		return nil
	}
	return fmt.Errorf("unknown ca command %q", args[0])
}

// approveInTPM approves values with the authority in the TPM, after the
// counter's next generation or its redefinition if asked: one PIN for all.
func approveInTPM(ca *hostkey.CA, caPath, tpmPath string, slots []int, values map[int][]byte, next, redefine bool, pinFd int) error {
	tpm, err := openTPM(tpmPath)()
	if err != nil {
		return err
	}
	defer tpm.Close()
	pin := &pinSource{fd: pinFd, prompt: "PIN"}
	defer pin.wipe()
	moved := false
	switch {
	case redefine:
		if err := ca.RedefineCounter(tpm, pin.get); err != nil {
			return err
		}
		moved = true
	case next:
		if err := ca.NextGeneration(tpm, pin.get); err != nil {
			return err
		}
		moved = true
	default:
		if err := ca.Sync(tpm); err != nil {
			return err
		}
	}
	if moved {
		// The counter has moved: the file follows it, approved or not.
		if err := ca.Save(caPath); err != nil {
			return err
		}
		fmt.Printf("The counter is at generation %d: every approval before it is revoked.\n", ca.FileGeneration())
	}
	signer, err := ca.TPMAuthority(tpm, pin.get)
	if err != nil {
		return err
	}
	for _, n := range slots {
		if err := ca.Approve(signer, n, values); err != nil {
			if moved {
				return fmt.Errorf("%w (the CA has no approval of generation %d yet: approve again)", err, ca.FileGeneration())
			}
			return err
		}
	}
	if err := ca.Save(caPath); err != nil {
		return err
	}
	fmt.Printf("Approved in %s at generation %d: %d state(s) in %s\n", slotsText(slots), ca.FileGeneration(), len(ca.Approvals), caPath)
	return nil
}

// slotsDefault is what 'ca approve' approves without --slot: every slot
// assh.conf names, else slot 0.
func slotsDefault(cfg config.Config) string {
	if len(cfg.Slots) == 0 {
		return "0"
	}
	return numbers(cfg.SlotNumbers())
}

// numbers is "0,2,7".
func numbers(n []int) string {
	s := make([]string, len(n))
	for i, v := range n {
		s[i] = strconv.Itoa(v)
	}
	return strings.Join(s, ",")
}

// parseSlots reads "0,1": slots of ca, each once.
func parseSlots(ca *hostkey.CA, s string) ([]int, error) {
	var slots []int
	for _, f := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil {
			return nil, fmt.Errorf("--slot %q: %w", s, err)
		}
		if ca.Slot(n) == nil {
			return nil, fmt.Errorf("no slot %d", n)
		}
		if slices.Contains(slots, n) {
			return nil, fmt.Errorf("--slot %q names slot %d twice", s, n)
		}
		slots = append(slots, n)
	}
	return slots, nil
}

// slotsText is "slot 0" or "slots 0 and 1".
func slotsText(slots []int) string {
	if len(slots) == 1 {
		return fmt.Sprintf("slot %d", slots[0])
	}
	return "slots " + strings.TrimPrefix(hostkey.PCRList(slots), "PCR ")
}

// listApprovals prints each slot's approvals, those below gen as revoked.
func listApprovals(ca *hostkey.CA, gen uint64) {
	for _, slot := range ca.Slots {
		fmt.Printf("  slot %d, %s:\n", slot.Number, hostkey.PCRList(slot.PCRs))
		n := 0
		for _, a := range ca.Approvals {
			if a.Slot != slot.Number {
				continue
			}
			n++
			var vals []string
			for _, p := range slot.PCRs {
				vals = append(vals, fmt.Sprintf("%d=%s…", p, hex.EncodeToString(a.PCRs[p])[:12]))
			}
			state := ""
			if ca.Counter != nil {
				state = fmt.Sprintf(" generation %d", a.Generation)
				if a.Generation < gen {
					state += " (revoked)"
				}
			}
			fmt.Printf("    approval %d:%s %s\n", n, state, strings.Join(vals, " "))
		}
		if n == 0 {
			fmt.Println("    no approval")
		}
	}
}

func parseHandle(s string) (tpm2.TPMHandle, error) {
	v, err := strconv.ParseUint(s, 0, 32)
	if err != nil {
		return 0, fmt.Errorf("not an NV handle: %q", s)
	}
	return tpm2.TPMHandle(v), nil
}

func printDA(tpm transport.TPM) {
	s, err := tpmadmin.ReadDA(tpm)
	if err != nil {
		fmt.Println("The dictionary attack state:", err)
		return
	}
	fmt.Printf("Dictionary attack protection (for the whole TPM): %d of %d failures", s.Failures, s.MaxTries)
	if s.InLockout {
		fmt.Print(", locked out")
	}
	fmt.Printf("; one failure forgotten every %d s; lockout authorization retry after %d s\n", s.Recovery, s.LockoutRecovery)
	if !s.LockoutAuthSet {
		fmt.Println("WARNING: the TPM has no lockout authorization: any process can reset the lockout and try PINs without end (assh tpm da --new-lockout-auth)")
	}
}

func tpmCommand(args []string) error {
	if len(args) > 0 && args[0] == "sha1" {
		return sha1Command(args[1:])
	}
	if len(args) == 0 || args[0] != "da" {
		return errors.New("tpm needs sha1 or da")
	}
	fs := flag.NewFlagSet("tpm da", flag.ExitOnError)
	cfg, err := commandConfig(fs, args[1:])
	if err != nil {
		return err
	}
	tpmPath := fs.String("tpm", cfg.TPM, "the TPM")
	maxTries := fs.Uint("max-tries", 0, "authorization failures that lock the TPM out (with --recovery and --lockout-recovery)")
	recovery := fs.Uint("recovery", 0, "seconds after which one failure is forgotten")
	lockoutRecovery := fs.Uint("lockout-recovery", 0, "seconds after a wrong lockout authorization before the next try")
	reset := fs.Bool("reset", false, "forget the counted failures and end a lockout")
	lockoutFd := fs.Int("lockout-auth-fd", -1, "read the lockout authorization from this file descriptor; default: empty, or ask the terminal when --ask-lockout-auth")
	askLockout := fs.Bool("ask-lockout-auth", false, "ask the terminal for the lockout authorization")
	newLockout := fs.Bool("new-lockout-auth", false, "set a lockout authorization, asked twice on the terminal")
	newLockoutFd := fs.Int("new-lockout-auth-fd", -1, "set a lockout authorization read from this file descriptor")
	fs.Parse(args[1:])
	set := 0
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "max-tries", "recovery", "lockout-recovery":
			set++
		}
	})
	if set != 0 && set != 3 {
		return errors.New("tpm da needs --max-tries, --recovery and --lockout-recovery together")
	}
	tpm, err := openTPM(*tpmPath)()
	if err != nil {
		return err
	}
	defer tpm.Close()
	var lockout []byte
	if *lockoutFd >= 0 || *askLockout {
		if lockout, err = readSecret(*lockoutFd, "lockout authorization", false); err != nil {
			return err
		}
		defer clear(lockout)
	}
	if *newLockout || *newLockoutFd >= 0 {
		n, err := readSecret(*newLockoutFd, "new lockout authorization", true)
		if err != nil {
			return err
		}
		defer clear(n)
		if err := tpmadmin.SetLockoutAuth(tpm, lockout, n); err != nil {
			return err
		}
		lockout = append([]byte(nil), n...)
		fmt.Println("The lockout authorization is set. Keep it off this machine: it resets the lockout and clears the TPM.")
	}
	if set == 3 {
		if err := tpmadmin.SetDA(tpm, lockout, uint32(*maxTries), uint32(*recovery), uint32(*lockoutRecovery)); err != nil {
			return err
		}
		fmt.Println("The dictionary attack parameters are set, for every user of the TPM.")
	}
	if *reset {
		if err := tpmadmin.ResetDA(tpm, lockout); err != nil {
			return err
		}
		fmt.Println("The counted failures are forgotten.")
	}
	printDA(tpm)
	return nil
}

// sha1Command allows or forbids SHA-1 on the TPM and says what it is.
func sha1Command(args []string) error {
	fs := flag.NewFlagSet("tpm sha1", flag.ExitOnError)
	cfg, err := commandConfig(fs, args)
	if err != nil {
		return err
	}
	tpmPath := fs.String("tpm", cfg.TPM, "the TPM")
	allow := fs.Bool("allow", false, "allow SHA-1 where the TPM has no active SHA-256 bank")
	forbid := fs.Bool("forbid", false, "forbid it again")
	fs.Parse(args)
	if *allow && *forbid {
		return errors.New("tpm sha1 takes --allow or --forbid")
	}
	tpm, err := openTPM(*tpmPath)()
	if err != nil {
		return err
	}
	defer tpm.Close()
	if *allow || *forbid {
		if err := hostkey.AllowSHA1(tpm, *allow); err != nil {
			return err
		}
	}
	active, err := hostkey.ActiveBanks(tpm)
	if err != nil {
		return err
	}
	ok, err := hostkey.SHA1Allowed(tpm)
	if err != nil {
		return err
	}
	names := make([]string, len(active))
	for i, b := range active {
		names[i] = string(b)
	}
	fmt.Printf("active PCR banks: %s\n", strings.Join(names, ", "))
	fmt.Printf("sha1 allowed: %v (NV index 0x%08X)\n", map[bool]string{true: "yes", false: "no"}[ok], uint32(hostkey.SHA1Handle))
	if b, err := hostkey.ResolveBank(tpm, hostkey.Auto); err != nil {
		fmt.Printf("bank auto: none (%v)\n", err)
	} else {
		fmt.Printf("bank auto: %s\n", b)
	}
	return nil
}

// stateFile is what 'serve' and 'agent' record of the PCRs before they
// close the window: the state to approve, which the TPM no longer holds.
type stateFile struct {
	Bank hostkey.Bank      `json:"bank"`
	PCRs map[string]string `json:"pcrs"` // index: hex
}

// recordState writes the PCR state of the boot's first start to path: an
// existing file is kept. A later start of the same boot (a restart) finds
// the window closed, and its state is none a boot ever has again; path is in
// /run, so a reboot starts it afresh.
func recordState(path string, bank hostkey.Bank, values map[int][]byte, log func(string)) {
	if path == "" {
		return
	}
	if _, err := os.Stat(path); err == nil {
		log("the PCR state of this boot's first start stays in " + path)
		return
	}
	if err := writeState(path, bank, values); err != nil {
		log("the PCR state is not recorded: " + err.Error())
	}
}

func writeState(path string, bank hostkey.Bank, values map[int][]byte) error {
	s := stateFile{Bank: bank, PCRs: map[string]string{}}
	for i, v := range values {
		s.PCRs[fmt.Sprint(i)] = hex.EncodeToString(v)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// eventList is --events: PCR:EVENT, in order.
type eventList []string

func (e *eventList) String() string     { return strings.Join(*e, " ") }
func (e *eventList) Set(v string) error { *e = append(*e, v); return nil }

// apply puts the value each named PCR has after its events, from zero,
// into values; every PCR named must be one the CA's slots read.
func (e eventList) apply(ca *hostkey.CA, values map[int][]byte) error {
	byPCR := map[int][]string{}
	var order []int
	for _, v := range e {
		k, ev, ok := strings.Cut(v, ":")
		i, err := strconv.Atoi(k)
		if !ok || err != nil || ev == "" {
			return fmt.Errorf("--events %q: PCR:EVENT", v)
		}
		if !slices.Contains(ca.PCRs(), i) {
			return fmt.Errorf("--events %q: no slot of the CA reads PCR %d", v, i)
		}
		if _, seen := byPCR[i]; !seen {
			order = append(order, i)
		}
		byPCR[i] = append(byPCR[i], ev)
	}
	for _, i := range order {
		v, err := hostkey.EventChain(ca.Bank, byPCR[i])
		if err != nil {
			return err
		}
		values[i] = v
	}
	return nil
}

func approveValues(ca *hostkey.CA, path, tpmPath string) (map[int][]byte, error) {
	if path == "" {
		tpm, err := openTPM(tpmPath)()
		if err != nil {
			return nil, err
		}
		defer tpm.Close()
		return ca.ReadPCRs(tpm)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s stateFile
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s.Bank != ca.Bank {
		return nil, fmt.Errorf("%s holds %s values, the CA reads %s", path, s.Bank, ca.Bank)
	}
	out := map[int][]byte{}
	for k, v := range s.PCRs {
		var i int
		if _, err := fmt.Sscan(k, &i); err != nil {
			return nil, fmt.Errorf("%s: PCR %q", path, k)
		}
		if out[i], err = hex.DecodeString(v); err != nil {
			return nil, fmt.Errorf("%s: PCR %d: %w", path, i, err)
		}
	}
	return out, nil
}

func readPublicKey(path string) (crypto.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM", path)
	}
	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "CERTIFICATE":
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return c.PublicKey, nil
	}
	return nil, fmt.Errorf("%s: a PEM %q, not a PUBLIC KEY", path, block.Type)
}

func readPrivateKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM", path)
	}
	var key any
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%s: a PEM %q", path, block.Type)
	}
	if err != nil {
		return nil, err
	}
	s, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s: no signing key", path)
	}
	return s, nil
}

// hostKeyFlags are what 'serve' and 'agent' share.
type hostKeyFlags struct {
	tpm, ca, state, keyType, principals, keyID string
	closePCR                                   int
	// conf is assh.conf: its slots and window are what a CA not created
	// yet will read (noCA).
	conf config.Config
}

func (h *hostKeyFlags) add(fs *flag.FlagSet, cfg config.Config, defaultState string) {
	if cfg.State != "" {
		defaultState = cfg.State
	}
	h.conf = cfg
	fs.StringVar(&h.tpm, "tpm", cfg.TPM, "the TPM")
	fs.StringVar(&h.ca, "ca", cfg.CA, "the CA file ('ca create')")
	fs.StringVar(&h.state, "state", defaultState, "where the PCR values of the boot's first start are written, for 'ca approve --values' (kept when there: a restart finds the window closed; put it in /run)")
	fs.StringVar(&h.keyType, "key-type", string(cfg.HostKeyType), "the host key: p256 or rsa2048, or a list in order of preference (the first the TPM takes)")
	fs.StringVar(&h.principals, "principals", strings.Join(cfg.Principals, ","), "the host names the certificate is valid for, comma-separated; * any (the clients' known_hosts patterns still choose the hosts)")
	fs.StringVar(&h.keyID, "key-id", cfg.KeyID, "the certificate's name in the clients' logs")
	fs.IntVar(&h.closePCR, "close-pcr", cfg.ClosePCR, "extend this PCR after the host key is made: the CA signs nothing more until the next boot (default: the CA's window; every slot must read it)")
}

// issue makes this boot's host key: certified through the first slot
// approved for the PCRs as they are, else temporary. The window is closed
// whatever comes of it: an approval for the state recorded is made
// afterwards, and takes effect at the next boot.
func (h *hostKeyFlags) issue(log func(string)) (*hostkey.HostKey, error) {
	if err := hostkey.NoDump(); err != nil {
		log("this process can be dumped: " + err.Error())
	}
	typ, err := hostkey.ParseType(h.keyType)
	if err != nil {
		return nil, err
	}
	ca, err := hostkey.LoadCA(h.ca)
	if os.IsNotExist(err) && len(h.conf.Slots) > 0 {
		return h.noCA(typ, log)
	}
	if err != nil {
		return nil, err
	}
	closePCR := h.closePCR
	if closePCR < 0 && ca.Window != 0 {
		closePCR = ca.Window
	}
	if closePCR >= 0 {
		for _, s := range ca.Slots {
			if !slices.Contains(s.PCRs, closePCR) {
				return nil, fmt.Errorf("slot %d does not read PCR %d: extending it would not close that slot", s.Number, closePCR)
			}
		}
	}
	open := openTPM(h.tpm)
	tpm, err := open()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()
	if h.conf.Bank == hostkey.Auto && ca.Bank == hostkey.SHA1 {
		// auto reads SHA-1 only while the TPM allows it.
		if ok, err := hostkey.SHA1Allowed(tpm); err != nil {
			return nil, err
		} else if !ok {
			return h.temporary(tpm, open, typ, closePCR, fmt.Errorf("the CA reads sha1, and sha1 is no longer allowed on this TPM ('assh tpm sha1 --allow')"), log)
		}
	}
	if values, err := ca.ReadPCRs(tpm); err != nil {
		return nil, err
	} else {
		recordState(h.state, ca.Bank, values, log)
	}
	principals := config.SplitList(h.principals)
	hk, ierr := hostkey.Issue(tpm, ca, hostkey.IssueOptions{Type: typ, Principals: principals, KeyID: h.keyID, Open: open})
	if closePCR >= 0 {
		if err := hostkey.Close(tpm, closePCR, "assh: closed"); err != nil {
			return nil, err
		}
		log(fmt.Sprintf("PCR %d is extended: the CA signs nothing more until the next boot", closePCR))
	}
	if ierr != nil {
		return nil, ierr
	}
	if hk.Temporary != nil {
		log(fmt.Sprintf("host key %s is TEMPORARY: the CA did not certify one (%v). ssh will report an unknown host key: compare its fingerprint with this one", hk.Fingerprint(), hk.Temporary))
		var m *hostkey.MismatchError
		if errors.As(hk.Temporary, &m) && h.state != "" {
			log(fmt.Sprintf("if this state is right: assh ca approve --ca %s --slot N --values %s ..., and reboot", h.ca, h.state))
		}
		return hk, nil
	}
	log(fmt.Sprintf("host key %s, certified by the CA %s through slot %d", hk.Fingerprint(), ca.Fingerprint(), hk.Slot))
	return hk, nil
}

// noCA is a boot before the CA is created: assh.conf names its slots, so
// the PCRs they read are recorded as at a boot with the CA, for the
// creation to approve ('ca approve --values'); the host key is temporary,
// and the window is closed all the same - else, once the CA is created and
// approved in this boot, any process could have it certify.
func (h *hostKeyFlags) noCA(typ hostkey.Type, log func(string)) (*hostkey.HostKey, error) {
	closePCR := h.closePCR
	if closePCR < 0 {
		closePCR = h.conf.Window
	}
	var pcrs []int
	for _, n := range h.conf.SlotNumbers() {
		for _, p := range h.conf.Slots[n] {
			if !slices.Contains(pcrs, p) {
				pcrs = append(pcrs, p)
			}
		}
	}
	slices.Sort(pcrs)
	open := openTPM(h.tpm)
	tpm, err := open()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()
	bank, err := hostkey.ResolveBank(tpm, h.conf.Bank)
	if err != nil {
		// No CA can be made on this TPM as assh.conf says: nothing to record.
		return h.temporary(tpm, open, typ, closePCR, fmt.Errorf("no CA at %s, and none can be made: %w", h.ca, err), log)
	}
	values, err := hostkey.ReadPCRs(tpm, bank, pcrs)
	if err != nil {
		return nil, err
	}
	recordState(h.state, bank, values, log)
	hk, err := hostkey.TemporaryKey(tpm, fmt.Errorf("no CA at %s yet", h.ca), hostkey.IssueOptions{Type: typ, Open: open})
	if closePCR > 0 {
		if cerr := hostkey.Close(tpm, closePCR, "assh: closed"); cerr != nil {
			return nil, cerr
		}
		log(fmt.Sprintf("PCR %d is extended: no CA created in this boot can sign before the next one", closePCR))
	}
	if err != nil {
		return nil, err
	}
	log(fmt.Sprintf("host key %s is TEMPORARY: there is no CA at %s yet. The PCR state of its slots is recorded in %s: create the CA and approve it there (assh ca create, then assh ca approve --values %s); the next boot certifies", hk.Fingerprint(), h.ca, h.state, h.state))
	return hk, nil
}

// temporary is the host key of a boot whose CA cannot sign, for why: made
// in the TPM, not certified; the window is closed all the same.
func (h *hostKeyFlags) temporary(tpm transport.TPM, open func() (transport.TPMCloser, error), typ hostkey.Type, closePCR int, why error, log func(string)) (*hostkey.HostKey, error) {
	hk, err := hostkey.TemporaryKey(tpm, why, hostkey.IssueOptions{Type: typ, Open: open})
	if closePCR > 0 {
		if cerr := hostkey.Close(tpm, closePCR, "assh: closed"); cerr != nil {
			return nil, cerr
		}
		log(fmt.Sprintf("PCR %d is extended: the CA signs nothing more until the next boot", closePCR))
	}
	if err != nil {
		return nil, err
	}
	log(fmt.Sprintf("host key %s is TEMPORARY: %v", hk.Fingerprint(), why))
	return hk, nil
}

func logger(s string) { fmt.Fprintln(os.Stderr, "assh:", s) }

// waitForSignal returns at SIGTERM or SIGINT.
func waitForSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	<-ch
}
