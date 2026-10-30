// Command assh is an SSH server whose host key lives in the TPM, and an
// agent that lends such a key to OpenSSH's sshd. See README.md.
package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"

	"github.com/tpm2-trust/assh/config"
	"github.com/tpm2-trust/assh/hostkey"
	"github.com/tpm2-trust/assh/persist"
	"github.com/tpm2-trust/assh/tpmadmin"
)

const usage = `assh - an SSH host key in the TPM

  assh ca create   --out FILE (--authority PUB.pem | --authority-tpm | --authority-once [--values FILE] [--events PCR:EVENT ...])
                   [--type p256|rsa2048] [--pcrs 0,7] [--bank sha256|sha1|auto] [--ref TEXT]
                   [--window-handle 0x01802915] [--pin-handle 0x01802913] [--counter-handle 0x01802912]
                   [--pin-fd N] [--pcr-key PEM]
  assh ca show     --ca FILE
  assh ca approve  --ca FILE [--slot N[,N...]] [--values FILE] [--yes]
                   authority in the TPM: [--next-generation] [--redefine-counter] [--pin-fd N]
                   [--events PCR:EVENT ...]: that PCR as from zero with these events
                   key elsewhere: (--authority-key KEY.pem | --signature FILE | --digest FILE)
  assh ca sign     --authority-key KEY.pem --statement FILE --signature OUT [--yes]
                                 where the key is: signs what the statement says
  assh ca pin      --ca FILE [--pin-fd N] [--new-pin-fd N]
  assh ca remove   --ca FILE [--force [--yes]]
                                 the CA and its window index, PIN index and counter
  assh tpm sha1    [--allow | --forbid]
  assh tpm da      [--max-tries 3 --recovery 1800 --lockout-recovery 1800] [--reset]
                   [--lockout-auth-fd N | --ask-lockout-auth]
                   [--new-lockout-auth | --new-lockout-auth-fd N]
  assh efivar get  NAME          an EFI variable's value, without its attributes
  assh efivar set  NAME VALUE | [--file FILE] NAME
                                 written in place, in one write
  assh efivar rm   NAME          removed (none there is not an error)
  assh serve       --ca FILE --authorized-keys FILE (-- COMMAND ... | --socket PATH)
                   [--listen :22] [--user NAME] [HOST KEY OPTIONS]
  assh agent       --ca FILE [--dir /run/assh] [--uid 0] [HOST KEY OPTIONS]
  assh close       [--ca FILE]   the window closed, nothing else (after the agent)

Host key options: [--key-type p256|rsa2048] [--principals '*'] [--key-id TEXT]
                  [--close-pcr N] [--state FILE]

Every command takes --config FILE, assh.conf (default ` + config.DefaultPath + ` when it
is there): KEY=VALUE lines that set what the flags set - ASSH_CA,
ASSH_CA_SLOT_<N>=PCRs, ASSH_LISTEN, ASSH_AUTHORIZED_KEYS
and the rest (README) - so that 'assh agent --config FILE' is all a
service needs; a flag given wins over the file. The CA's slots are the
file's: 'ca create' makes them, and every command - 'agent' at its start -
takes the file's slots as they are now (a slot gone or changed loses its
approvals, a new one has none).
Every command takes --tpm PATH (default /dev/tpmrm0). A CA FILE may be an
EFI variable instead, efi:NAME (efivarfs, vendor GUID ` + persist.VarGUID + `):
where nothing else survives a reboot, or outside the boot image a slot
measures. 'efivar' reads, writes and removes such variables - aSSH's
(NAME) or another vendor's (NAME-GUID) - the way the CA's are: written
in place, never removed first, the immutable mark lifted and put back.
ASSH_EFIVARS in the environment points it at another directory than
efivarfs (tests).

The CA is created in the TPM and never leaves it. It has up to 16 slots,
each a PCR selection (ASSH_CA_SLOT_<N>; 'ca create --pcrs' is slot 0),
and signs while the PCRs hold a state the authority approved in a slot
('ca approve --slot'); the slots are tried from 0 up. Its window is an NV
index its own policy reads: read-locked, the CA signs nothing until the
next boot, whatever an approval says - and it is locked in the boot that
creates the CA. 'ca approve' shows what it approves and asks; '--digest'
writes it as a statement, which 'ca sign' signs where the key is. The
authority is a key elsewhere, or a key in the TPM opened by a PIN; then
every approval names a generation of a counter in the TPM, and
'ca approve --next-generation' revokes every approval made before. A PIN or
a lockout authorization is read from the terminal or a file descriptor
(--pin-fd), never from the command line or the environment. 'serve'
and 'agent' make a host key in the TPM at their start - gone at the next
reboot - and have the CA certify it; then they close the CA's window,
also when anything failed ('close' does it after the agent, however it
ended), so the CA signs nothing more until the next boot. When no
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
	if d := os.Getenv("ASSH_EFIVARS"); d != "" {
		persist.VarDir = d
	}
	var err error
	switch os.Args[1] {
	case "ca":
		err = caCommand(os.Args[2:])
	case "tpm":
		err = tpmCommand(os.Args[2:])
	case "efivar":
		err = efivarCommand(os.Args[2:])
	case "serve":
		err = serveCommand(os.Args[2:])
	case "agent":
		err = agentCommand(os.Args[2:])
	case "close":
		err = closeCommand(os.Args[2:])
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
		return errors.New("ca needs create, show, approve, sign, pin or remove")
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
			slot0 = hostkey.Numbers(p)
		}
		pcrs := fs.String("pcrs", slot0, "slot 0's PCRs (the other slots are assh.conf's)")
		windowHandle := fs.String("window-handle", fmt.Sprintf("0x%08X", cfg.WindowHdl), "the NV handle of the CA's window index: read-locked, it closes the CA until the next boot")
		bank := fs.String("bank", string(cfg.Bank), "their bank: sha256, sha1, or auto (sha256 where the TPM has it, else sha1 where 'tpm sha1 --allow' allows it)")
		ref := fs.String("ref", cfg.PolicyRef, "what the authority's approvals are bound to (at most 32 bytes)")
		authOnce := fs.Bool("authority-once", cfg.AuthOnce, "an authority for the creation alone: it approves every slot now and is gone - no approval ever after")
		valuesPath := fs.String("values", "", "--authority-once: the PCR values to approve, as 'agent' recorded them; default: what the TPM holds now")
		var events eventList
		fs.Var(&events, "events", "--authority-once: PCR:EVENT - that PCR approved as from zero with these events in order (a state known before it is booted); repeatable")
		pcrKey := fs.String("pcr-key", cfg.PCRKey, "the public key (PEM) whose signatures the slots of ASSH_CA_SLOT_<N>_SIGNED take")
		fs.Parse(args[1:])
		cfg.PCRKey = *pcrKey
		if *out == "" || btoi(*authPath != "")+btoi(*authTPM)+btoi(*authOnce) != 1 {
			return errors.New("ca create needs --out, and one of --authority, --authority-tpm and --authority-once")
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
		cfg.Slots = maps.Clone(cfg.Slots)
		if cfg.Slots == nil {
			cfg.Slots = map[int][]int{}
		}
		cfg.Slots[0] = p
		slots, err := slotSpecs(cfg)
		if err != nil {
			return err
		}
		tpm, err := openTPM(*tpmPath)()
		if err != nil {
			return err
		}
		defer tpm.Close()
		wh, err := parseHandle(*windowHandle)
		if err != nil {
			return err
		}
		opts := hostkey.CAOptions{Type: t, Bank: b, Slots: slots, WindowHandle: wh, PolicyRef: []byte(*ref)}
		var ca *hostkey.CA
		if *authOnce {
			// The values every slot is approved for, as the slots will hold
			// them: from a recorded state or the TPM, PCRs named in --events
			// calculated.
			if opts.Bank, err = hostkey.ResolveBank(tpm, b); err != nil {
				return err
			}
			var values map[int][]byte
			if *valuesPath != "" {
				if values, err = readState(*valuesPath, opts.Bank); err != nil {
					return err
				}
			} else if values, err = hostkey.ReadPCRs(tpm, opts.Bank, cfg.PCRs()); err != nil {
				return err
			}
			if err := events.apply(opts.Bank, cfg.PCRs(), values); err != nil {
				return err
			}
			if ca, err = hostkey.CreateOnceCA(tpm, opts, values); err != nil {
				return err
			}
		} else if *authTPM {
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
		if err := ca.Save(*out); err != nil {
			return err
		}
		if !persist.IsVar(*out) {
			pub, _ := ca.AuthorizedKey()
			if err := os.WriteFile(*out+".pub", pub, 0o644); err != nil {
				return err
			}
		}
		fmt.Print(ca.Describe())
		line, _ := ca.KnownHosts("*")
		fmt.Printf("Clients trust it with this known_hosts line (narrow the * to the host's names):\n  %s\n", line)
		fmt.Println("Its window is closed in this boot: it signs from the next boot on.")
		if !*authOnce {
			fmt.Printf("Approve the PCR state it may sign in: assh ca approve --ca %s ...\n", *out)
		}
		return nil
	case "show":
		caPath := fs.String("ca", cfg.CA, "the CA file")
		fs.Parse(args[1:])
		ca, err := loadCA(*caPath, cfg, say)
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
		open, werr := ca.WindowOpen(tpm)
		switch {
		case werr != nil:
			fmt.Println(werr)
		case !open:
			fmt.Println("The window is closed until the next boot: the CA signs nothing now.")
		}
		if now, err := ca.ReadPCRs(tpm); err == nil {
			if a := ca.Approved(now, pcrSignatures(cfg.PCRSigs, say)); a != nil && a.Generation == gen {
				if open {
					fmt.Printf("The PCRs hold a state approved in slot %d now, and the window is open: the CA signs.\n", a.Slot)
				} else {
					fmt.Printf("The PCRs hold a state approved in slot %d now.\n", a.Slot)
				}
			} else {
				fmt.Println("The PCRs hold no approved state now.")
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
		yes := fs.Bool("yes", false, "approve what is shown without asking (scripts); default: ask on the terminal")
		fs.Parse(args[1:])
		ca, err := loadCA(*caPath, cfg, say)
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
		if err := events.apply(ca.Bank, ca.PCRs(), values); err != nil {
			return err
		}
		if err := checkSignedKeys(ca, slots, cfg.PCRKey); err != nil {
			return err
		}
		// What is signed is shown first: neither the CA file nor assh.conf
		// is trusted, whoever approves reads it. A signature made
		// elsewhere was decided there.
		if *sigPath == "" && *digestPath == "" {
			if err := showAndConfirm(ca, slots, values, *next || *redefine, *yes); err != nil {
				return err
			}
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
			// The digest, and beside it the statement it follows from: the
			// signer computes the digest from what it reads (ca sign).
			st, err := ca.Statement(slot, values)
			if err != nil {
				return err
			}
			d, err := st.Digest()
			if err != nil {
				return err
			}
			b, err := st.Marshal()
			if err != nil {
				return err
			}
			if err := os.WriteFile(*digestPath, d, 0o644); err != nil {
				return err
			}
			if err := os.WriteFile(*digestPath+".statement", b, 0o644); err != nil {
				return err
			}
			fmt.Print(st)
			fmt.Printf("Where the authority's key is: assh ca sign --authority-key AUTHORITY.key --statement %s.statement --signature SIG\n", *digestPath)
			fmt.Printf("then here: assh ca approve --ca %s --slot %d --signature SIG", *caPath, slot)
			if *valuesPath != "" {
				fmt.Printf(" --values %s", *valuesPath)
			}
			fmt.Printf("\n(The digest alone, SHA-256 %s, is in %s.)\n", hex.EncodeToString(d), *digestPath)
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
	case "sign":
		keyPath := fs.String("authority-key", "", "the authority's private key (PEM)")
		stPath := fs.String("statement", "", "the statement 'ca approve --digest' wrote")
		sigPath := fs.String("signature", "", "where the signature goes, for 'ca approve --signature'")
		yes := fs.Bool("yes", false, "sign what is shown without asking (scripts)")
		fs.Parse(args[1:])
		if *keyPath == "" || *stPath == "" || *sigPath == "" {
			return errors.New("ca sign needs --authority-key, --statement and --signature")
		}
		b, err := os.ReadFile(*stPath)
		if err != nil {
			return err
		}
		st, err := hostkey.ParseStatement(b)
		if err != nil {
			return fmt.Errorf("%s: %w", *stPath, err)
		}
		key, err := readPrivateKey(*keyPath)
		if err != nil {
			return err
		}
		if fp := keyFingerprint(key.Public()); fp != st.Authority {
			return fmt.Errorf("the statement is for the authority %s, the key is %s", st.Authority, fp)
		}
		fmt.Print(st)
		if err := confirm("Sign this approval", *yes); err != nil {
			return err
		}
		d, err := st.Digest()
		if err != nil {
			return err
		}
		sig, err := key.Sign(rand.Reader, d, crypto.SHA256)
		if err != nil {
			return err
		}
		if err := os.WriteFile(*sigPath, sig, 0o644); err != nil {
			return err
		}
		fmt.Printf("Signed: %s. Add it where the CA is: assh ca approve --slot %d --signature %s (and the --values it was made with)\n", *sigPath, st.Slot, *sigPath)
		return nil
	case "remove":
		caPath := fs.String("ca", cfg.CA, "the CA file, or efi:NAME")
		pinHandle := fs.String("pin-handle", fmt.Sprintf("0x%08X", cfg.PINHandle), "with no CA file: the PIN index's handle")
		counterHandle := fs.String("counter-handle", fmt.Sprintf("0x%08X", cfg.CounterHdl), "with no CA file: the counter's handle")
		windowHandle := fs.String("window-handle", fmt.Sprintf("0x%08X", cfg.WindowHdl), "with no CA file: the window index's handle")
		force := fs.Bool("force", false, "also remove what is at these handles and is not defined as aSSH's (a previous installation's leftovers): each shown first")
		yes := fs.Bool("yes", false, "--force: remove what is shown without asking (scripts)")
		fs.Parse(args[1:])
		var h hostkey.Handles
		for _, x := range []struct {
			s string
			h *tpm2.TPMHandle
		}{{*pinHandle, &h.PIN}, {*counterHandle, &h.Counter}, {*windowHandle, &h.Window}} {
			v, err := parseHandle(x.s)
			if err != nil {
				return err
			}
			*x.h = v
		}
		tpm, err := openTPM(*tpmPath)()
		if err != nil {
			return err
		}
		defer tpm.Close()
		removed, err := hostkey.RemoveCA(tpm, *caPath, h)
		for _, r := range removed {
			fmt.Println("removed", r)
		}
		if errors.Is(err, hostkey.ErrLeft) && *force {
			return removeForce(tpm, h, *yes)
		}
		if errors.Is(err, hostkey.ErrLeft) {
			return fmt.Errorf("%w (an index of a previous installation: --force removes it, after showing it)", err)
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
		ca, err := loadCA(*caPath, cfg, say)
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
	return hostkey.Numbers(cfg.SlotNumbers())
}

// loadCA is the CA at path with assh.conf's slots: what every command
// works with, so that a slot changed in the file counts at the next start.
// The file keeps what it has until a command saves the CA. Where assh.conf
// does not fit the CA (another window, say), the CA's own slots, and warn
// says why. Without slots in assh.conf, the CA as it is.
func loadCA(path string, cfg config.Config, warn func(string)) (*hostkey.CA, error) {
	ca, err := hostkey.LoadCA(path)
	if err != nil || len(cfg.Slots) == 0 {
		return ca, err
	}
	if changed, err := cfg.Match(ca); err != nil {
		warn("assh.conf's slots are not applied: " + err.Error())
	} else if changed {
		warn("the CA's slots are assh.conf's: " + strings.TrimSpace(ca.Describe()))
	}
	return ca, nil
}

func say(s string) { fmt.Println(s) }

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

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// slotSpecs are assh.conf's slots, their signed PCRs
// (ASSH_CA_SLOT_<N>_SIGNED) with ASSH_PCR_KEY.
func slotSpecs(cfg config.Config) ([]hostkey.SlotSpec, error) {
	var key crypto.PublicKey
	if len(cfg.Signed) > 0 {
		var err error
		if key, err = readPublicKey(cfg.PCRKey); err != nil {
			return nil, fmt.Errorf("ASSH_PCR_KEY: %w", err)
		}
	}
	var out []hostkey.SlotSpec
	for _, n := range cfg.SlotNumbers() {
		s := hostkey.SlotSpec{Number: n, PCRs: cfg.Slots[n]}
		if p, ok := cfg.Signed[n]; ok {
			var err error
			if s.Signed, err = hostkey.NewSigned(p, key); err != nil {
				return nil, fmt.Errorf("ASSH_CA_SLOT_%d_SIGNED: %w", n, err)
			}
		}
		out = append(out, s)
	}
	return out, nil
}

// pcrSignatures are ASSH_PCR_SIGNATURE's signatures; none where the file is
// not there (a slot with signed PCRs then is not met).
func pcrSignatures(path string, log func(string)) hostkey.PCRSignatures {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		log(fmt.Sprintf("no signatures of PCRs (%v): a slot with signed PCRs is not met", err))
		return nil
	}
	p, err := hostkey.ParsePCRSignatures(b)
	if err != nil {
		log(fmt.Sprintf("%s: %v", path, err))
		return nil
	}
	return p
}

// eventList is --events: PCR:EVENT, in order.
type eventList []string

func (e *eventList) String() string     { return strings.Join(*e, " ") }
func (e *eventList) Set(v string) error { *e = append(*e, v); return nil }

// apply puts the value each named PCR of bank has after its events, from
// zero, into values; every PCR named must be among pcrs, the slots'.
func (e eventList) apply(bank hostkey.Bank, pcrs []int, values map[int][]byte) error {
	byPCR := map[int][]string{}
	var order []int
	for _, v := range e {
		k, ev, ok := strings.Cut(v, ":")
		i, err := strconv.Atoi(k)
		if !ok || err != nil || ev == "" {
			return fmt.Errorf("--events %q: PCR:EVENT", v)
		}
		if !slices.Contains(pcrs, i) {
			return fmt.Errorf("--events %q: no slot of the CA reads PCR %d", v, i)
		}
		if _, seen := byPCR[i]; !seen {
			order = append(order, i)
		}
		byPCR[i] = append(byPCR[i], ev)
	}
	for _, i := range order {
		v, err := hostkey.EventChain(bank, byPCR[i])
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
	return readState(path, ca.Bank)
}

// readState is a state file's values, which must be of bank.
func readState(path string, bank hostkey.Bank) (map[int][]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s stateFile
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s.Bank != bank {
		return nil, fmt.Errorf("%s holds %s values, the CA reads %s", path, s.Bank, bank)
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
	// conf is assh.conf: its slots are what a CA not created yet will read
	// (noCA), its window handle what is closed when the CA cannot be read.
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
	fs.IntVar(&h.closePCR, "close-pcr", cfg.ClosePCR, "also extend this PCR (0-15) when the window closes, for what others bind to it (default: none)")
}

// issue makes this boot's host key: certified through the first slot
// approved for the PCRs as they are, else temporary. Once the TPM is open,
// the window is closed on every way out - a host key made, an error at any
// step - so that no failure leaves the CA signing for the rest of the boot:
// an approval for the state recorded is made afterwards, and takes effect
// at the next boot.
func (h *hostKeyFlags) issue(log func(string)) (hk *hostkey.HostKey, err error) {
	if err := hostkey.NoDump(); err != nil {
		log("this process can be dumped: " + err.Error())
	}
	open := openTPM(h.tpm)
	tpm, err := waitTPM(h.tpm, open, log)
	if err != nil {
		return nil, err
	}
	defer tpm.Close()
	var ca *hostkey.CA
	defer func() {
		if cerr := h.closeWindow(tpm, ca, log); cerr != nil {
			hk, err = nil, errors.Join(err, cerr)
		}
	}()
	typ, err := hostkey.ParseType(h.keyType)
	if err != nil {
		return nil, err
	}
	ca, err = loadCA(h.ca, h.conf, log)
	if os.IsNotExist(err) && len(h.conf.Slots) > 0 {
		return h.noCA(tpm, open, typ, log)
	}
	if err != nil {
		return nil, err
	}
	o := hostkey.IssueOptions{Type: typ, Principals: config.SplitList(h.principals), KeyID: h.keyID, Open: open}
	if h.conf.Bank == hostkey.Auto && ca.Bank == hostkey.SHA1 {
		// auto reads SHA-1 only while the TPM allows it.
		if ok, err := hostkey.SHA1Allowed(tpm); err != nil {
			return nil, err
		} else if !ok {
			hk, err := hostkey.TemporaryKey(tpm, errors.New("the CA reads sha1, and sha1 is no longer allowed on this TPM ('assh tpm sha1 --allow')"), o)
			return h.temporary(hk, err, log)
		}
	}
	values, err := ca.ReadPCRs(tpm)
	if err != nil {
		return nil, err
	}
	recordState(h.state, ca.Bank, values, log)
	o.PCRSignatures = pcrSignatures(h.conf.PCRSigs, log)
	hk, err = hostkey.Issue(tpm, ca, o)
	if hk, err = h.temporary(hk, err, log); err != nil {
		return nil, err
	}
	if hk.Temporary == nil {
		log(fmt.Sprintf("host key %s, certified by the CA %s through slot %d", hk.Fingerprint(), ca.Fingerprint(), hk.Slot))
	} else if m := (*hostkey.MismatchError)(nil); errors.As(hk.Temporary, &m) && h.state != "" {
		log(fmt.Sprintf("if this state is right: assh ca approve --ca %s --slot N --values %s ..., and reboot", h.ca, h.state))
	}
	return hk, nil
}

// noCA is a boot before the CA is created: assh.conf names its slots, so
// the PCRs they read are recorded as at a boot with the CA, for the
// creation to approve ('ca approve --values'); the host key is temporary.
// A CA created in this boot signs from the next one on.
func (h *hostKeyFlags) noCA(tpm transport.TPM, open func() (transport.TPMCloser, error), typ hostkey.Type, log func(string)) (*hostkey.HostKey, error) {
	o := hostkey.IssueOptions{Type: typ, Open: open}
	bank, err := hostkey.ResolveBank(tpm, h.conf.Bank)
	if err != nil {
		// No CA can be made on this TPM as assh.conf says: nothing to record.
		return h.temporary(hostkey.TemporaryKey(tpm, fmt.Errorf("no CA at %s, and none can be made: %w", h.ca, err), o))
	}
	values, err := hostkey.ReadPCRs(tpm, bank, h.conf.PCRs())
	if err != nil {
		return nil, err
	}
	recordState(h.state, bank, values, log)
	hk, err := h.temporary(hostkey.TemporaryKey(tpm, fmt.Errorf("no CA at %s yet", h.ca), o))
	if err != nil {
		return nil, err
	}
	log(fmt.Sprintf("the PCR state of the slots is recorded in %s: create the CA and approve it there (assh ca create, then assh ca approve --values %s); the next boot certifies", h.state, h.state))
	return hk, nil
}

// temporary logs a temporary key.
func (h *hostKeyFlags) temporary(hk *hostkey.HostKey, err error, log ...func(string)) (*hostkey.HostKey, error) {
	if err != nil {
		return nil, err
	}
	if hk.Temporary != nil {
		l := logger
		if len(log) > 0 {
			l = log[0]
		}
		l(fmt.Sprintf("host key %s is TEMPORARY: %v. ssh reports an unknown host key: compare its fingerprint with this one", hk.Fingerprint(), hk.Temporary))
	}
	return hk, nil
}

// closeWindow closes the window: the CA's window index, or - when the CA
// could not be read - the one assh.conf names, if it is defined as a
// window; then the extra PCR, if one is set.
func (h *hostKeyFlags) closeWindow(tpm transport.TPM, ca *hostkey.CA, log func(string)) error {
	handle := tpm2.TPMHandle(h.conf.WindowHdl)
	if ca != nil && ca.WindowHandle() != 0 {
		handle = ca.WindowHandle()
	}
	var errs []error
	if there, err := hostkey.CloseWindow(tpm, handle); err != nil {
		errs = append(errs, err)
	} else if there {
		log(fmt.Sprintf("the window is closed (NV index 0x%08X): the CA signs nothing more until the next boot", uint32(handle)))
	}
	if h.closePCR >= 0 {
		if err := hostkey.ExtendPCR(tpm, h.closePCR, "assh: closed"); err != nil {
			errs = append(errs, err)
		} else {
			log(fmt.Sprintf("PCR %d is extended", h.closePCR))
		}
	}
	return errors.Join(errs...)
}

// waitTPM opens the TPM once its device is there: early in a boot it may
// come after the agent starts. A TPM that does not come within a minute
// is an error.
func waitTPM(path string, open func() (transport.TPMCloser, error), log func(string)) (transport.TPMCloser, error) {
	deadline := time.Now().Add(time.Minute)
	logged := false
	for {
		if _, err := os.Stat(path); err == nil || time.Now().After(deadline) {
			return open()
		}
		if !logged {
			log("waiting for the TPM at " + path)
			logged = true
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// closeCommand is 'close': the window closed, and nothing else - what the
// agent's unit runs after the agent, however it ended. An assh.conf that
// does not parse still closes the default window index.
func closeCommand(args []string) error {
	fs := flag.NewFlagSet("close", flag.ExitOnError)
	cfg, cerr := commandConfig(fs, args)
	if cerr != nil {
		logger("assh.conf: " + cerr.Error() + "; closing the default window index")
		cfg = config.Default()
	}
	var h hostKeyFlags
	h.add(fs, cfg, "")
	fs.Parse(args)
	tpm, err := waitTPM(h.tpm, openTPM(h.tpm), logger)
	if err != nil {
		return err
	}
	defer tpm.Close()
	var ca *hostkey.CA
	if h.ca != "" {
		if c, err := hostkey.LoadCA(h.ca); err == nil {
			ca = c
		}
	}
	if err := h.closeWindow(tpm, ca, logger); err != nil {
		return err
	}
	// The default too, when assh.conf did not parse or named another.
	if def := hostkey.DefaultWindowHandle; (ca == nil || ca.WindowHandle() != def) && tpm2.TPMHandle(cfg.WindowHdl) != def {
		if _, err := hostkey.CloseWindow(tpm, def); err != nil {
			logger(err.Error())
		}
	}
	return cerr
}

// checkSignedKeys refuses an approval of a slot whose signed PCRs' key is
// not assh.conf's ASSH_PCR_KEY: the CA file could name any key.
func checkSignedKeys(ca *hostkey.CA, slots []int, pcrKey string) error {
	for _, n := range slots {
		s := ca.Slot(n)
		if s == nil || s.Signed == nil {
			continue
		}
		if pcrKey == "" {
			return fmt.Errorf("slot %d takes signed PCRs: ASSH_PCR_KEY names the key that may sign them", n)
		}
		want, err := readPublicKey(pcrKey)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKIXPublicKey(want)
		if err != nil {
			return err
		}
		if !bytes.Equal(der, s.Signed.Key) {
			return fmt.Errorf("slot %d takes PCRs signed by %s, not by ASSH_PCR_KEY (%s): create the CA again", n, keyFingerprintDER(s.Signed.Key), keyFingerprint(want))
		}
	}
	return nil
}

// showAndConfirm prints what each slot's approval says and asks on the
// terminal, unless yes.
func showAndConfirm(ca *hostkey.CA, slots []int, values map[int][]byte, moving, yes bool) error {
	for _, n := range slots {
		st, err := ca.Statement(n, values)
		if err != nil {
			return err
		}
		if moving {
			st.Generation++
		}
		fmt.Print(st)
	}
	if moving {
		fmt.Println("The counter moves first: every approval before it is revoked.")
	}
	return confirm("Approve this", yes)
}

// confirm asks the terminal for a yes; without one, yes must be given.
func confirm(question string, yes bool) error {
	if yes {
		return nil
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("no terminal to confirm on: give --yes")
	}
	defer tty.Close()
	fmt.Fprintf(tty, "%s? [y/N] ", question)
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil {
		return errors.New("not confirmed")
	}
	if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
		return errors.New("not confirmed")
	}
	return nil
}

func keyFingerprint(k crypto.PublicKey) string {
	sk, err := ssh.NewPublicKey(k)
	if err != nil {
		return "?"
	}
	return ssh.FingerprintSHA256(sk)
}

func keyFingerprintDER(der []byte) string {
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "?"
	}
	return keyFingerprint(k)
}

// removeForce removes, after showing each and a confirmation, what is at
// aSSH's handles and is not defined as aSSH's: a previous installation's
// leftovers. Never a handle a CA file names.
func removeForce(tpm transport.TPM, h hostkey.Handles, yes bool) error {
	h = h.Defaults()
	var there []tpm2.TPMHandle
	for _, x := range []struct {
		what   string
		handle tpm2.TPMHandle
	}{{"PIN index", h.PIN}, {"counter", h.Counter}, {"window index", h.Window}} {
		pub, name, err := persist.ReadNVPublic(tpm, x.handle)
		if err != nil {
			continue
		}
		fmt.Printf("At aSSH's %s handle 0x%08X: an NV index of %d bytes, attributes 0x%08X, Name %x\n",
			x.what, uint32(x.handle), pub.DataSize, attributeBits(pub.Attributes), name.Buffer)
		there = append(there, x.handle)
	}
	if len(there) == 0 {
		return nil
	}
	if err := confirm("Remove these", yes); err != nil {
		return err
	}
	for _, handle := range there {
		if _, err := persist.RemoveNV(tpm, handle, persist.Any); err != nil {
			return err
		}
		fmt.Printf("removed NV index 0x%08X\n", uint32(handle))
	}
	return nil
}

func attributeBits(a tpm2.TPMANV) uint32 {
	b := tpm2.Marshal(a)
	if len(b) != 4 {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func logger(s string) { fmt.Fprintln(os.Stderr, "assh:", s) }

// waitForSignal returns at SIGTERM or SIGINT.
func waitForSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	<-ch
}

// efivarCommand is 'efivar get|set|rm': an EFI variable, aSSH's or another
// vendor's, read, written and removed as the CA's are (package persist).
func efivarCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("efivar needs get, set or rm")
	}
	fs := flag.NewFlagSet("efivar "+args[0], flag.ExitOnError)
	file := fs.String("file", "", "set: the value from this file")
	fs.Parse(args[1:])
	if fs.NArg() < 1 {
		return fmt.Errorf("efivar %s needs a variable: NAME or NAME-GUID", args[0])
	}
	location := persist.VarPrefix + fs.Arg(0)
	switch args[0] {
	case "get":
		b, err := persist.ReadVar(location)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(b)
		return err
	case "set":
		var value []byte
		switch {
		case *file != "" && fs.NArg() == 1:
			b, err := os.ReadFile(*file)
			if err != nil {
				return err
			}
			value = b
		case *file == "" && fs.NArg() == 2:
			value = []byte(fs.Arg(1))
		default:
			return errors.New("efivar set needs a value: NAME VALUE, or --file FILE NAME")
		}
		return persist.WriteVar(location, value)
	case "rm":
		_, err := persist.RemoveVar(location)
		return err
	}
	return fmt.Errorf("efivar %s: get, set or rm", args[0])
}
