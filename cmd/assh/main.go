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
	"strings"
	"syscall"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/mrwiora/assh/hostkey"
)

const usage = `assh - an SSH host key in the TPM

  assh ca create   --out FILE --authority PUB.pem [--type p256|rsa2048]
                   [--pcrs 0,7] [--bank sha256] [--ref TEXT]
  assh ca show     --ca FILE
  assh ca approve  --ca FILE (--authority-key KEY.pem | --signature FILE |
                   --digest FILE) [--values FILE]
  assh serve       --ca FILE --authorized-keys FILE (-- COMMAND ... | --socket PATH)
                   [--listen :22] [--user NAME] [HOST KEY OPTIONS]
  assh agent       --ca FILE [--dir /run/assh] [--uid 0] [HOST KEY OPTIONS]

Host key options: [--key-type p256|rsa2048] [--principals '*'] [--key-id TEXT]
                  [--close-pcr N] [--state FILE]

Every command takes --tpm PATH (default /dev/tpmrm0).

The CA is created in the TPM and never leaves it. It signs while the PCRs
it is bound to hold a state the authority approved ('ca approve'). 'serve'
and 'agent' make a host key in the TPM at their start - gone at the next
reboot - and have the CA certify it; --close-pcr then extends that PCR, so
the CA signs nothing more until the next boot. Clients trust the CA:

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

func caCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("ca needs create, show or approve")
	}
	fs := flag.NewFlagSet("ca "+args[0], flag.ExitOnError)
	tpmPath := fs.String("tpm", "/dev/tpmrm0", "the TPM")
	switch args[0] {
	case "create":
		out := fs.String("out", "", "the CA file to write (its public key goes beside it, .pub)")
		authPath := fs.String("authority", "", "the authority's public key (PEM): it approves the PCR states")
		typ := fs.String("type", "p256", "the CA's key: p256 or rsa2048")
		pcrs := fs.String("pcrs", "0,7", "the PCRs the CA is bound to")
		bank := fs.String("bank", "sha256", "their bank: sha256 or sha1")
		ref := fs.String("ref", "assh", "what the authority's approvals are bound to (at most 32 bytes)")
		fs.Parse(args[1:])
		if *out == "" || *authPath == "" {
			return errors.New("ca create needs --out and --authority")
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
		auth, err := readPublicKey(*authPath)
		if err != nil {
			return err
		}
		tpm, err := openTPM(*tpmPath)()
		if err != nil {
			return err
		}
		defer tpm.Close()
		ca, err := hostkey.CreateCA(tpm, t, b, p, auth, []byte(*ref))
		if err != nil {
			return err
		}
		if err := ca.Save(*out); err != nil {
			return err
		}
		pub, _ := ca.AuthorizedKey()
		if err := os.WriteFile(*out+".pub", pub, 0o644); err != nil {
			return err
		}
		fmt.Print(ca.Describe())
		line, _ := ca.KnownHosts("*")
		fmt.Printf("Clients trust it with this known_hosts line (narrow the * to the host's names):\n  %s\n", line)
		fmt.Printf("Approve the PCR state it may sign in: assh ca approve --ca %s ...\n", *out)
		return nil
	case "show":
		caPath := fs.String("ca", "", "the CA file")
		fs.Parse(args[1:])
		ca, err := hostkey.LoadCA(*caPath)
		if err != nil {
			return err
		}
		fmt.Print(ca.Describe())
		if tpm, err := openTPM(*tpmPath)(); err == nil {
			defer tpm.Close()
			if now, err := ca.ReadPCRs(tpm); err == nil {
				if ca.Approved(now) != nil {
					fmt.Println("The PCRs hold an approved state now: the CA signs.")
				} else {
					fmt.Println("The PCRs hold no approved state now: the CA signs nothing.")
				}
			}
		}
		return nil
	case "approve":
		caPath := fs.String("ca", "", "the CA file, which gets the approval")
		keyPath := fs.String("authority-key", "", "the authority's private key (PEM): signs here")
		sigPath := fs.String("signature", "", "the authority's signature over the digest, made elsewhere (PKCS #1 v1.5 or ECDSA DER, as openssl pkeyutl -sign makes it)")
		digestPath := fs.String("digest", "", "write the digest to sign to this file, and approve nothing")
		valuesPath := fs.String("values", "", "the PCR values to approve, as 'serve' or 'agent' recorded them (--state); default: what the TPM holds now")
		fs.Parse(args[1:])
		ca, err := hostkey.LoadCA(*caPath)
		if err != nil {
			return err
		}
		values, err := approveValues(ca, *valuesPath, *tpmPath)
		if err != nil {
			return err
		}
		switch {
		case *digestPath != "":
			d, err := ca.ApprovalDigest(values)
			if err != nil {
				return err
			}
			if err := os.WriteFile(*digestPath, d, 0o644); err != nil {
				return err
			}
			fmt.Printf("Sign %s (SHA-256 digest %s) with the authority, then: assh ca approve --ca %s --signature SIG", *digestPath, hex.EncodeToString(d), *caPath)
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
			if err := ca.AddApproval(values, sig); err != nil {
				return err
			}
		case *keyPath != "":
			key, err := readPrivateKey(*keyPath)
			if err != nil {
				return err
			}
			if err := ca.Approve(key, values); err != nil {
				return err
			}
		default:
			return errors.New("ca approve needs --authority-key, --signature or --digest")
		}
		if err := ca.Save(*caPath); err != nil {
			return err
		}
		fmt.Printf("Approved: %d state(s) in %s\n", len(ca.Approvals), *caPath)
		return nil
	}
	return fmt.Errorf("unknown ca command %q", args[0])
}

// stateFile is what 'serve' and 'agent' record of the PCRs before they
// close the window: the state to approve, which the TPM no longer holds.
type stateFile struct {
	Bank hostkey.Bank      `json:"bank"`
	PCRs map[string]string `json:"pcrs"` // index: hex
}

func writeState(path string, ca *hostkey.CA, values map[int][]byte) error {
	s := stateFile{Bank: ca.Bank, PCRs: map[string]string{}}
	for i, v := range values {
		s.PCRs[fmt.Sprint(i)] = hex.EncodeToString(v)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
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
}

func (h *hostKeyFlags) add(fs *flag.FlagSet, defaultState string) {
	fs.StringVar(&h.tpm, "tpm", "/dev/tpmrm0", "the TPM")
	fs.StringVar(&h.ca, "ca", "", "the CA file ('ca create')")
	fs.StringVar(&h.state, "state", defaultState, "where the PCR values before closing are written, for 'ca approve --values'")
	fs.StringVar(&h.keyType, "key-type", "p256", "the host key: p256 or rsa2048")
	fs.StringVar(&h.principals, "principals", "*", "the host names the certificate is valid for, comma-separated; * any (the clients' known_hosts patterns still choose the hosts)")
	fs.StringVar(&h.keyID, "key-id", "assh", "the certificate's name in the clients' logs")
	fs.IntVar(&h.closePCR, "close-pcr", -1, "extend this PCR after the host key is certified: the CA signs nothing more until the next boot")
}

// issue makes this boot's host key. The window is closed whatever comes
// of it: an approval for the state recorded is made afterwards, and takes
// effect at the next boot.
func (h *hostKeyFlags) issue(log func(string)) (*hostkey.HostKey, error) {
	if err := hostkey.NoDump(); err != nil {
		log("this process can be dumped: " + err.Error())
	}
	ca, err := hostkey.LoadCA(h.ca)
	if err != nil {
		return nil, err
	}
	typ, err := hostkey.ParseType(h.keyType)
	if err != nil {
		return nil, err
	}
	open := openTPM(h.tpm)
	tpm, err := open()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()
	if values, err := ca.ReadPCRs(tpm); err != nil {
		return nil, err
	} else if h.state != "" {
		if err := writeState(h.state, ca, values); err != nil {
			log("the PCR state is not recorded: " + err.Error())
		}
	}
	var principals []string
	for _, p := range strings.Split(h.principals, ",") {
		if p = strings.TrimSpace(p); p != "" {
			principals = append(principals, p)
		}
	}
	hk, ierr := hostkey.Issue(tpm, ca, hostkey.IssueOptions{Type: typ, Principals: principals, KeyID: h.keyID, Open: open})
	if h.closePCR >= 0 {
		if err := hostkey.Close(tpm, h.closePCR, "assh: closed"); err != nil {
			return nil, err
		}
		log(fmt.Sprintf("PCR %d is extended: the CA signs nothing more until the next boot", h.closePCR))
	}
	if ierr != nil {
		var m *hostkey.MismatchError
		if errors.As(ierr, &m) && h.state != "" {
			return nil, fmt.Errorf("the CA does not sign: %v. If this state is right: assh ca approve --ca %s --values %s ..., and reboot", ierr, h.ca, h.state)
		}
		return nil, ierr
	}
	log(fmt.Sprintf("host key %s, certified by the CA %s", hk.Fingerprint(), ca.Fingerprint()))
	return hk, nil
}

func logger(s string) { fmt.Fprintln(os.Stderr, "assh:", s) }

// waitForSignal returns at SIGTERM or SIGINT.
func waitForSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	<-ch
}
