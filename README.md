# aSSH: an SSH host key that never leaves the TPM

aSSH gives an SSH server a host key that is made inside the TPM and
certified by a certificate authority (CA) that is inside the TPM too. No
host key and no secret of one is ever stored - not on the disk, not in an
unencrypted boot image. It is a Go library and a command:

| | |
|---|---|
| `hostkey` | the CA in the TPM, the approvals of the PCR states it signs in, the per-boot host key and its certificate |
| `server` | an SSH server split in two: the side that speaks SSH runs as nobody, in namespaces of its own, under Landlock, and holds neither the key nor what a login leads to |
| `agent` | an ssh-agent socket that lends the host key to OpenSSH's sshd (`HostKeyAgent`) |
| `cmd/assh` | the command: `ca create`, `ca show`, `ca approve`, `serve`, `agent` |

[tpm2-kira](../tpm2-kira) uses it for the SSH server of its boot image.

## How the keys are held

```
authority key (yours: a file, a YubiKey, an HSM)
   │ signs approvals: "the CA may sign while PCR 0, 7, ... hold these values"
   ▼
SSH CA ─ ECDSA P-256 or RSA-2048, created in the TPM, never exported
   │ policy: PolicyAuthorize(authority) over PolicyPCR - no password
   │ at a server's start, in an approved state:
   ▼
host key of this boot ─ made in the TPM under the NULL hierarchy (its seed
   │                    changes at every reboot), certified by the CA
   ▼
every key exchange of this boot, signed by the TPM
```

- **The CA** (`ca create`) is created inside the TPM. Its file holds only
  the TPM's wrapped copy, which loads in this TPM alone, the authority's
  public key and the approvals; nothing in it is a secret.
- **An approval** (`ca approve`) is the authority's signature over a PCR
  state. The CA signs only while the PCRs hold an approved state. After a
  firmware update the authority approves the new state: the CA and the
  clients' trust in it stay the same.
- **At its start** a server (`serve`, `agent`, or a program with the
  library) has the TPM make a new host key and the CA certify it
  (`hostkey.Issue`). The host key needs an authorization value that is in
  that process's memory alone; it signs every key exchange of this boot,
  whatever the PCRs hold later, and loads nowhere after the next reboot.
- **Closing the window** (`--close-pcr N`, `hostkey.Close`) extends a PCR
  right after the certificate is made: the CA signs nothing more until the
  next boot, so a process started later - or a restarted server - gets no
  certificate. A boot can also close the window by itself (tpm2-kira binds
  its CA to PCR 0 and 7 before the OS separator extends them).
- **Clients trust the CA**, not a key, with one `known_hosts` line:

  ```
  @cert-authority host.example,192.0.2.10 ecdsa-sha2-nistp256 AAAA...   # the CA's .pub
  ```

  A new host key at every boot asks them nothing. The certificate's
  principal is `*` by default (any name; the pattern in `known_hosts`
  chooses the hosts) - OpenSSH refuses a host certificate without a
  principal. Tested with OpenSSH 10.6.

What this protects against: a copy of the disk or the boot image (no key in
it), another machine (the CA loads in this TPM alone), another PCR state
(the CA does not sign), a process after the window closed (no
certificate). What it does not: root while the server runs can read the
host key's authorization value from its memory (the process is not
dumpable, which keeps other users and core dumps out) and have the TPM
sign with it - until the next reboot, and on this machine only.

## The command

```bash
# The authority: any RSA or ECDSA key (P-256, P-384); keep it off the machine
openssl ecparam -name prime256v1 -genkey -noout -out authority.key
openssl ec -in authority.key -pubout -out authority.pub

# The CA, bound to the firmware, the Secure Boot state and PCR 15
assh ca create --out /etc/assh/os-ca.json --authority authority.pub --pcrs 0,7,15
# -> /etc/assh/os-ca.json.pub, and the known_hosts line

# Approve the state the CA may sign in: as the TPM holds it now ...
assh ca approve --ca /etc/assh/os-ca.json --authority-key authority.key
# ... or as a server recorded it before it closed the window, signed elsewhere
assh ca approve --ca /etc/assh/os-ca.json --values /run/assh/agent.pcrs.json --digest d.bin
openssl pkeyutl -sign -inkey authority.key -pkeyopt digest:sha256 -in d.bin -out d.sig
assh ca approve --ca /etc/assh/os-ca.json --values /run/assh/agent.pcrs.json --signature d.sig

assh ca show --ca /etc/assh/os-ca.json
```

### A server of its own: `assh serve`

```bash
assh serve --ca ca.json --authorized-keys keys --listen :2222 --close-pcr 15 \
    -- /usr/local/bin/unlock-menu          # run for each login, in a pseudo-terminal
assh serve --ca ca.json --authorized-keys keys --socket /run/myapp/session.sock
```

Only an interactive session is served: commands, subsystems and
forwardings are refused, and lines of `authorized_keys` with options in
front of the key are left out (the options are not honoured).

- **With a command** (after `--`) each login runs it, as `--user` or as
  assh runs, in a pseudo-terminal when the client asked for one (its size
  follows the client's window), with `ASSH_USER`, `ASSH_KEY` (the login
  key's fingerprint) and `ASSH_REMOTE` in its environment.
- **With `--socket`** each login is handed to the program listening there:
  a line of JSON first (`{"user", "key", "remote", "term", "cols",
  "rows"}`), then the session's bytes both ways.

### sshd's host key: `assh agent`

sshd keeps doing SSH; the agent signs for it, with a host key of this boot
in the TPM and the CA's certificate:

```bash
assh agent --ca /etc/assh/os-ca.json --close-pcr 15     # systemd/assh-agent.service
```

```
# /etc/ssh/sshd_config.d/assh.conf
HostKey         /run/assh/host.pub
HostCertificate /run/assh/host-cert.pub
HostKeyAgent    /run/assh/agent.sock
```

The agent answers root alone (sshd), offers rsa-sha2-256 and -512 for an
RSA key (never SHA-1's ssh-rsa; SHA-512 where the TPM has it), and records
the PCR values it found before closing the window in
`/run/assh/agent.pcrs.json`: when it has no approval for them - the first
boot, a firmware update - approve that file and reboot. It cannot be
restarted within a boot (the window is closed); sshd can.

**PCR 15** is the default choice for the window: the firmware does not
use it and it cannot be reset (16 and 23 can, and are refused). Its value
before the agent closes it must be the same at every boot - systemd may
extend it with the machine ID or a volume key (`tpm2-measure-pcr=`) before
the agent starts, which is fine as long as that order is fixed. Anything
bound to PCR 15 that is used after the agent started (a volume enrolled
with `systemd-cryptenroll --tpm2-pcrs=15`) no longer unlocks.

## The library

```go
ca, _ := hostkey.LoadCA("/etc/assh/os-ca.json")
tpm, _ := transport.OpenTPM("/dev/tpmrm0")
hk, err := hostkey.Issue(tpm, ca, hostkey.IssueOptions{
	Open: func() (transport.TPMCloser, error) { return transport.OpenTPM("/dev/tpmrm0") },
})
hostkey.Close(tpm, 15, "myapp: closed")      // optional: no certificate after this

ln, _ := net.Listen("tcp", ":2222")
srv, err := server.Start(server.Options{
	Listener:       ln.(*net.TCPListener),
	HostKey:        hk.SSH(),               // the certificate and the key in the TPM
	AuthorizedKeys: keys,                   // server.ParseAuthorizedKeys
	Command:        func() *exec.Cmd { return exec.Command("/proc/self/exe", "ssh-child") },
	Session:        func(s *server.Session) { go handle(s) },   // or server.RunCommand
})
// and in main(): if os.Args[1] == "ssh-child" { server.ChildMain() }
```

`server` takes any `ssh.Signer`; `hostkey` works without `server`, and
`agent` with any signer.

## Tests

```bash
go test -count=1 ./...
```

Needs `swtpm` for the TPM tests (they are skipped without it), and
OpenSSH's `ssh`, `ssh-keygen` and `openssl` for the command's test, which
logs in with OpenSSH's client through a `@cert-authority` line, approves a
recorded state with a signature openssl made, and runs the agent after a
reboot of the software TPM.

## Known limits

- **go-tpm is pinned to an unreleased commit**
  (`v0.9.9-0.20261001171150-36f205946d7e`, google/go-tpm#446): v0.9.8 cuts
  an authorization value at any zero byte in its HMAC sessions, where the
  TPM drops only trailing ones, and a random host key authorization value
  then fails about one time in eight. Move to the first release with the
  fix.
- **RSA-2048 host keys** sign rsa-sha2-256 in `serve` (many TPMs lack
  SHA-512); the agent offers rsa-sha2-512 too and fails it on such a TPM -
  set sshd's `HostKeyAlgorithms` then, or use P-256.
- **The approvals are the authority's.** Whoever holds the authority key
  can approve another state; keep it on a token, or off the machine.
