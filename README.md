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
| `tpmadmin` | what the TPM itself holds for an authority with a PIN: the PIN, the dictionary attack parameters, the lockout authorization |
| `cmd/assh` | the command: `ca create`, `ca show`, `ca approve`, `ca pin`, `tpm da`, `serve`, `agent` |

[tpm2-kira](https://github.com/mrwiora/tpm2-kira) uses it, as a git
submodule, for the SSH server of its boot image.

## The keys

| key | what it is | where it is | does it leave the TPM? | what lets it sign |
|---|---|---|---|---|
| **CA** | the machine's identity to SSH clients: ECDSA P-256 or RSA-2048 | made in the TPM; the CA file holds the TPM's wrapped copy | never: it is made `fixedTPM` and `fixedParent`, and the wrapped copy loads in this TPM alone | a PCR state the authority approved; no password |
| **authority** | the key whose signatures approve PCR states | **elsewhere**: a file, a YubiKey, an HSM - or **in the TPM**: the key A, its wrapped copy in the CA file | elsewhere: its private key never comes to the TPM, only its public key does. In the TPM: A is made there and never leaves | elsewhere: whatever guards that key. In the TPM: the PIN, with no PCR condition |
| **host key** | the key of one boot | made in the TPM under the NULL hierarchy; stored nowhere | never; it loads nowhere after the next reboot | an authorization value in the server process's memory alone |

```
authority ── signs approvals: "the CA may sign while PCR 0, 7, ... hold these values"
   │
   ▼
CA ───────── signs, while the PCRs hold an approved state, the certificate of
   │
   ▼
host key ─── signs every key exchange of this boot
```

Clients trust the CA, not a key, with one `known_hosts` line:

```
@cert-authority host.example,192.0.2.10 ecdsa-sha2-nistp256 AAAA...   # the CA's .pub
```

A new host key at every boot asks them nothing. The certificate's
principal is `*` by default (any name; the pattern in `known_hosts`
chooses the hosts) - OpenSSH refuses a host certificate without a
principal. Tested with OpenSSH 10.6.

Nothing in the CA file is a secret: the wrapped copies load in this TPM
alone, the rest are public keys and signatures. The CA, the authority in
the TPM and the host keys are noDA: a dictionary attack lockout never
stops them.

## How an approval works

The authority is not something the CA holds or opens. It is the one key
whose signatures the CA's policy accepts, and an approval is such a
signature over a PCR state. The TPM checks it every time the CA signs.

**1. `ca create`: the CA names its authority.** The CA's policy is fixed
when it is made, and is part of it for good:

```
CA policy = PolicyAuthorize(Name of the authority, policyRef)
```

The Name is a hash of the authority's public key as the TPM loads it.
The policyRef (`--ref`, `assh` by default, at most 32 bytes) binds the
approvals to this use: an authority with several CAs signs approvals that
do not cross over. No PCR value is in the policy, so the CA - and the
clients' `known_hosts` line - stay the same through every change of the
PCRs.

**2. `ca approve`: the authority signs a state.**

```
approved       = PolicyPCR(the CA's PCRs, H(their values))  [; PolicyNV(G == n)   with a counter]
ApprovalDigest = SHA-256(approved ‖ policyRef)
```

The approval - the PCR values, the generation n, the signature over the
digest - goes into the CA file. It is a statement ("the CA may sign while
the PCRs hold these values"), not a secret. The digest is computed
without the TPM, so a key elsewhere can sign it on another machine.

**3. `Issue`: the TPM checks the approval.** When a server starts:

1. The TPM loads the CA and the authority: A from the CA file, or the
   public key of one elsewhere (`LoadExternal`). Both in the owner
   hierarchy: PolicyAuthorize refuses the ticket of a NULL-hierarchy key.
2. `VerifySignature`: the TPM checks the approval's signature over the
   digest, and gives a ticket that says so.
3. A policy session runs `PolicyPCR` over the PCRs as they are now and,
   with a counter, `PolicyNV(G == n)` over the counter as it is now. Its
   digest is `approved` only if the TPM's state is the approved one.
4. `PolicyAuthorize`, with the ticket, turns that digest into the CA's
   policy.
5. The CA signs the certificate of this boot's host key in that session.

An approval with other PCR values written into the file fails step 2;
an approval for another state fails step 3; an approval of an older
generation fails step 3 too.

## When the PCRs change

A firmware update, a new Secure Boot key or another boot path changes the
PCRs, and the CA signs nothing (`Issue` names the PCRs that differ) until
the authority approves the new state. Nothing is lost: the CA and the
clients' trust in it stay as they are.

1. **Boot the new state.** `agent` and `serve` record the PCR values they
   find before they close the window, also when the CA does not sign
   (`--state`; `/run/assh/agent.pcrs.json`, `/run/assh/serve.pcrs.json`).
2. **The authority approves that file**: a key elsewhere (below) or the
   PIN (below).
3. **Reboot.** The window was closed at this boot (`--close-pcr`); the
   approval takes effect at the next.

The values may come from elsewhere too: a program that knows the next
boot's PCRs - tpm2-kira replays the firmware's event log - approves them
with the library (`CA.Approve`, `CA.AddApproval`) before the reboot.
Approve only a state you trust: in it, the CA signs.

## The authority elsewhere

For approvals made by someone who is not at the device - an administrator
of many machines, signing offline, or tpm2-kira's signing key. Any RSA
(2048, 3072, 4096 bits) or ECDSA (P-256, P-384) key; its private key never
comes to the machine.

```bash
# 1. The authority, once, off the machine
openssl ecparam -name prime256v1 -genkey -noout -out authority.key
openssl ec -in authority.key -pubout -out authority.pub

# 2. On the machine: the CA, bound to the firmware, the Secure Boot state and PCR 15
assh ca create --out /etc/assh/os-ca.json --authority authority.pub --pcrs 0,7,15
# -> /etc/assh/os-ca.json.pub, and the known_hosts line

# 3. Approve a state: the TPM's now (no --values), or one a server recorded
assh ca approve --ca /etc/assh/os-ca.json --values /run/assh/agent.pcrs.json --digest d.bin

# 4. Off the machine: sign the digest
openssl pkeyutl -sign -inkey authority.key -pkeyopt digest:sha256 -in d.bin -out d.sig

# 5. On the machine: add the approval
assh ca approve --ca /etc/assh/os-ca.json --values /run/assh/agent.pcrs.json --signature d.sig
```

- With `--values`, steps 3 and 5 need no TPM: they run wherever a copy of
  the CA file is, and the CA file with the new approval goes back to the
  machine.
- Step 4 is anything that signs a SHA-256 digest with the key: PKCS #1
  v1.5 for RSA, DER ECDSA. Step 5 checks the signature before it saves.
- With the key at hand, `--authority-key authority.key` does steps 3 to 5
  in one.
- After every change of the PCRs: steps 3 to 5 with the recorded values.

**Its approvals are never revoked.** A CA with an authority elsewhere has
no counter: removing an approval from the file revokes nothing, a copy of
the file from before still works should the machine boot that state
again. Whoever holds the key decides. To end an old state for good, make
a new CA, or use the authority in the TPM.

## The authority in the TPM: a PIN, and revocation

With `ca create --authority-tpm` there is no key outside the machine.
Three things in the TPM, none of them secret outside it:

```
P  PIN index   NV counter at 0x01802913, its authorization value = the PIN.
               Written once when it is made, holding that value k for good.
               Its policy allows one more thing: a PIN change (NV_ChangeAuth).
A  authority   ECDSA P-256 key, made in the TPM, its wrapped copy in the CA
               file. Usable through PolicySecret(P) ; PolicyNV(P == k) ; Sign:
               the PIN, and no PCR condition.
G  counter     NV counter at 0x01802912, incremented through P - the PIN.
               Every approval names its value: PolicyPCR ; PolicyNV(G == n).
```

A's policy has no PCR in it, so the PIN approves in any boot state: on the
device itself, after a firmware update, with nobody else involved.

```bash
assh tpm da --new-lockout-auth --max-tries 3 --recovery 1800 --lockout-recovery 1800
assh ca create --out /etc/assh/os-ca.json --authority-tpm --pcrs 7,15     # asks for the PIN twice
assh ca approve --ca /etc/assh/os-ca.json                                 # this state; asks for the PIN
# after the PCRs changed, booted in the new state: approve what the agent
# recorded, and revoke every approval before it
assh ca approve --ca /etc/assh/os-ca.json --values /run/assh/agent.pcrs.json --next-generation
assh ca pin --ca /etc/assh/os-ca.json                                     # change the PIN
assh tpm da --ask-lockout-auth --reset                                    # end a lockout
```

- **Use stays automatic.** While the PCRs hold a state approved for the
  counter's current value, `Issue` (the agent, `serve`) gets its
  certificate with no PIN - also after an OS update that leaves the bound
  PCRs as they were. It reads G, which is noDA and needs no authorization.
- **A move** to another state (another safespace combination) is
  `ca approve --next-generation`, with the PIN: G is incremented, then A
  signs the new state for the new value. Every approval of an older value
  stops working inside the TPM; one put back into the file is refused too.
  Without `--next-generation` the new approval is added beside the others.
- **The PIN** is what a TPM takes as an authorization value: 6 to 32 bytes,
  any values, the last not zero (the TPM drops trailing zeros). No hashing,
  no normalization. It is read from the terminal without echo, or from a
  file descriptor (`--pin-fd N`, every byte as it is: `printf '%s'`, not
  `echo`) - never from argv or the environment, never stored, never logged.
  Everything that proves it runs in a salted HMAC session, everything that
  carries it is encrypted: it never crosses the bus in the clear.
- **Wrong PINs** are counted by the TPM's dictionary attack protection, P
  being the only object here that is not noDA: guessed through A or
  through G, it is one counter. With `tpm da --max-tries 3 --recovery 1800`
  three wrong PINs lock it out, then one try per 30 minutes. During a
  lockout the right PIN is refused too; `Issue` is not affected.
- **A PIN change** (`ca pin`) changes P's authorization value in place:
  the old PIN opens nothing afterwards, from any copy of any file, and the
  CA, its approvals and the clients' known_hosts line stay as they are.

The dictionary attack parameters and the failure count belong to the TPM,
not to assh: every object in the TPM that is not noDA shares them (a volume
unlocked with a TPM PIN, say), and anyone who can use the TPM can spend the
tries - which keeps the owner from approving for a while, never `Issue`
from working.

**The lockout authorization must be set**, and kept off the machine:
without one any process may reset the lockout and try PINs without end.
`ca create --authority-tpm` refuses a TPM without one (`assh tpm da
--new-lockout-auth`). It is also what clears the TPM.

## When the TPM is cleared, the CA is lost

TPM2_Clear (`tpm2_clear`, "Clear TPM" in the firmware's setup, a firmware
update that resets a firmware TPM) gives the owner hierarchy a new storage
seed, and another TPM (a new mainboard) has one of its own. The wrapped
copies of the CA and of A then load nowhere, and P and G are gone with
the clear. Nothing brings the CA back, by design: a CA that could be
restored would be a secret kept outside the TPM.

What remains to do is what a new machine needs: `ca create`, an approval,
and the new `known_hosts` line on every client. Until a client has it, it
refuses the host.

## What it protects against

Any authority: a copy of the disk or the boot image (no key in it),
another machine (the CA loads in this TPM alone), another PCR state (the
CA does not sign), a process after the window closed (no certificate).

What it does not: root while the server runs can read the host key's
authorization value from its memory (the process is not dumpable, which
keeps other users and core dumps out) and have the TPM sign with it -
until the next reboot, and on this machine only. And whoever holds the
authority can approve another state: keep a key elsewhere on a token, or
off the machine.

The authority in the TPM, against root on the device with the owner
authorization empty, as on most machines:

| attack | result |
|---|---|
| guessing the PIN, through A or G | the TPM's lockout, which root cannot reset without the lockout authorization |
| an approval of an older generation, in the file or put back into it | refused by PolicyNV in the TPM |
| undefining P and defining it again alike, with a PIN of one's own | the clone has P's Name but never its value k: the TPM sets a counter's first value above any value a counter of that Name had (TPM 2.0 Part 1, 37.2.6.3). It opens neither A nor G |
| undefining G and defining it again alike | until it is incremented its Name differs and the CA signs nothing; it cannot be incremented without the PIN; the owner's next `--next-generation` lands above every old value |
| replacing G with another index | the CA signs nothing; `ca approve --redefine-counter`, with the PIN, puts G back |
| copying the CA file to another TPM | neither the CA nor A loads there |

What it does not protect against:

- **Deleting** G stops the CA until `--redefine-counter`; **deleting P**
  ends approvals for good (no P can hold k again: the rule that stops the
  clone). `Issue` keeps working with the current approval; after the next
  change of the bound PCRs the CA must be created again, with a new
  known_hosts line. Both need only the owner authorization, which is empty
  on most machines: a denial of service, never a way in.
- **Root that watches the PIN being typed** - reading the terminal or
  assh's memory - has it. Type it only in a system you trust (for
  safespace: the combination being moved to).
- The key that salts the PIN's sessions is read from the TPM over the same
  bus; an active interposer on the bus could substitute it. It is not
  checked against the TPM's endorsement key.

## Serving: `assh serve` and `assh agent`

At its start a server has the TPM make a new host key and the CA certify
it (`hostkey.Issue`). The host key's authorization value is in that
process's memory alone; the key signs every key exchange of this boot,
whatever the PCRs hold later, and loads nowhere after the next reboot.

**Closing the window** (`--close-pcr N`, `hostkey.Close`) extends a PCR
right after the certificate is made: the CA signs nothing more until the
next boot, so a process started later - or a restarted server - gets no
certificate. A boot can also close the window by itself (tpm2-kira binds
its CA to PCR 0 and 7 before the OS separator extends them).

**PCR 15** is the default choice for the window: the firmware does not
use it and it cannot be reset (16 and 23 can, and are refused). Its value
before the window is closed must be the same at every boot - systemd may
extend it with the machine ID or a volume key (`tpm2-measure-pcr=`) before
the server starts, which is fine as long as that order is fixed. Anything
bound to PCR 15 that is used after the window closed (a volume enrolled
with `systemd-cryptenroll --tpm2-pcrs=15`) no longer unlocks.

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

The agent answers root alone (sshd) and offers rsa-sha2-256 and -512 for
an RSA key (never SHA-1's ssh-rsa; SHA-512 where the TPM has it). It
cannot be restarted within a boot (the window is closed); sshd can. Until
the state is approved, sshd has no host key from it.

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

With an authority elsewhere:

```go
ca, _ := hostkey.CreateCA(tpm, hostkey.P256, hostkey.SHA256, []int{0, 7}, authorityPub, []byte("myapp"))
d, _ := ca.ApprovalDigest(values)               // sign d elsewhere, then:
ca.AddApproval(values, sig)                     // or ca.Approve(signer, values) with the key at hand
```

With the authority in the TPM (the PIN is a callback, asked when the TPM
needs it):

```go
ca, _ := hostkey.CreatePINCA(tpm, hostkey.PINCAOptions{Type: hostkey.P256, Bank: hostkey.SHA256,
	PCRs: []int{7, 15}, PIN: askPIN})
ca.NextGeneration(tpm, askPIN)                  // a move: older approvals stop working
a, _ := ca.TPMAuthority(tpm, askPIN)            // a crypto.Signer
ca.Approve(a, values)
tpmadmin.ChangePIN(tpm, ca, askOldPIN, askNewPIN)
```

`server` takes any `ssh.Signer`; `hostkey` works without `server`, and
`agent` with any signer.

## Tests

```bash
go test -count=1 ./...
```

Needs `swtpm` for the TPM tests (they are skipped without it), and
OpenSSH's `ssh`, `ssh-keygen` and `openssl` for the command's tests, which
log in with OpenSSH's client through a `@cert-authority` line, approve a
recorded state with a signature openssl made, move a CA with a PIN to
another state, and run the agent after reboots of the software TPM.

## Known limits

- **go-tpm is pinned to an unreleased commit**
  (`v0.9.9-0.20261001171150-36f205946d7e`, google/go-tpm#446): v0.9.8 cuts
  an authorization value at any zero byte in its HMAC sessions, where the
  TPM drops only trailing ones, and a random host key authorization value
  then fails about one time in eight. Move to the first release with the
  fix.
- **assh builds with a fork of go-tpm** (`replace` in go.mod,
  github.com/mrwiora/go-tpm): it adds TPM2_NV_ChangeAuth and
  TPM2_DictionaryAttackLockReset, and checks the response of a command that
  changes an authorization value with the new value. Only `tpmadmin` needs
  it; a program that uses `hostkey` without `tpmadmin` (tpm2-kira) builds
  with go-tpm as released. Drop the replace once upstream has them.
- **RSA-2048 host keys** sign rsa-sha2-256 in `serve` (many TPMs lack
  SHA-512); the agent offers rsa-sha2-512 too and fails it on such a TPM -
  set sshd's `HostKeyAlgorithms` then, or use P-256.
- **A cleared TPM loses the CA** (above): there is no backup of it.
