# TODO-SEC: security findings P2, P3 and info, with the fixes proposed

From the security review of 4f0ddf1 (2026-10-29). P1 is in PLAN.md. Each fix comes with a
test that fails before it. Line numbers are of 4f0ddf1. Strike an item when it is done.

## P2

### P2-6: the CA's public area is not checked

`hostkey/file.go:228-255`: `ParseCA` takes `Public` as it is. Root puts in a key of its
own, and `ca show` / `CA.KnownHosts` print a `known_hosts` line for it; an administrator
who enrols a client from that line trusts root's key.

- `ParseCA` requires `Public` to equal the CA's template - type, attributes, the policy
  `caPolicyFor(A's Name, ref, W's Name, v)` from P1-5 - except `Unique`, as
  `checkTPMAuthority` already does for A.
- `ca show` with a TPM at hand also `Load`s `Public`/`Private`: a fixedTPM key that loads
  was made in this TPM. Without a TPM it says the line is unverified.
- Test: a file with another P-256 public key is refused; `ca show` on a swapped blob says
  it does not load.

### P2-7: one host locks out SSH before login

`server/child.go:42-43,245-249`: 8 pre-login connections in all, 30 s each, no limit per
source.

- At most 2 pre-login connections per source address (/64 for IPv6).
- From 4 of 8 on, drop new ones with a probability rising to 1 (OpenSSH's MaxStartups
  `4:30:8`), so a flood never holds every place.
- 10 s for the version exchange and the key exchange, the 30 s for the login after it.
- Test: 8 idle connections from one address leave a login from another possible.

### P2-8: a session outlives its client

`server/command.go:40,69-71`, `cmd/assh/serve.go:153-157`.

- PTY: when the copy from the client ends, close the master: the shell gets SIGHUP;
  after a short grace, `kill(-pgid, SIGKILL)`.
- Pipes: close the command's stdin when the client's input ends (`ssh host cmd < file`).
- `--socket`: close the connection to the program when the client goes; the program sees
  EOF.
- Test: a client killed mid-session frees its slot, and the command is gone (`/proc`).

### P2-9: the root half trusts the child

`server/server.go:243-313`, `server/proto.go:74`. The child is to be treated as
compromised.

- **Signing**: only data of 20, 32, 48 or 64 bytes (an exchange hash), at most one per
  connection the child announced, and at most N per second overall; anything else ends the
  child (`Stop()`), logged.
- **Sessions**: a cap in the parent (`sessionMax`), an ID used twice is refused, User at
  most 64 bytes of `[A-Za-z0-9._-]`, Key a `SHA256:` fingerprint, Remote an address, Term
  `[A-Za-z0-9._+-]`, at most 32 bytes. Rows/cols bounded.
- **Protocol**: `MSG_TRUNC`/`MSG_CTRUNC` are errors; a second `ready` is an error; any
  receive error ends the child instead of leaving the loop silently.
- Test: a fake child (the protocol over a socketpair) that sends 1 KB to sign, a duplicate
  ID, a 10 KB user name, two `ready`s: each ends it, the parent stays up.

### P2-10: SHA-1 and DSA for client keys

`server/child.go:137-154`: x/crypto's default list includes `ssh-rsa` (SHA-1) and DSA.

- `PublicKeyAuthAlgorithms`: ed25519, sk-ed25519, ecdsa-sha2-nistp256/384/521,
  sk-ecdsa, rsa-sha2-256, rsa-sha2-512.
- `ParseAuthorizedKeys` leaves out `ssh-dss` lines and counts them as left out.
- Breaks: an RSA client that signs only `ssh-rsa` (OpenSSH < 7.2) cannot log in.
- Test: an `ssh -o PubkeyAcceptedAlgorithms=ssh-rsa` login is refused, rsa-sha2-256
  accepted.

### P2-11: a lockout authorization the TPM stores as empty

`tpmadmin/tpmadmin.go:130-138`: only `len(new)==0` is refused; all-zero bytes are trimmed
to empty.

- The rules of `CheckPIN` (no trailing zero byte, 8 to 32 bytes) for a new lockout
  authorization, then `LockoutAuthSet` must say set, or it is an error.
- Test: `--new-lockout-auth-fd` with 16 zero bytes is refused.

### P2-12: two library paths skip a check the command makes

- `CA.Approve` with a TPM authority signs for the file's generation without `Sync`: root
  raises `Counter.Generation` in the file, the approval for n+1 survives the next move.
  `TPMAuthority` reads G and refuses a file that differs (`policy.go:241-273`).
- `hostkey.Issue` does not check `SHA1Allowed` for a SHA-1 CA (`tpm.go:619`): a program
  on the library ignores `tpm sha1 --forbid`. `Issue` checks it and makes a temporary key.
- Tests: a library approval after a file edit of the generation is refused; `Issue` on a
  SHA-1 CA after `--forbid` is temporary.

## P3

### P3-13: the agent's unit runs with every privilege

`systemd/assh-agent.service`. The agent needs `/dev/tpmrm0`, `/run/assh`, the CA file or
efivarfs (read), assh.conf (read), an AF_UNIX socket.

```
RuntimeDirectory=assh
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes          # the sockets stay for sshd
UMask=0022
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
DevicePolicy=closed
DeviceAllow=/dev/tpmrm0 rw
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
```

- Verify with `systemd-analyze security assh-agent.service` and a boot with an `efi:` CA
  (efivarfs read under `ProtectSystem=strict` is fine; `ProtectKernelTunables` would make
  `/sys` read-only: fine for reading too, to be confirmed). `ExecStopPost=assh close` from
  P1-1 needs the same.
- Test: safearch's `tests/vm.sh` boots with the unit.

### P3-14: persist edge cases

- `persist/efivar.go:86-112`: an empty value is a delete for efivarfs. `WriteVar` refuses
  it ("use RemoveVar").
- `persist/efivar.go:110-121`: the immutable mark is not put back when the write fails.
  `defer` it once lifted.
- `persist/nv.go:71-85`: between `NVReadPublic` and `NVUndefineSpace` another owner could
  replace the index. Undefine in an HMAC session with the owner's empty auth: cpHash binds
  the index's Name, the TPM refuses a changed one.
- Tests: an empty write leaves the variable; a failed write (a read-only directory) keeps
  the mark; the HMAC undefine works on swtpm.

### P3-15: `efivar` writes any vendor's variable

`persist/efivar.go:47-63`, `cmd/assh/main.go:1139-1165`: `BootOrder`, `Boot####`, shim's
`Mok*` can be rewritten or deleted by a typo in a script.

- Allowed without more: aSSH's GUID, and those in `ASSH_EFIVAR_VENDORS` (safearch's).
- Anything else: `--vendor GUID` given explicitly. The EFI-global GUID
  (`8be4df61-93ca-11d2-aa0d-00e098032b8c`) and shim's (`605dab50-e046-4300-abb6-3dd810dd8b23`)
  refused.
- Test: `efivar set BootOrder-8be4df61-…` is refused.

### P3-16: `config.Write` takes any value

`config/config.go:386-434`.

- `Write` runs every value through `set()` (what `Parse` checks) and refuses control
  characters, so a newline cannot make a second key.
- Written to a temp file in the directory, fsync, rename, the old mode and owner kept.
- Test: `KeyID="x\nASSH_AGENT_UID=1000"` is refused; a crash between write and rename
  leaves the old file (write to a read-only target).

### P3-17: output files and `/run/assh`

`cmd/assh/main.go:289,388,778-796`, `cmd/assh/serve.go:174-215`.

- One helper, `writeFile(path, data, mode)`: temp file in the directory with `O_EXCL`,
  fsync, rename; the target not followed when it is a symlink (`O_NOFOLLOW` on the final
  check). Used for `.pub`, `--digest`, the statement, the state file, the agent's files.
- The agent's directory: created 0755 by root, or refused when it exists and is not
  root's, or group/world-writable - so nobody can plant `agent.pcrs.json` for the owner
  to approve.
- The state file: written with `O_EXCL` (the boot's first start), no stat-then-write.
- Tests: a symlink at `--digest` is not followed; a world-writable `--dir` is refused.

### P3-18: log injection from the client

`server/child.go:151,282,331,337`, `server/server.go:254`, `cmd/assh/serve.go:100`.

- The parent writes the child's text through one function that replaces control
  characters (`strconv.Quote` for names, types). The child is untrusted, so the parent
  does it.
- Test: a login name with `\n` and `\x1b[` comes out escaped in the log.

### P3-19: the agent stops answering, silently

`agent/agent.go:63-66`, `cmd/assh/serve.go:223`.

- `Serve` retries `Accept` on temporary errors (EMFILE, ENFILE, ECONNABORTED) with a short
  backoff; any other error is returned, and `agent` exits with it (systemd shows the
  failure; sshd then has no host key, which is visible, not silent).
- `agent.Listen` makes the directory 0700 as its comment says, or the comment goes - the
  socket's 0600 and the peer check are what protect it.
- Test: an Accept error injected through a wrapped listener; the agent goes on.

### P3-20: the terminal after Ctrl-C at the PIN prompt

`cmd/assh/secret.go:72-75`.

- Around the terminal read, `signal.Notify` for SIGINT, SIGTERM, SIGHUP: restore the
  termios, clear the buffers, exit 130.
- Test: a pty-driven test sends ^C at the prompt and checks ECHO is back.

### P3-21: `readState` parses loosely

`cmd/assh/main.go:910-913`.

- Keys by `strconv.Atoi` with an exact round trip, 0-23, no duplicates; values of the
  bank's digest size; anything else refuses the file.
- Test: `"7x"`, `" 7"`, `"-1"`, `"24"`, a duplicate, a short value: each refused.

## Info: small fixes along the way

- [ ] Lockout authorization copies not cleared (`cmd/assh/main.go:687,698`); secrets read
      into a fixed `maxSecret+1` buffer instead of `io.ReadAll`/`append` (`secret.go:31,88`).
- [ ] `ASSH_EFIVARS` honoured only in test builds (`main.go:102`): a build tag, or the
      tests set `persist.VarDir` through a hidden flag.
- [ ] The namespace fallback (`server/server.go:194-198`) only on EPERM/EINVAL/ENOSPC
      from clone, not on any `Start` error.
- [ ] `SetDA` refuses `maxTries=0` (locks out every DA-protected object).
- [ ] `--config` found by the flag package, not a pre-scan of the arguments
      (`main.go:145-160`).
- [ ] Descriptor leak in the child when `ctl.send` fails (`server/child.go:375-378`).
- [ ] The umask change in `agent.Listen` (`agent.go:50`) replaced by `fchmod` of the
      socket before `listen`.
- [ ] `strconv.Atoi` errors in `serve.go:84-85` (fall back to uid 0) are errors; the
      `MkdirAll` error at `:89` checked.

## Info: README notes, no code

- Signed PCRs accept any policy the build key signed (other phases, banks, selections):
  use a key that signs for this purpose alone.
- The login is decided in the unprivileged half: a pre-login bug in x/crypto/ssh is a
  session as the command's user. Recommend `--user` other than root where the command
  allows it.
- Pathname Unix sockets stay reachable from the unprivileged half (Landlock's scoping
  covers abstract sockets; to be confirmed for the kernel's current ABI); the D-Bus system
  bus, for instance, answers it as its uid.
