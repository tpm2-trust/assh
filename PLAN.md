# PLAN: security fixes, P1

Status: **implemented** (2026-10-29); the VM runs are to come. From the security review of
4f0ddf1; P2, P3 and the info items are in TODO-SEC.md.

Decided (2026-10-29): new CAs are acceptable; the unprivileged half keeps nobody unless a
user can be chosen safely that nobody else uses; P1 first, as its own merge.

## Goal

Close the five P1 findings, each with a test that fails before the fix:

| # | Finding |
|---|---|
| 1 | the window stays open when `agent`/`serve` fail before they close it |
| 2 | `ca remove` undefines NV indices an untrusted CA file names |
| 3 | seccomp lets `clone`/`clone3` make namespaces |
| 4 | the unprivileged half is dumpable, and shares its uid with every other `nobody` |
| 5 | the authority signs what an untrusted CA file and assh.conf say; the window is only as good as the approval |

## How each is fixed

### P1-5: the window and the command in the CA's own policy (a new CA format)

Today the window is a PCR every slot must read: the approval carries it, so an approval of
a slot without it - made from an edited file - signs after the window. The fix takes the
window out of the approvals and into the CA's policy, which is fixed at creation and which
nothing in a file can change.

**W, the window index.** Every CA gets an NV index of its own (default `0x01802915`,
`ASSH_WINDOW_HANDLE`):

```
W  NV counter, TPMA_NV_READ_STCLEAR, AuthRead + AuthWrite with an empty authValue, NoDA.
   Incremented once at ca create: its value v is in the CA file.
```

```
CA policy = PolicyAuthorize(A, ref) ; PolicyCommandCode(TPM2_Sign) ; PolicyNV(W == v)
```

- **Closing** is `TPM2_NV_ReadLock(W)`: from then on PolicyNV fails (`TPM_RC_NV_LOCKED`),
  whatever an approval says, until `TPM2_Startup(CLEAR)` - the next boot. A resume from
  S3 (Startup STATE) keeps the lock, as it keeps a PCR.
- **No clone reopens it.** Undefined and defined again alike, W has its Name back but its
  first value lands above every value a counter had (the rule P already relies on): never
  v again. Root can increment or delete W - the CA then signs nothing: a denial of
  service, never a way in, like deleting the CA.
- **PolicyCommandCode(Sign)**: in an approved state the CA signs and does nothing else
  (no Certify, Quote, ...). After PolicyAuthorize, so it is the CA's, not the approval's.
- **`AdminWithPolicy`** on the CA and on A: the ADMIN role goes through the policy too,
  not an empty password (an info item, taken with the format change).
- **Slots no longer need the window PCR.** `ASSH_CA_WINDOW` and the "every slot reads the
  window" rule go. `--close-pcr`/`ASSH_CLOSE_PCR` stays as an extra: a PCR extended at
  the close for others that bind to it (tpm2-kira's PCR 15 event; safearch's combination
  in PCR 15 stays a slot's PCR as before).

**What the owner signs is shown.** The window is now safe from the file; the selection is
not: root can edit slot 0 to read PCR 7 alone, and an approval of it certifies any OS
booted under the same Secure Boot keys (before the close).

- `ca approve` prints, before it asks for the PIN or signs: the CA's fingerprint, slot,
  bank, each PCR and its value, the signed key's fingerprint, the generation - and, on a
  terminal, asks to confirm (`--yes` for scripts).
- `--digest` writes a **statement** (JSON: the same fields) beside the digest, and a new
  `assh ca sign --authority-key KEY --statement FILE --signature OUT` - run where the
  key is - computes the digest from the statement itself, shows it, and signs. The
  opaque `d.bin` + `openssl pkeyutl` path stays possible but is no longer the documented
  one.
- `ca approve` refuses a slot with signed PCRs whose key is not `ASSH_PCR_KEY`.

A PIN typed into a root-controlled system is lost anyway (README); the statement is the
defence for a key elsewhere, and a check for the owner at the device.

**API (tpm2-kira follows):** `CAOptions.Window` becomes `WindowHandle`;
`hostkey.Close(tpm, pcr, event)` becomes `ca.Close(tpm)` (lock W) plus
`hostkey.ExtendPCR(tpm, pcr, event)` for the extra; `CA.Window` goes;
`RemoveCA` removes W too. tpm2-kira's `remote_hostkey.go`, `sshscreen/hostkey.go`,
`remote_assh.go` and their tests change with it.

**Tests (swtpm):** after `Close` the CA signs nothing in an approved state; after a
reboot (`Startup CLEAR`) it signs again; W undefined and redefined alike: nothing; an
approval of a slot without PCR 15 still stops at the close; PolicyCommandCode: `Certify`
with the CA in an approved session fails; `ca sign` and `ca approve --digest` agree.

### P1-1: the window closed on every exit

- `issue` and `noCA` open the TPM first and `defer` the close: whatever returns - a bad
  key type, an unreadable CA file, a TPM error at ReadPCRs - W is locked (and the extra
  PCR extended) before the process exits.
- Which W: the CA file's when it loads; otherwise the one assh.conf names, or the default
  handle - locked only when it has W's shape (`persist.Shaped`), so a foreign index at
  that handle is never read-locked.
- An unparsable assh.conf: the default handle, as above, then the error.
- **The TPM does not open**: wait for `/dev/tpmrm0` to appear (a state, with an upper
  bound), then fail. And a new `assh close [--config]` - lock W, extend the extra PCR,
  nothing else - which the unit runs as `ExecStopPost=`: systemd runs it after every
  exit of the agent, a failed one included.
- Window PCR restricted to 0-15 (the DRTM PCRs 17-22 can be reset; info item).

**Tests:** for each error path (bad type, garbage CA file, CA file missing without
slots, TPM fault injected after open) the CA cannot sign afterwards; `assh close` on a
machine without a CA does nothing and is no error.

### P1-2: `ca remove` removes only what is provably aSSH's

The NV public areas in the file are no proof: a public area must have aSSH's shape **and**
the Name the TPM reports.

- **P**: equal to `written(pinIndexPublic(h))` - its policy is a constant.
- **G**: equal to the counter template whose policy is computed from P's Name and k: so
  only a counter that belongs to an aSSH PIN index goes. Without a file, k is read from P
  (`OwnerRead`) after P passed its own check.
- **W**: equal to W's template.
- Each with `persist.Shaped(template)` combined with `persist.Named` (a new
  `persist.All(...)`), so `persist` keeps its rule in one place.
- **`--force`**, for what a previous installation left at aSSH's handles (an index of
  another format, a CA file lost): removes the index at each of aSSH's handles - the
  defaults and those assh.conf or the flags name (P, G, W), never a handle a CA file
  names - whatever its shape. Each index is shown first (handle, attributes, size,
  Name) and removed after a confirmation on the terminal (`--yes` for scripts).

**Tests:** a CA file whose PIN entry names a foreign owner index: that index stays; a
foreign 8-byte counter with the generic attributes at the counter handle, without a file:
stays; aSSH's own P, G, W: removed.

### P1-3: no namespaces through `clone`

In the seccomp filter, before the deny list:

- `clone3` -> `ENOSYS`: its flags are in memory the filter cannot read; Go's runtime makes
  threads with `clone` and falls back from `clone3` on ENOSYS.
- `clone` with any of `CLONE_NEWNS|NEWCGROUP|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET`
  (mask `0x7E020000`; `CLONE_NEWTIME` exists only for clone3/unshare) -> `EPERM`, by
  `BPF_JSET` on the low word of args[0] (amd64 and arm64 alike).

**Tests:** after `Apply`, a raw `clone(CLONE_NEWUSER|SIGCHLD)` fails with EPERM, `clone3`
with ENOSYS, goroutines that need new threads still run. tpm2-kira's `gate-child` suite
runs against it.

### P1-4: not dumpable, and a uid of its own

- **`PR_SET_DUMPABLE 0`** in `sandbox.Apply` (process-wide): another process of the same
  uid can no longer ptrace it or read its `/proc/<pid>/mem`, `environ`, `fd` - the attack
  path. Test: `/proc/self/status` says `0` after Apply; a ptrace attach from a second
  process of the same uid fails.
- **A uid nobody else uses**, chosen per start (`server.Options.UID` 0 = choose):
  1. from a range, `ASSH_CHILD_UIDS` (default `0x7FFE0000-0x7FFEFFFF`: above every range
     systemd hands out - DynamicUser 61184-65519, containers 524288-1879048191 - and below
     2^31, so nothing treats it as negative);
  2. a candidate is taken only when no user database names it (`os/user.LookupId`),
     no process runs with it (every `/proc/<pid>/status` Uid line), and assh's own lock
     file for it, `/run/assh/uid/<uid>`, is held with `flock` by this server for the
     child's life - so two assh servers never share one;
  3. gid the same number, no supplementary groups, as now;
  4. no free candidate, no writable `/run/assh`: nobody (65534), logged.
  The child owns no file and makes none (Landlock), so a uid that no account names is no
  loss. What sharing nobody left - signals from other nobody processes (SIGSTOP: a denial
  of service) - is gone with it.
  Tests: two servers at once get different uids; a uid in the range already used by a
  process is skipped; a full range falls back to nobody.

## Steps

- [x] 1. P1-3 and P1-4 (sandbox, server): small, independent, tests
- [x] 2. P1-5: W, the new CA policy, `AdminWithPolicy`, `Close`, statement and `ca sign`,
       confirmation; format version up (an older CA file: "create the CA again")
- [x] 3. P1-1 on top of it: deferred close, `assh close`, the unit's `ExecStopPost=`
- [x] 4. P1-2: P, G, W by their definition (`persist.Defined`); `ca remove --force`
- [x] 5. README (window, approvals, statement, commands, security), AGENTS.md rules: the
       window is the CA's policy; nothing returns before the close; persist removes by
       shape and Name
- [x] 6. `go test -count=1 ./...`; tpm2-kira adapted to the API (its working tree,
       uncommitted), its unit and swtpm suites run; `../pin assh`
- [ ] 7. VM runs (`tools/vmtest.py --target both`, safearch's `tests/vm.sh`): later

## What breaks

- **Every CA is made again** (format and policy): tpm2-kira's `KIRAasshCA`, safearch's
  `SAFEasshCA`; clients need the new `@cert-authority` line.
- `ASSH_CA_WINDOW` and `ca create --window` go; `ASSH_WINDOW_HANDLE`,
  `ASSH_CHILD_UIDS`, `assh close`, `ca sign` come.
- tpm2-kira: `CAOptions.Window`, `CA.Window`, `hostkey.Close` change (above).
- The unprivileged half runs as a uid from the range, not nobody.

Found while implementing: W is closed when the CA is made, since before the
CA exists there is no W to close: a CA signs from the boot after its
creation. safearch's `--authority-once` in the initrd then certifies from
its second boot on (open question 1).

## Decisions (2026-10-29)

1. W's default handle `0x01802915`.
2. The child's uid range `0x7FFE0000-0x7FFEFFFF`.
3. `ca approve` asks to confirm on a terminal; `--yes` for scripts.
4. `ca remove --force` for leftovers at aSSH's handles, shown and confirmed.

## Open questions

1. safearch's first boot after `ca create --authority-once` in the initrd serves a
   temporary key: acceptable, or an explicit opt-in that leaves the window of the
   creating boot open (only where nothing runs before the agent closes it)?
