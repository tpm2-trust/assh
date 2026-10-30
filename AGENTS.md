# Notes for agents working on aSSH

aSSH is used by other projects (tpm2-kira includes it as the git
submodule `assh/`, through a `replace` in its go.mod; safearch as a
submodule too). In the tpm2-trust workspace this checkout is the one that
is edited: `go.work` builds tpm2-kira and the vault against it, and
`../pin assh` moves the submodules to its HEAD. A change to an exported
name is a change to them: build and test tpm2-kira after one.

- **No host key and no secret of one is stored.** The CA lives in the TPM;
  host keys are made in the TPM under the NULL hierarchy, one per boot;
  their authorization values live in one process's memory. Do not add a
  mode that writes a key, or a secret that unlocks one, to a file. A
  cleared TPM loses the CA, and that is accepted: no backup, no export.
- **The PIN is never stored, logged or passed in argv or the environment.**
  It comes from the terminal or a file descriptor; whatever proves it to
  the TPM runs in a salted session, whatever carries it is encrypted.
- **Only the PIN index is DA-protected.** The storage primary, the CA, the
  authority key, the counter and the host keys are noDA, so that a lockout
  after wrong PINs never stops `Issue`. Anything that holds the PIN must
  be counted, and anything else must not be.
- **hostkey builds with go-tpm as released.** tpm2-kira compiles assh with
  its own go-tpm; assh's `replace` (the fork) does not reach it. Commands
  only the fork has are used in `tpmadmin` alone.
- **The window is the CA's own policy, and it fails closed.** Every CA
  has a window index W that its policy reads (`PolicyAuthorize ;
  PolicyCommandCode(Sign) ; PolicyNV(W == v)`), read-locked to close it: no
  approval can leave it out. A CA is created with its window closed, and
  every way out of `agent`/`serve` - a failure at any step - closes it
  (`assh close` after the unit, too). Never add a path that returns before
  the close, or a CA that signs in the boot that made it - but a CA made
  once with `--window-open`, whose approvals exist at its creation, made
  where nothing untrusted runs before the agent (an initrd). Nothing but W
  closes a CA: no PCR is extended at the close.
- **A temporary key is a host key like the others**: made in the TPM
  under the NULL hierarchy, never in software, and never certified. It is
  what a server serves when no slot certifies, and before the CA exists
  (assh.conf naming its slots: their PCRs recorded); an unreadable CA file
  or a TPM that does not open stays an error - with the window closed.
- **SHA-1 only where the TPM allows it.** `auto` reads SHA-1 only on a
  TPM without an active SHA-256 bank and while `hostkey.SHA1Handle` is
  there; others (safearch's initrd) read that index at its handle, so it
  stays where it is.
- **An authority made once approves once.** `--authority-once` makes it
  in the TPM under the NULL hierarchy, approves every slot, flushes it;
  never store it, never make it again for the same CA. Signed PCRs
  (`Slot.Signed`) are what keeps such a CA useful across updates.
- **A CA file may be an EFI variable** (`efi:NAME`, assh's GUID): plain,
  not authenticated, because the TPM checks everything in it. Keep it so:
  nothing that the TPM does not check goes into a CA file.
- **Every setting has a key in assh.conf** (`config`, `ASSH_*`), and a
  flag given wins over it. A new flag of how a CA, host key or server is
  set up gets its key too, in `Config`, `set`, `Lines` and the README's
  table. Nothing secret goes into it, and nothing in it is trusted.
- **No backwards compatibility.** One file format, the current one
  (`hostkey.fileVersion`); another version is an error that says to
  create the CA again. No migrations.
- **The side that speaks SSH holds nothing.** `server`'s unprivileged half
  runs as a uid no one else has (`sandbox.ClaimUID`; nobody only when none
  is free), in namespaces of its own, confined by `sandbox` - not dumpable,
  no namespace it could make - and asks for every signature; it never gets
  the key or a session's other end before a login. Keep it that way.
- **Whoever approves reads what is approved.** `ca approve` shows the
  statement and asks; a key elsewhere signs a statement (`ca sign`), not
  bytes it cannot read. Nothing from the CA file or assh.conf is taken as
  what the owner meant.
- **NV indices and EFI variables go through `persist`.** Nothing calls
  NVUndefineSpace or writes efivarfs by itself: an index is removed only
  when it is provably ours - defined exactly as aSSH defines it at that
  handle (`persist.Defined`), never because a CA file names it; the
  exceptions: `RedefineCounter` replaces what is at the CA's own handle
  after the PIN is proven, and `ca remove --force` removes what a person
  saw and confirmed (`persist.Any`) - absent is not an error, and a
  variable is written in place, never removed first. Programs built on aSSH use the
  same package (tpm2-kira) or the `assh efivar` command (safearch's
  scripts).
- **A confinement step covers every thread.** prctl, Landlock and
  seccomp act on the thread that asks, and a Go program has several from
  its start: `sandbox` takes each step on all of them
  (`syscall.AllThreadsSyscall`, seccomp's TSYNC). Never confine with a
  plain `unix.Prctl` or `unix.Syscall`.
- **Tests run with `-count=1` and wait for a state, never for a time.**
  TPM tests use swtpm (`internal/swtpmtest`) and are skipped without it.
- **Comments and docs say what it is**, not what it was.
