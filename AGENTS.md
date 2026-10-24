# Notes for agents working on aSSH

aSSH is used by other projects (tpm2-kira includes it as the git
submodule `assh/`, through a `replace` in its go.mod). A change to an
exported name is a change to them: build and test tpm2-kira after one.

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
- **The window closes every slot.** A CA with a window has every slot
  read that PCR; a slot that does not would sign after the window closed.
- **A temporary key is a host key like the others**: made in the TPM
  under the NULL hierarchy, never in software, and never certified. It is
  what a server serves when no slot certifies; an unreadable CA file or a
  TPM that does not open stays an error.
- **No backwards compatibility.** One file format, the current one
  (`hostkey.fileVersion`); another version is an error that says to
  create the CA again. No migrations.
- **The side that speaks SSH holds nothing.** `server`'s unprivileged half
  runs as nobody, in namespaces of its own, under Landlock, and asks for
  every signature; it never gets the key or a session's other end before
  a login. Keep it that way.
- **Tests run with `-count=1` and wait for a state, never for a time.**
  TPM tests use swtpm (`internal/swtpmtest`) and are skipped without it.
- **Comments and docs say what it is**, not what it was.
