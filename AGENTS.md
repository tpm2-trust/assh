# Notes for agents working on aSSH

aSSH is used by other projects (tpm2-kira, `../tpm2-kira`, through a
`replace` in its go.mod). A change to an exported name is a change to them:
build and test tpm2-kira after one.

- **No host key and no secret of one is stored.** The CA lives in the TPM;
  host keys are made in the TPM under the NULL hierarchy, one per boot;
  their authorization values live in one process's memory. Do not add a
  mode that writes a key, or a secret that unlocks one, to a file.
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
