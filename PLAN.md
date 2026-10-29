# PLAN: README reworked for what aSSH is now

Status: **done** (confirmed 2026-10-29).

## Goal

The README grew one section per feature (slots, window, temporary key, PIN authority, signed
PCRs, authority-once, SHA-1, EFI variable, persist, sandbox) and is now a chronological
pile: correct in nearly every detail, hard to read front to back, with gaps where the newer
packages are. Rework it into a document ordered by what a reader needs - what it is, how to
run it, how it works, how to choose, reference - with every fact checked against the code.

## Findings (README against f16b87b)

| # | Finding | Fix |
|---|---|---|
| 1 | Only tpm2-kira named as a user; safearch uses the `assh` command in its image and initrd | both, with what each uses |
| 2 | `persist` and `sandbox` have a table row and nothing else; `assh efivar` is not documented beyond usage | a section each (rules, API, the command) |
| 3 | The window is explained twice ("The window", "Closing the window"/"PCR 15") | one section |
| 4 | Three authorities (elsewhere, PIN, once) plus signed PCRs are spread over 4 sections with no way to compare | a comparison table, then one subsection each |
| 5 | No quick start, no build/install: the systemd unit (`systemd/assh-agent.service`) and sshd's `Include` appear only in passing | "Quick start" and "Building" |
| 6 | The agent's files are partly listed (`sshd.conf`, `status`); `host.pub`, `host-cert.pub`, `agent.sock`, `agent.pcrs.json` are not | one table of what the agent writes in `/run/assh` |
| 7 | `ca show`, `ca remove`, `tpm da` described only inside examples | a command reference table |
| 8 | ASCII diagrams; the workspace asks for Mermaid | Mermaid: trust chain, Issue sequence |
| 9 | Library section lacks `CAOptions.Slots`/`SlotSpec`/`NewSigned`, `CreateOnceCA`, `RemoveCA`, `persist`, `sandbox` | added, short |
| 10 | Unprivileged half: README says "namespaces of its own"; it is net, IPC, PID, mount, UTS, plus no-new-privs, MDWE, Landlock, seccomp | stated precisely in the server section |

No security issue found in the README's claims.

## Structure

1. Title, one paragraph, users (tpm2-kira, safearch), the packages table
2. Quick start: CA + agent + sshd in five commands (authority in the TPM), the known_hosts line
3. How it works: the keys (table), trust chain (Mermaid), slots and approvals, `Issue`
   (Mermaid sequence), the window, the temporary key
4. The authority: comparison table; elsewhere; in the TPM (PIN, counter, DA, lockout auth);
   once; signed PCRs (combinable with each)
5. Over the machine's life: PCRs change, a move, the TPM cleared, `ca remove`
6. Where the CA is kept: a file or an EFI variable
7. The SHA-1 bank
8. Serving: `assh agent` with sshd (files it writes, the unit, key ID, status), `assh serve`
9. assh.conf: the key table (unchanged content, checked against `config`)
10. Commands: one table of every command
11. The library: hostkey, server, agent, tpmadmin, config, persist, sandbox
12. Security: what it protects against, what not, the PIN authority's attack table
13. Building and testing; known limits (go-tpm pin and fork)

## Steps

- [x] 1. Rewrite README.md in the structure above, keeping its terse style and every
       still-true fact; nothing about earlier versions. Quick start with the PIN authority
- [x] 2. Every flag, assh.conf key and API name in it checked against the code
- [x] 3. `go vet ./...`, `go test -count=1 ./...` (swtpm); the library examples compiled
       against the API
- [x] 4. History moved to HISTORY.md: the previous plan (one CA layout, the CA in an EFI
       variable, its VM runs) and the go-tpm #446 note from `hostkey/auth_test.go`
- [ ] 5. Commit in `assh/` on `docs/readme` when confirmed; `../pin assh` afterwards

## Decisions (2026-10-29)

1. The previous plan's reasoning goes to HISTORY.md, as does history in code comments.
2. The quick start uses the authority in the TPM (PIN).
3. English, the current terse style.
