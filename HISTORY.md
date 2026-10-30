# History

Reasoning behind aSSH's design that the code and the README no longer
carry: why it is as it is, what was tried and measured. The README says
what it is.

## A PCR extended at the close (until 2026-10-30)

Before W, the window was a PCR (15) every slot had to read, extended when
the window closed. With W in the CA's policy (2026-10-29) the PCR stayed as
an extra, `--close-pcr` / `ASSH_CLOSE_PCR`, for what others bound to it
(tpm2-kira's code screen, safearch). It was removed so that a CA closes one
way everywhere: W alone. A PCR extended at the close also broke anything
bound to it afterwards (a volume enrolled with `--tpm2-pcrs=15`), and a
slot that leaves the PCR out was never stopped by it.

W closed at creation made safearch's identity, made in the initrd, certify
only from its second boot; `--window-open` restores the first, for CAs made
once alone.

## go-tpm pinned past v0.9.8 (2026-10)

go-tpm v0.9.8 cut an authorization value at any zero byte in its HMAC
sessions, where the TPM drops only trailing ones. A host key's
authorization value is random, so about one key in eight failed to sign.
google/go-tpm#446 fixed it; until a release has it, go.mod requires the
unreleased commit `36f205946d7e` (`hostkey/auth_test.go` signs with zero
bytes in every position). The fork (`github.com/mrwiora/go-tpm`, the branch
of google/go-tpm#452) adds TPM2_NV_ChangeAuth on top, for `tpmadmin`
alone.

## One CA layout for tpm2-kira and safearch, the CA in an EFI variable (2026-10-25/26)

Done 2026-10-26 (VM runs below). Built on the slots, the window and the
temporary key; it brought the CA in an EFI variable, `ca approve --slot
0,1` and assh.conf.

### Goal

The same CA layout in both projects:

| Slot | PCRs | Confidence |
|---|---|---|
| 0 | 0 (firmware), 2 (option ROMs), 7 (Secure Boot), 11 (the UKI and its phases), 15 (window); on GRUB machines 8 and 9 (GRUB's commands and files) instead of 11 | higher |
| 1 | 7, 15 | lower: still certifies after a kernel/image update that was not approved yet, a new option ROM, or a firmware update |

Window: PCR 15, closed right after the host key is certified.

The CA file, approvals included, lives in an **EFI variable**, in both
projects. No copy of it in a boot image: that is what makes PCR 11
possible. An approval carried inside the image it measures can never
match - it changes PCR 11 itself. safearch's earlier sealing of the CA
file to PCR 11 (systemd-creds) was dropped with it.

### Who signs in each project

| | tpm2-kira | safearch |
|---|---|---|
| authority | the signing key (`seal.key`, or the YubiKey) - the one that reseals | the authority key in the TPM, opened by the PIN |
| policyRef | `tpm2-kira ssh ca` | `safespace identity` |
| counter | none | yes: `--next-generation` revokes every older approval |

### Why the EFI variable is safe for it

Whatever is in the variable is checked by the TPM, never trusted.

| Attack on the variable | Result |
|---|---|
| read it | nothing: public keys, approvals, and the CA key wrapped by this TPM's storage key (loads in this TPM alone) |
| forge or edit an approval | the TPM refuses the signature, or the PCRs do not match |
| copy it to another machine | the CA does not load there: temporary key |
| delete or corrupt it (root, or a firmware reset of the NVRAM) | no certificate (temporary key), and the CA is gone, as with a TPM clear |
| write back an older approval (root) | the CA signs only if the machine boots that older state: with a counter (safearch) revoked; without one (tpm2-kira) it works for an older, still signed kernel - a downgrade, listed in tpm2-kira's known limits |

Writing an EFI variable takes root (or the firmware), and root can delete
the identity in any design. Attributes: non-volatile, boot service and
runtime access; no authenticated variable, since nothing would check it
that the TPM does not already check.

Size: the variable keeps the approvals of the next boot alone. Firmware
limits per variable are usually 8 KB or more; a compact encoding (CBOR,
zstd) was left for a machine that refuses, none has.

### tpm2-kira's side

- The CA's home is `KIRAasshCA`; `/etc/tpm2-kira/ssh_ca.json` and the
  image's copy of the CA went away (the `.pub` stays: what clients trust).
- Values of the next boot's code screen: PCR 0, 2, 7 replayed from the
  event log; PCR 11 predicted from the built UKI with the phase
  `enter-initrd`; PCR 15 empty.
- Approved by `reseal`, which the post-build hooks run after every image
  rebuild; a rebuild whose reseal is skipped (YubiKey not plugged in)
  still certifies through slot 1.
- GRUB machines: slot 0 is PCR 0, 2, 7, 8, 9, 15, PCR 8 and 9 predicted
  from grub.cfg and the files GRUB loads, chosen from the event log when
  the CA is created.

### safearch's side: what an update changes

Checked 2026-10-25 against systemd 262 and safearch's `lib/compose.sh`. The
agent starts in the root, `Before=sysinit.target`. By then, of the slot's
PCRs:

| PCR | Holds at the agent's start | Changes with an update | Known on the build host |
|---|---|---|---|
| 0, 2 | the firmware's measurements + `os-separator` | no | no - machine values, read from the machine (the agent's record) |
| 7 | Secure Boot state, PK/KEK/db/dbx, the db entry that authorized systemd-boot and the UKI + `os-separator` | no (same db key); yes after a dbx update or a key rotation | no |
| 11 | the UKI's sections + `enter-initrd` + `leave-initrd` | yes | yes: the UKI alone decides it |
| 15 | `safespace-combination:<name>`, then nothing (systemd-pcrmachine and -pcrfs masked or ordered after the agent) | no | yes (from the name) |

So the one value an update needs from outside is PCR 11, and it is fully
predictable from the release. A firmware update moves slot 0 only; a dbx
update moves both slots: temporary key until approved after the reboot.
`systemd-pcrproduct` measures into an NvPCR, not PCR 15. A PCR 11
predicted on the build host and sent to the machine over a signed channel
was left for later; signed PCRs (`ASSH_CA_SLOT_<N>_SIGNED`) came instead.

### Decisions (2026-10-25)

1. Variable names `KIRAasshCA` (tpm2-kira), `SAFEasshCA` (safearch),
   aSSH's GUID `24415b90-39be-45c0-a9a3-d547ebe28ea0`.
2. The variable is the CA's only copy, in both: a wiped NVRAM loses it,
   as a TPM clear does.
3. GRUB machines: slot 0 with PCR 8 and 9 instead of 11.
4. safearch after an update: slot 1 until slot 0 is approved for the
   recorded state after the reboot.
5. Slot 1 is PCR 7, 15 in both projects: a firmware update costs slot 0
   only.

What broke: tpm2-kira's existing CAs were not read; `control` created the
CA again and clients needed the new `@cert-authority` line.

### VM test, Arch UKI (2026-10-26)

QEMU/OVMF, Secure Boot with sbctl, a TPM, LUKS2 + btrfs, systemd 262;
tpm2-kira set up with `control`.

- `control` created the CA in `KIRAasshCA` (1294 bytes, attributes 7,
  immutable flag set again); the image build's reseal rewrote it with the
  predicted PCR 11.
- Boot: certified through slot 0; OpenSSH accepted the certificate with
  `StrictHostKeyChecking=yes` and only the `@cert-authority` line; PCR 15
  extended afterwards.
- A rebuild whose reseal did not run, with a changed command line:
  certified through slot 1. `reseal` afterwards approved slot 0 again.
- aSSH on real efivarfs: a variable rewritten larger (1321 bytes) and
  smaller (1294), read back without trailing bytes, immutable flag kept,
  deleted.

Learned: the boot image's DHCP client asked with another identity than
the running system's (no machine-id in the image), so the code screen got
another address; tpm2-kira's image now asks as the running system does.

### VM test, Debian GRUB (2026-10-26)

Debian 13, GRUB + shim, LUKS2 + LVM, dhcpcd, a TPM, Secure Boot in Setup
Mode. CA slot 0 PCR 0, 2, 7, 8, 9, 15, reseal approved PCR 8/9 predicted
from the rebuilt initrd. At boot `run` mounted efivarfs, read
`KIRAasshCA`, certified through slot 0; the disk unlocked from the SSH
session.
