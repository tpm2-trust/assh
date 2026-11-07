# History

Reasoning behind aSSH's design that the code and the README no longer
carry: why it is as it is, what was tried and measured. The README says
what it is.

## The window index W replaced by PCR 15 in the CA's policy (2026-11-01)

W (an NV counter, read-locked at the close; 2026-10-29 to 2026-11-01) was
replaced by PCR 15 in the CA's own policy (`PolicyPCR(15 == open value)`
after PolicyAuthorize), closed by an extend. Why the PCR 15 window of
before W was left, and what answers each reason now:

- *An approval could leave PCR 15 out* (a slot read it only if its approval
  said so). Now the CA's policy reads it, fixed at creation: no approval,
  of any slot, signed or not, can leave it out.
- *A PCR extended at the close broke what was bound to it afterwards* (a
  volume enrolled with `--tpm2-pcrs=15`). Still true for a binding to PCR
  15 as it is after the close; the close happens at fixed points of the
  boot (before systemd measures volume keys, the machine-id and file
  systems), so a binding made on the running system meets the same value
  at every boot of the same setup. A binding to PCR 15 at zero after the
  close cannot hold, as it cannot with systemd's own measurements.
- *W closed at creation made safearch's identity certify from its second
  boot*; `--window-open` gave the first back. Now `--open-events`: the open
  value is what the initrd measures, and only a CA made once is left open.

What W had that PCR 15 does not: it was the CA's alone, so nothing else
could close it early; PCR 15 is systemd's too, and anything that measures
into it before the server closes the CA (and any process with the TPM's
device) stops the CA for the boot - a denial of service, never a way in.
What PCR 15 has that W did not: nothing in the TPM to define, remove or
clone, no handle to configure, and the close needs no CA file.

Three ways to close were tried side by side on the VMs (tpm2-trust's
branches `exp/close-counter`, `exp/close-pcr15`, `exp/debian-uki`). The
other two, and why not:

- *A window on another project's counter* (`--window-external`: kira's
  slot 0 generation index, one read-lock for its codes and the CA). It
  tied the CA to a user's index - no such index, no CA; the index
  deleted, the CA stopped - and kept the window open as long as the user
  needed the index, not until the certificate. Root with the empty owner
  password could delete the read-locked index and define it again with
  the same Name, and whoever held the index's write key could reopen the
  CA in the same boot: an aSSH window, a counter, cannot be made again
  alike. It also showed that a window index that counts towards the
  dictionary attack cannot be read-locked in a lockout - one more reason
  for the rule that only the PIN index is DA-protected.
- *No new close at all, the boot made like Arch's on Debian* (systemd-boot
  and a UKI, so that systemd-pcrosseparator closes). Debian 13's systemd
  (257) has no separator; the close was needed there anyway.

## EFI variables in the workspace's go-uefi-slim module (2026-10-30)

`persist` wrote efivarfs itself, and did not put the immutable mark back
when a write failed, nor refuse an empty write, which efivarfs takes as a
removal (TODO-SEC P3-14). The workspace first moved to go-uefi (sbctl's
library). Upstream lacked a settable directory, removal, putting the mark
back and truncation, and its check of the mark created a missing file (an
empty variable on efivarfs). A fork had them, but upstream did not take
them, and go-uefi cost aSSH 422 KB and three modules (go-uefi, afero,
pkg/errors). So the workspace has its own module, `go-uefi-slim`, with the standard
library and x/sys alone; `persist` keeps its API on top of it.

## A PCR extended at the close (until 2026-10-30)

Before W, the window was a PCR (15) every slot had to read, extended when
the window closed. With W in the CA's policy (2026-10-29) the PCR stayed as
an extra, `--close-pcr` / `ASSH_CLOSE_PCR`, for what others bound to it
(kira's code screen, safearch). It was removed so that a CA closes one
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
bytes in every position). TPM2_NV_ChangeAuth for `tpmadmin` came from a
fork (`github.com/mrwiora/go-tpm`, google/go-tpm#452) until upstream took
it (`c395998`, 2026-10-30), which go.mod now requires.

## One CA layout for kira and safearch, the CA in an EFI variable (2026-10-25/26)

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

| | kira | safearch |
|---|---|---|
| authority | the signing key (`seal.key`, or the YubiKey) - the one that reseals | the authority key in the TPM, opened by the PIN |
| policyRef | `kira ssh ca` | `safespace identity` |
| counter | none | yes: `--next-generation` revokes every older approval |

### Why the EFI variable is safe for it

Whatever is in the variable is checked by the TPM, never trusted.

| Attack on the variable | Result |
|---|---|
| read it | nothing: public keys, approvals, and the CA key wrapped by this TPM's storage key (loads in this TPM alone) |
| forge or edit an approval | the TPM refuses the signature, or the PCRs do not match |
| copy it to another machine | the CA does not load there: temporary key |
| delete or corrupt it (root, or a firmware reset of the NVRAM) | no certificate (temporary key), and the CA is gone, as with a TPM clear |
| write back an older approval (root) | the CA signs only if the machine boots that older state: with a counter (safearch) revoked; without one (kira) it works for an older, still signed kernel - a downgrade, listed in kira's known limits |

Writing an EFI variable takes root (or the firmware), and root can delete
the identity in any design. Attributes: non-volatile, boot service and
runtime access; no authenticated variable, since nothing would check it
that the TPM does not already check.

Size: the variable keeps the approvals of the next boot alone. Firmware
limits per variable are usually 8 KB or more; a compact encoding (CBOR,
zstd) was left for a machine that refuses, none has.

### kira's side

- The CA's home is `KIRAasshCA`; `/etc/kira/ssh_ca.json` and the
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

1. Variable names `KIRAasshCA` (kira), `SAFEasshCA` (safearch),
   aSSH's GUID `24415b90-39be-45c0-a9a3-d547ebe28ea0`.
2. The variable is the CA's only copy, in both: a wiped NVRAM loses it,
   as a TPM clear does.
3. GRUB machines: slot 0 with PCR 8 and 9 instead of 11.
4. safearch after an update: slot 1 until slot 0 is approved for the
   recorded state after the reboot.
5. Slot 1 is PCR 7, 15 in both projects: a firmware update costs slot 0
   only.

What broke: kira's existing CAs were not read; `control` created the
CA again and clients needed the new `@cert-authority` line.

### VM test, Arch UKI (2026-10-26)

QEMU/OVMF, Secure Boot with sbctl, a TPM, LUKS2 + btrfs, systemd 262;
kira set up with `control`.

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
another address; kira's image now asks as the running system does.

### VM test, Debian GRUB (2026-10-26)

Debian 13, GRUB + shim, LUKS2 + LVM, dhcpcd, a TPM, Secure Boot in Setup
Mode. CA slot 0 PCR 0, 2, 7, 8, 9, 15, reseal approved PCR 8/9 predicted
from the rebuilt initrd. At boot `run` mounted efivarfs, read
`KIRAasshCA`, certified through slot 0; the disk unlocked from the SSH
session.
