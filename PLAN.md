# PLAN: one SSH CA layout for tpm2-kira and safearch, the CA in an EFI variable

Status: **done** (confirmed 2026-10-25; VM runs 2026-10-26): steps 1-5. Builds on assh `feat/slots`
(format 3: slots, window, temporary key).

## Goal

- The same CA layout in both projects:

  | Slot | PCRs | Confidence |
  |---|---|---|
  | 0 | 0 (firmware), 2 (option ROMs), 7 (Secure Boot), 11 (the UKI and its phases), 15 (window); on GRUB machines 8 and 9 (GRUB's commands and files) instead of 11 | higher |
  | 1 | 7, 15 | lower: still certifies after a kernel/image update that was not approved yet, a new option ROM, or a firmware update |

  Window: PCR 15, closed right after the host key is certified.
- The CA file, approvals included, lives in an **EFI variable**, in both projects, read and
  written by assh. No copy of it in a boot image. That is what makes PCR 11 possible: an
  approval carried inside the image it measures can never match (it changes PCR 11 itself).
- Old builds are no concern (safearch's PCR 11 sealing of the CA file is dropped).

## What an approval is

An approval is the authority's signature over one PCR state of one slot. In the file:

```
Approval{ Slot int, PCRs map[int][]byte (the slot's PCR values), Generation uint64, Signature }
```

What is signed (all SHA-256; it is what the TPM computes itself in a policy session):

```
pcrDigest      = SHA-256( value[p] for each PCR p of the slot, in index order )
approvedPolicy = PolicyPCR(selection = the slot's PCRs in the CA's bank, pcrDigest)
                 [ ; PolicyNV(counter index, == Generation) ]   only with a counter (PIN authority)
                 -- as a policy digest, starting from 32 zero bytes
ApprovalDigest = SHA-256( approvedPolicy || policyRef )
Signature      = TPMT_SIGNATURE of the authority over ApprovalDigest
```

The CA key's own policy is fixed at creation: `PolicyAuthorize(authority Name, policyRef)`.
It names no PCR. When the CA signs a host certificate, the TPM:

1. `TPM2_VerifySignature(authority, ApprovalDigest, Signature)` → a ticket, only if the
   signature is the authority's;
2. `PolicyPCR` in a session: passes only if the PCRs **now** hold the approved values;
3. `PolicyNV` (with a counter): passes only if the counter is **now** at Generation;
4. `PolicyAuthorize(approvedPolicy, policyRef, ticket)` turns that into the CA's policy;
5. `TPM2_Sign` with the CA key.

So an approval is a **public statement** "the CA may sign while slot N's PCRs hold these
values": it contains nothing secret, and it cannot be forged or altered without the
authority's key (signing key / the PIN-protected key in the TPM).

| Who signs | tpm2-kira | safearch |
|---|---|---|
| authority | the signing key (`seal.key`, or the YubiKey) - the one that reseals | the authority key in the TPM, opened by the PIN |
| policyRef | `tpm2-kira ssh ca` | `safespace identity` |
| counter | none | yes: `--next-generation` revokes every older approval |

## Is the EFI variable safe for it?

Yes: whatever is in the variable is checked by the TPM, never trusted.

| Attack on the variable | Result |
|---|---|
| read it | nothing: public keys, approvals, and the CA key wrapped by this TPM's storage key (loads in this TPM alone) |
| forge or edit an approval | the TPM refuses the signature (step 1) or the PCRs don't match (step 2) |
| copy it to another machine | the CA doesn't load there: temporary key |
| delete or corrupt it (root, or a firmware reset of the NVRAM) | no certificate (temporary key) - and the CA is gone, as with a TPM clear (see open question 2) |
| write back an older approval (root) | the CA signs only if the machine actually boots that older state: with a counter (safearch) revoked; **without one (tpm2-kira) it works** for an older, still signed kernel - a downgrade. Same as today with a copied file; listed in tpm2-kira's known limits |

Writing an EFI variable takes root (or the firmware); root can delete the identity in any
design. Attributes: non-volatile, boot service and runtime access; no authenticated
variable (nothing would check it that the TPM doesn't already check).

## Design

### assh

- `hostkey`: the CA in an EFI variable. `LoadCA("efi:NAME")`, `(*CA).Save("efi:NAME")`: efivarfs
  (`/sys/firmware/efi/efivars/<name>-<GUID>`, 4 bytes of attributes, then the file), the
  immutable flag cleared for a write and set again; the efivarfs directory injectable for
  tests. One GUID for assh: `24415b90-39be-45c0-a9a3-d547ebe28ea0`.
- The CLI: `--ca efi:NAME` wherever it takes `--ca FILE`.
- Size: the variable keeps the approvals of the next boot alone (both slots). Today ≈1.6 KB
  with one approval; with two ≈2 KB. Firmware limits per variable are usually ≥ 8 KB; if a
  machine refuses, a compact encoding (CBOR/zstd) is the next step, not now.
- `ca approve --slot 0,1`: several slots with one PIN entry and one `--next-generation`.

### tpm2-kira

- The CA's home is the EFI variable `KIRAasshCA`. `/etc/tpm2-kira/ssh_ca.json` goes away
  (the `.pub` beside it stays: what clients trust). The image carries no CA:
  `/etc/tpm2-kira/ssh/ca.json` is dropped from it, and the SSH part of the boot plan no
  longer depends on approvals (only: on, network, TPM, a CA, a login key).
- Values of the next boot's code screen: PCR 0, 2, 7 replayed from the event log; PCR 11
  predicted from the built UKI with the phase `enter-initrd` (`PredictPCR11FromUKI`, as
  `seal` does); PCR 15 empty.
- Approved by **`reseal`**, which the post-build hooks already run after every image
  rebuild (mkinitcpio post hook, initramfs-tools post-update.d and kernel postinst): it
  approves both slots with the signing key and writes the variable. `control` does the
  same at quit, and creates the CA. A rebuild whose reseal is skipped (YubiKey not
  plugged in): slot 1 still certifies, the console says slot 0 is not approved.
- `run --ssh-ca efi:KIRAasshCA`: reads the variable in the initrd (efivarfs: mounted
  by systemd on Arch; mounted by `init-premount/tpm2-kira` on Debian).
- **GRUB machines:** slot 0 is PCR 0, 2, 7, 8, 9, 15: PCR 8 and 9 predicted from grub.cfg
  and the files GRUB loads, as `seal`'s slot 0 there. The choice is made when the CA is
  created, from the event log, as `seal` decides (`DefaultPCRSelection`).

### safearch (its PLAN.md follows this)

- `SAFEasshCA` holds the assh CA file as is: no systemd-creds sealing (old builds
  dropped).
- Approved with the PIN: at creation and at a move, both slots.
- **After an update** only PCR 11 moves (see "What an update changes" below): slot 1
  certifies after the reboot, and `safespace-seal --approve` approves slot 0 for the
  recorded state with the PIN.
- **Later:** the build host predicts the release's PCR 11 (`systemd-measure calculate
  --phase=enter-initrd:leave-initrd`, as `compose_check` already computes the policy) and
  the machine approves it before the reboot. That needs a safe distribution channel for
  the value (signed by the build host, e.g. with the PCR signing key, and checked on the
  machine) - not now.

### What an update changes (safearch, checked 2026-10-25 against systemd 262 and lib/compose.sh)

The agent starts in the root, `Before=sysinit.target`. By then, of the slot's PCRs:

| PCR | Holds at the agent's start | Changes with an update | Known on the build host |
|---|---|---|---|
| 0, 2 | the firmware's measurements + `os-separator` (systemd-pcrosseparator, initrd, extends 0-7, 9, 12-14) | no | no - machine values, read from the machine (the agent's record) |
| 7 | Secure Boot state, PK/KEK/db/dbx, the db entry that authorized systemd-boot and the UKI + `os-separator` | no (same db key); **yes** after a dbx update or a key rotation | no - machine values, read from the machine |
| 11 | the UKI's sections (one UKI for every combination) + `enter-initrd` + `leave-initrd` (systemd-pcrphase-initrd's stop at the switch; `sysinit` comes after sysinit.target) | **yes** | **yes**: the UKI alone decides it, the same for every machine and combination |
| 15 | `safespace-combination:<name>` (select), then nothing (systemd-pcrmachine and -pcrfs masked or ordered after the agent) | no | yes (from the name) |

So PCR 0 and 2 are never calculated: they don't change with an update and are taken from
the machine. The one value an update needs from outside is PCR 11, and it is fully
predictable from the release. A firmware update (PCR 0, 2) moves slot 0 only; a dbx
update (PCR 7) moves both slots: temporary key until approved after the reboot. `systemd-pcrproduct` measures
into an NvPCR, not PCR 15.

## Steps

- [x] 1. assh: EFI variable storage (`LoadCA`/`Save` with `efi:NAME`, `--ca efi:NAME`), tests with a
      fake efivarfs directory; `ca approve --slot 0,1`; README, AGENTS.md.
- [x] 2. tpm2-kira: slot 0 with PCR 11; the CA in `KIRAasshCA`; `reseal` and `control`
      approve both slots and write it; the image without the CA; `run` reads the variable;
      efivarfs on Debian; docs/SSH.md, help, HISTORY.md. Tests: swtpm (prediction matches
      the replayed boot; slot 1 after an unapproved rebuild; window), unit (plan, fake
      efivarfs).
- [x] 3. VM (Arch UKI, Debian GRUB): the variable written by reseal, read at the code
      screen, certified through slot 0; a rebuild without reseal → slot 1 (Arch).

## VM test, Arch UKI (2026-10-26)

QEMU/OVMF, Secure Boot with sbctl, a TPM, LUKS2 + btrfs, systemd 262. tpm2-kira installed
at the package's paths, set up with `control` (hook, command line, signing key, TOTP
slots, network DHCP, SSH, CA P-256).

- `control` created the CA in `KIRAasshCA` (1294 bytes, attributes 7, immutable flag set
  again); the image build's reseal rewrote it with the predicted PCR 11.
- Boot: `certified … through slot 0`; OpenSSH accepted the certificate with
  `StrictHostKeyChecking=yes` and only the `@cert-authority` line; code #0 matched; the
  disk unlocked from the session; PCR 15 extended afterwards.
- A rebuild whose reseal did not run (signing key moved away) with a changed command line:
  TOTP slot 0 failed on PCR 11 as expected, the host key was `certified … through slot 1`.
  `reseal` afterwards approved slot 0 again; a second reseal: "every slot is approved".
- assh on real efivarfs: a variable rewritten larger (1321 bytes) and smaller (1294),
  read back without trailing bytes, immutable flag kept, deleted.

### Learned: the address at boot is not the running system's

The image's systemd-networkd asks DHCP with `ClientIdentifier=mac` (the image has no
machine-id); the running system's asks with IAID+DUID (from the machine-id). The DHCP
server sees two clients: the code screen got 172.17.2.100, the system 172.17.2.198. The
console shows the address, but whoever expects the machine at its usual address finds
nothing - and a `known_hosts` line that names the hosts must name both.

Done (2026-10-26, decided: the identity from the host, control.conf overrides): the image
asks as the running system does, read at every build from its DHCP client - systemd-
networkd (`networkctl --json`: IAID + DUID → `ClientIdentifier=duid`, `IAID=`,
`DUIDType=`, `DUIDRawData=`), NetworkManager's lease, dhcpcd (its DUID file, the MAC's
last four bytes as IAID); Debian's image asks with busybox' udhcpc (`-x 0x3d:`), as
klibc's ipconfig sends no identifier. Verified: Arch .198 at the code screen and after,
Debian .196 both times. safearch keeps the running system's network, no image network.

### VM test, Debian GRUB (2026-10-26)

Debian 13, GRUB + shim, LUKS2 + LVM, dhcpcd, a TPM, Secure Boot in Setup Mode. The .deb
built from the working trees: control set the keyscript, the slots, DHCP and SSH; the CA
slot 0 PCR 0, 2, 7, 8, 9, 15 (GRUB), reseal approved PCR 8/9 predicted from the rebuilt
initrd. At boot `run` mounted efivarfs, read KIRAasshCA, certified through slot 0, udhcpc
got .196, the disk unlocked from the SSH session.
- [x] 4. safearch: PLAN.md updated (done with this plan); its implementation follows its
      own steps.
- [x] 5. assh.conf (`config`, decided 2026-10-26): every setting of assh in one KEY=VALUE
      file (`ASSH_*`), `--config` on every command, a flag wins; `ca sync` makes a CA's
      slots the file's. tpm2-kira: /etc/tpm2-kira/assh.conf beside control.conf (the CA,
      its slots, the port, the keys), control writes the slots it works out, reseal
      follows an edit; control.conf keeps the network, SSH on/off, the hold, and the
      image's DHCP identity (TPM2_KIRA_NET_DHCP_ID).

## What changes / breaks

- tpm2-kira: existing CAs (`/etc/tpm2-kira/ssh_ca.json`) are not read: control creates the
  CA again, clients need the new `@cert-authority` line. Every rebuild's reseal also writes
  an EFI variable (≈2 KB, once per rebuild).
- safearch: no change to anything built yet (plan only).

## Decisions (2026-10-25)

1. Variable names `KIRAasshCA` (tpm2-kira), `SAFEasshCA` (safearch), assh's GUID.
2. The variable is the CA's only copy, in both: a wiped NVRAM loses it, as a TPM clear.
3. GRUB machines: slot 0 with PCR 8 and 9 instead of 11.
4. safearch after an update: slot 1 until slot 0 is approved for the recorded state after
   the reboot. A predicted PCR 11 from the build host over a safe channel: later.
5. Slot 1 is PCR 7, 15 in both projects: a firmware update costs slot 0 only.
