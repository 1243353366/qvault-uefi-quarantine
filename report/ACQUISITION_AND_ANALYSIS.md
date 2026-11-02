# Acquisition and analysis boundaries

How this project treats firmware samples, what the lab has to look like, and what an emulator
cannot tell you. Written because "we reverse engineer UEFI implants" invites two very different
readings, and only one of them is in scope here.

## What is in scope

Analysis of **published-source material and firmware images you are authorised to hold**: a dump
from hardware you own, a vendor image, or an artefact already documented in the literature. The
deliverable is detection, attribution discipline and remediation - never a working implant.

## What is not in scope, and will not be produced here

No new bootkit, implant or persistence mechanism. No patch to a known implant to make it
undetectable. No bypass of Secure Boot or of flash write protection. The mechanism is published;
reproducing it adds nothing to defence and everything to the supply of attack tooling.

## Three cases, not one claim

"Persists in hardware past Secure Boot" is the sort of sentence that makes a limitations page
weaker, because it merges three situations with different evidence and different remediation.
The taxonomy in `qvault/residency.py` is the single source; the table below is generated from it.

| family | substrate | hardware-resident | survives | removed by | revocation |
|---|---|---|---|---|---|
| lojax | SPI flash | yes | os reinstall, disk wipe, esp reformat, bootloader update | external reflash with a vendor image from a programmer; read-back comparison against the vendor image before returning to service | not sufficient on its own |
| moonbounce | SPI flash | yes | os reinstall, disk wipe, esp reformat, bootloader update | external reflash with a vendor image from a programmer; NVRAM considered separately, since the implant used it for storage | not sufficient on its own |
| blacklotus | EFI System Partition | no | os reinstall preserving esp | reformat and recreate the ESP; apply dbx/SVN revocation for the vulnerable bootloader | sufficient with ESP rebuild |

Three consequences follow, and they are the reason the table is code rather than prose:

- **Evidence differs.** For an SPI-resident implant only an out-of-band read is ground truth.
  For an ESP-resident implant an SPI read finds nothing, and the evidence is boot-partition
  content plus MOK, `dbx`/SVN and measured-boot state.
- **Remediation differs.** Reflash removes a flash module. It does nothing to a file on the
  ESP, and reformatting the ESP does nothing to a flash module.
- **Revocation differs.** `dbx` revocation is an effective control for BlackLotus's
  signed-but-vulnerable bootloader. It closes the boot path for a flash module without removing
  the module, so a read-back comparison is the closure criterion, not a revocation date.

## Working from a dump, not a live board

The rule that matters most: **do not analyse an actively infected board you depend on.** Take an
image, then work from the image.

1. **Acquire with an external SPI programmer.** Ground truth is the flash device's own contents,
   read by something outside the platform. Software readers (chipsec and friends) query the same
   SMM and SPI controller the implant may control, so they can be answered with a forgery. They
   are a lead generator, never the evidence.
2. **Diff against a clean vendor image** for that exact board and firmware version. A dump alone
   is not a finding; a difference from the vendor's own bytes is.
3. **Carve modules** with UEFITool NE or `uefi-firmware-parser`. Record section offsets and
   hashes so another analyst can reach the same bytes from the same image.
4. **Disassemble DXE drivers** in Ghidra with an EFI loader, or IDA with efiXplorer. Treat names
   as attacker-supplied until proven otherwise.
5. **Air-gap the analysis box.** Samples and tooling stay off the network, and the acquisition
   host is not the analysis host. This is separation of duties applied to a lab bench.
6. **Own the recovery path before you touch anything.** A programmer plus a verified known-good
   image for every board in the rack. Persistence in firmware means a mistake costs a reflash,
   and a board with no image and no programmer is a brick with a story attached.

Every artefact that leaves the bench carries source, timestamps, SHA-256 and chain of custody -
the same requirements `qvault/provenance.py` enforces, for the same reason: an analysed sample
whose provenance is unrecorded is not evidence.

## What an emulator cannot tell you

QEMU with OVMF is useful for logic, bootkit control flow and driver behaviour. It is not a model
of the platform's write protection, and that is where a large part of this class lives or dies.

- **`BIOS_CNTL` and the protected range registers are not emulated.** Whether a flash region is
  writable, and by whom, depends on the chipset's registers, the flash descriptor and SMM. A
  guest in QEMU has none of that state, so a write that would be blocked on real hardware
  succeeds, and a write that would succeed may be reported as blocked.
- **SPI controller behaviour is absent.** Anything that reasons about write-enable cycles,
  descriptor regions or lockdown timing cannot be validated in emulation.
- **SMM is not the real SMM.** SMI delivery, SMRAM locking and the interaction with the flash
  controller are approximations at best.
- **Measured boot is simulated.** A TPM in emulation reproduces the interface, not the assurance.

So: use the emulator to understand code, and use hardware when the question is a security
property. A claim about write protection that was only ever tested under OVMF is a hypothesis,
and `qvault/residency.py` plus the trust model exist to stop that hypothesis being reported as
a finding.

## The first step depends on why you are looking

This page describes project work: dumps you are authorised to hold, analysed to improve detection
and remediation. If instead you suspect **one of your own machines** is infected, the workflow is
different and starts elsewhere: stop using it for anything sensitive, do not run scanners from it
and trust the result, take the acquisition out of band (external programmer for firmware, a
read-only copy of the ESP for boot-partition cases), and preserve evidence before attempting
eradication. Analysis is the second step, not the first. A machine you are trying to clean is not
a lab bench.
