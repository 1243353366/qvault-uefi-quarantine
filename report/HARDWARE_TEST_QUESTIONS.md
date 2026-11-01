# Unanswered questions that require hardware testing

Everything below cannot be settled by reading, by static analysis, or in a VM.
Each entry states why hardware is required, what rig answers it, the cheapest
experiment, and what result would confirm or refute the current assumption.

These are the questions where this project is currently guessing. They are listed
in the order that would most improve defensive decisions.

**Safety constraints for every experiment here**

- Bench hardware only. Never a production machine, never a machine with data you
  care about, never one holding credentials.
- Work only from stock vendor images obtained from the OEM. No experimental
  firmware implants, no modified boot chains for persistence. Two questions below
  would classically have required manufacturing a malicious module; both have an
  observational substitute, noted inline, and the substitute is what is specified.
- Full external flash backup before the first power-on, and a verified restore
  procedure, or the board is a write-off.
- Assume any SPI write may brick the board. Cost it before starting.

---

## H1. Does a full-region firmware update actually remove an unexpected FFS file?

**Why documents cannot answer it.** Vendor release notes describe features, not
region coverage. Whether a capsule rewrites the entire BIOS region or preserves
sectors is an implementation detail that differs per OEM and per update mechanism.

**Rig.** Two identical boards of one model with a known SPI-writeable path, a
hardware SPI programmer with a clip, the OEM's latest capsule, and a way to flash
a modified image that is not the running OS (programmer is fine).

**Experiment.** *(Observational substitute for implant testing.)* Read the flash
and hash it per region and per FFS file. Apply the OEM capsule through the OEM's
own update path. Read the flash again and diff. Then answer the real question:
does the byte range the capsule touched cover the free space at the end of each
DXE volume, where a foreign module would sit?

**Confirm / refute.** Confirms "a full-region update removes it" only if the whole
BIOS region's free space is rewritten. Refutes the current claim if the capsule
writes only changed files, leaving volume slack untouched.

**Effort.** 1 day per model. Directly decides whether "update the firmware" is
remediation or theatre. This is the single most decision-relevant experiment here.

---

## H2. Which BIOS write-protection bits are actually set, per OEM and SKU?

**Why documents cannot answer it.** `BIOSWE`, `BLE`, `SMM_BWP`, the `PR0`-`PR5`
ranges, `FLOCKDN` and descriptor region permissions are firmware policy, not
architecture. Two boards from the same vendor with different BIOS revisions may
differ. No datasheet states what a shipping platform configures.

**Rig.** A live-boot CHIPSEC environment per model; a small fleet sample covering
each generation in use.

**Experiment.** Run `chipsec_main` on the BIOS-write-protection and SPI-protection
modules; record `BIOS_CNTL`, each `PRx`, `FLOCKDN`, the descriptor region table,
and whether Boot Guard is enabled. Record BIOS version and date with each result.

**Confirm / refute.** Produces a per-model exposure table: which machines are one
kernel bug away from a firmware implant. Refutes any assumption that "modern"
implies "protected".

**Effort.** Hours per model, once. This is the metric that should appear on a risk
register, and almost nowhere does it.

---

## H3. Does the `BLE` race still work on current chipsets?

**Why documents cannot answer it.** The Speed Racer technique dates from 2015.
Whether current PCHs close it by policy, by `SMM_BWP`, or not at all is an
empirical question, and vendors have no incentive to publish the answer.

**Rig.** Bench boards spanning generations, with a programmer available to restore
after failed attempts.

**Experiment.** In a laboratory setting, with the vendor image restorable, measure
whether a write to the BIOS region can be completed while `BLE` is set. Record
which of `SMM_BWP`, `PRx` and descriptor permissions blocked it, if any.

**Confirm / refute.** Confirms the mitigation hierarchy in report §2.4, or shows
that `PRx`/`FLOCKDN` are now the only load-bearing controls.

**Effort.** 2-3 days, and genuinely risky for the board.

---

## H4. Does measured boot actually detect a modified firmware component on this platform?

**Why documents cannot answer it.** Measurement coverage is a firmware
implementation choice: which components are extended into which PCR, and whether
that happens before or after the modification point, varies by vendor and by
whether Boot Guard is in verified or measured mode.

**Rig.** One board, TPM 2.0 with a readable event log, two firmware states: stock,
and stock plus a *vendor-supplied* optional module or a firmware setting change
that alters the image.

**Experiment.** Capture the TCG log and a TPM quote (`pcrread` / `tpm2_quote`) in
each state; diff the event log and the PCR values.

**Confirm / refute.** If PCR0/PCR4 do not change when a DXE component changes, then
measured boot is not a detection control for firmware modification on that
platform, and any architecture relying on it (including parts of §7.5 and the
vault's own trust assumptions) needs the correction.

**Effort.** 1-2 days. High value: it either validates or demolishes a load-bearing
assumption.

---

## H5. Does a NVRAM reset actually clear `MokList`, and what is the boot outcome?

**Why documents cannot answer it.** The report states [INFERRED] that clearing
NVRAM removes BlackLotus's trust anchor but leaves it unbootable. Whether a given
firmware clears the MOK variable on a CMOS/NVRAM reset, and whether the machine
then boots or bricks, is platform behaviour.

**Rig.** A bench machine with an ESP you control, and the ability to reflash/recover.

**Experiment.** Enroll a *test* MOK certificate of your own (a legitimate
supported operation via `mokutil`), confirm it appears in `MokList`, then clear
NVRAM both ways (CMOS battery / firmware menu option) and observe the variable and
the boot result.

**Confirm / refute.** Determines whether the documented recovery step is safe in
practice, and whether "clear NVRAM" is a viable emergency action during an
incident.

**Effort.** 4 hours. Cheap, and it changes incident-response guidance.

---

## H6. Do DRTM late-launch measurements exclude a compromised DXE/SMM environment?

**Why documents cannot answer it.** TXT and SKINIT are specified to establish a
fresh measurement root after platform boot. Whether a specific platform's
implementation gives a verifier a trustworthy statement in the presence of a
modified DXE phase is exactly the question the enclave design depends on, and it
is empirical.

**Rig.** A DRTM-capable board, TPM, and a known-good launch environment.

**Experiment.** Establish a baseline late-launch measurement on stock firmware.
Then introduce a benign, vendor-documented change (an added option ROM, a firmware
setting that alters the image) and re-measure.

**Confirm / refute.** If late-launch values are insensitive to pre-boot firmware
state, DRTM cannot attest "the enclave host's firmware is clean" and the vault must
not claim it does.

**Effort.** 3-5 days. This is the question that decides whether the enclave's trust
story is real or aspirational.

---

## H7. Is the BIOS region writable from the OS while DMA protection is enabled?

**Why documents cannot answer it.** The interaction between IOMMU/VT-d policy,
`SMM_BWP`, and the SPI controller's write path is configuration-dependent.

**Rig.** Bench board with VT-d, a test OS, and CHIPSEC.

**Experiment.** With DMA remapping enforced, attempt a lab-controlled BIOS-region
write from a kernel driver you control, and record which mechanism blocked it.

**Confirm / refute.** Determines whether "we enabled VT-d and HVCI" has any bearing
on firmware persistence. The expectation is that it does not; proving it matters
because the assumption is widespread.

**Effort.** 1 day.

---

## H8. What does an out-of-band SPI read-back actually recover on a live-ish board?

**Why documents cannot answer it.** In-circuit reads are affected by the PCH being
in a low-power state, by the flash chip's own protection bits, and by pin sharing.
The practical question for forensics is whether a clip read gives a byte-identical
image to a chip-off read.

**Rig.** Two identical boards, a clip programmer, a hot-air station, and a second
recovery path.

**Experiment.** Read board A in circuit; read board B chip-off; compare hashes per
region. Note any read that requires the board to be powered (which changes the
evidence handling rules).

**Confirm / refute.** Validates or invalidates the acquisition procedure in §7.2 as
an evidentiary method.

**Effort.** 1 day, moderate risk. This one has direct legal consequences if the
answer is "close but not identical".

---

## H9. Does the SPI descriptor ever under-declare the physical flash size?

**Why documents cannot answer it.** Some boards ship a flash part larger than the
descriptor's regions account for. That space is outside every region, unmeasured
by any region-based tool, and is a plausible hiding place. Whether it exists on a
given model is a hardware fact.

**Rig.** Bench board, programmer, chip datasheet, and the descriptor dump.

**Experiment.** Compare physical chip capacity (SFDP / part number) against the
declared regions and the BIOS region size. Compute the unexplained remainder, and
read it directly.

**Confirm / refute.** If unexplained space exists, every "region hash" based
detection in §7.3 has a blind spot, and the acquisition procedure must read the
whole chip, not just declared regions.

**Effort.** 2 hours. Cheap, and it closes a real blind spot.

---

## H10. Which Windows loader builds does the MoonBounce `OslArchTransferToKernel` patch survive on?

**Why documents cannot answer it.** The implant scans `0x158878` bytes for a
`retfq` tail at a fixed offset range. Whether that lands correctly depends on the
specific `winload.efi` build. The published report describes one victim.

**Rig.** Bench machine with virtualisation, a matrix of Windows builds (legal
images), and a debugger. No malware and no implant: the question is about the
*loader's* structure, not about infecting it.

**Experiment.** For each build, disassemble `winload.efi`, locate
`OslArchTransferToKernel`, record its offset and whether the tail is `48 CB`
(`retfq`), and compute the distance from a `call ExitBootServices` return address.

**Confirm / refute.** Bounds the affected population: if most post-2019 builds no
longer match, the implant is narrower than the "works on any Windows" framing
implies. Answers open question 2 in report §15 without touching a sample.

**Effort.** 2 days, and entirely safe: it analyses Microsoft binaries.

---

## H11. Do handle-protection semantics differ across Windows builds and EDR agents?

**Why documents cannot answer it.** `ObSetHandleAttributes` with
`ProtectFromClose`, and the resulting `ERROR_SHARING_VIOLATION` that Microsoft's
IR guidance uses as a detection, interact with kernel version and with whichever
security product is loaded.

**Rig.** Bench VMs across builds, plus the EDR agents in your estate. This is
hardware-adjacent: it needs real agent versions, not a clean lab.

**Experiment.** Reproduce the handle-protection pattern with your own benign test
driver, then attempt `certutil -hashfile` against the protected file under each
agent version, recording the error.

**Confirm / refute.** Validates or invalidates the hunt in §7.6. If agents change
the error code, the detection is silently 100% false-negative.

**Effort.** 2 days.

---

## H12. Does a vendor recovery path restore the ME region or only the BIOS region?

**Why documents cannot answer it.** "BIOS Flashback"/dual-BIOS recovery is
documented as user-facing behaviour, not as a region map. If it leaves the ME
region untouched, then a compromise there survives recovery, and the recovery
procedure in §8 is incomplete.

**Rig.** Bench board with a vendor recovery feature, programmer, and ME region
hashes from the stock image.

**Experiment.** Hash all regions; run the recovery feature; hash again; diff.

**Confirm / refute.** Determines whether "recovered by the vendor tool" can be
stated as eradication. On most platforms the honest answer will be "BIOS only".

**Effort.** 1 day.

---

## H13. What does the enclave's isolation look like against a DMA-capable attacker?

**Why documents cannot answer it.** IOMMU behaviour with a specific Thunderbolt or
PCIe device, in a specific BIOS configuration, with a specific OS, is empirical.
Every "the enclave is isolated" claim rests on it.

**Rig.** Enclave-class host, a DMA-capable device (a cheap PCIe attacker card or a
Thunderbolt device), and a benign memory-scraping test you write yourself.

**Experiment.** With IOMMU on and off, and with pre-boot DMA enabled and disabled,
attempt to read known memory from the host.

**Confirm / refute.** Produces the actual isolation boundary for zone 4, which the
architecture currently asserts rather than measures.

**Effort.** 2-3 days.

---

## H14. Do TPM sealing policies survive a firmware update, and should they?

**Why documents cannot answer it.** Sealing keys to PCR values is often proposed as
"keys unseal only on a known-good machine". What happens on a legitimate firmware
update is vendor- and policy-specific, and getting it wrong permanently destroys
access to the vault.

**Rig.** Bench machine with TPM, a disposable vault instance, and a firmware update
you are willing to apply.

**Experiment.** Seal a test key to a PCR policy; apply a signed vendor firmware
update; attempt to unseal. Record whether access is lost and which policy would
have survived.

**Confirm or refute.** Determines whether PCR sealing is a usable control for the
KEK or a scheduled outage waiting to happen.

**Effort.** 1 day, and it protects against a self-inflicted catastrophic loss.

---

## What this list implies

Three of these (H1, H4, H7) would change the report's conclusions if they came out
the other way. Two (H2, H9) would change the detection strategy. One (H14) is about
not destroying the archive you built.

None of them can be answered by reading more publications, which is precisely the
point: the current document is a reconstruction of what others have published, and
these are the places where the evidence runs out and the hardware has to speak.
