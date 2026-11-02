# Published-source fingerprints and their defensive inversion

Generated from `qvault/fingerprints.py` by `tools/gen_fingerprints.py`. Do not edit by hand.

## What this is not

No LoJax, MoonBounce or BlackLotus sample was handled to produce this catalogue. Nothing in
this repository contains malware, and no entry below is primary-sourced. Each one comes from
published analysis, carries that source, and is graded accordingly. `assert_catalogue_integrity()`
**refuses** a `CONFIRMED` grade here, because a claim of primary analysis would be false.

## Why a string match is only a lead

The same bytes appear in a compromised firmware image, in an EDR rule, and in the notes of
anyone reading both. A textual match therefore caps at `INFERRED`, and every entry carries the
benign explanation that most often produces it. `LOJAX-1` is the clearest case: `rpcnetp` is
also the legitimate Absolute/Computrace anti-theft agent, so its presence is normal on a great
many OEM machines. Alerting on it without corroboration is the textbook false positive.

## The catalogue

### lojax

| id | kind | matched on | grade | benign reading to exclude | hostile when | countermeasure |
|---|---|---|---|---|---|---|
| `LOJAX-1` | artifact | `rpcnetp.exe` | CORROBORATED | Absolute/Computrace anti-theft agent, legitimately factory-installed by several OEMs | rpcnetp present while the OEM's Computrace option is disabled or the licence is inactive | Application allowlisting plus OEM confirmation that the Computrace agent is provisioned; detection alone is not actionable because the binary is often legitimate |
| `LOJAX-2` | registry | `Services/Rpcnetp` | CORROBORATED | the same anti-theft agent, installed by its vendor installer | service re-created shortly after removal, or created with a binary outside the vendor path | Monitor service creation for this name; treat re-creation after removal as the signal |
| `LOJAX-3` | structure | `module-absent-from-vendor-image` | INFERRED | a legitimate OEM firmware update that post-dates the reference image | the vendor confirms no such module, and the module's PE has no vendor signature | Out-of-band SPI read compared against a vendor-published reference, not an OS scan |

**Sources.**

- ESET, 'LoJax: First UEFI rootkit found in the wild, courtesy of the Sednit group' (2018)

### moonbounce

| id | kind | matched on | grade | benign reading to exclude | hostile when | countermeasure |
|---|---|---|---|---|---|---|
| `MOON-1` | structure | `unnamed-pe-section` | CORROBORATED | some legitimate DXE drivers ship sections with blank names | an unnamed section in CORE_DXE, or any module whose unnamed section is executable | Compare every DXE module against the vendor reference; an unnamed section that is new relative to the reference justifies re-imaging the SPI flash from a known-good dump |
| `MOON-2` | structure | `entry-point-outside-sections` | INFERRED | a packing or obfuscation tool, or a malformed image that will not boot | combined with an unnamed executable section and a boot that still succeeds | Re-image the firmware; a module whose entry point is not in any section cannot be trusted to be the module the vendor published |
| `MOON-3` | structure | `code-appended-after-last-section` | INFERRED | padding or alignment bytes written by a flashing tool | appended bytes that disassemble as code and are reachable from a patched prologue | Boot Guard or an equivalent hardware-anchored verification of the first stage, so a patched driver is refused at boot rather than observed afterwards |

**Sources.**

- Kaspersky GReAT, 'MoonBounce: the dark side of UEFI firmware' (2022)

### blacklotus

| id | kind | matched on | grade | benign reading to exclude | hostile when | countermeasure |
|---|---|---|---|---|---|---|
| `BL-1` | config | `hvci-disabled` | CORROBORATED | an administrator disabling memory integrity for driver compatibility, or a VM | HVCI off together with Defender off and BitLocker suspended on the same host | Re-enable HVCI; audit who changed it. The combination is the finding, not any one setting |
| `BL-2` | config | `defender-disabled` | CORROBORATED | a third-party AV product that takes over, or an enterprise policy | tamper protection disabled by something other than the management tool | Tamper protection plus a management-side baseline; a local change should be an alert |
| `BL-3` | config | `bitlocker-suspended` | CORROBORATED | a firmware update or an OS upgrade that suspends protection by design | suspended with no corresponding update event in the servicing log | Alert on suspension without a matching servicing event; re-seal the TPM afterwards |
| `BL-4` | config | `secure-boot-bypass-cve` | CORROBORATED | an unpatched machine that was never exploited | a bootloader version known-vulnerable in use after the dbx update was available | Apply the revocation list (dbx) update; verify Secure Boot state is on and dbx current rather than assuming it |
| `BL-5` | structure | `unexpected-efi-certificate` | INFERRED | a legitimate custom key enrolment by the device owner | a certificate in the firmware key store that no administrator can account for | Inventory db/MokList against a known set; require physical presence for enrolment |

**Sources.**

- ESET, 'BlackLotus UEFI bootkit: Myth confirmed' (2023)
- Microsoft MSRC, CVE-2022-21894 Secure Boot security feature bypass
- NSA/CISA BlackLotus remediation guidance (2023)


## Defensive inversion

For each mechanism the families use, the control that defeats it. This is the useful
direction: the mechanism is published, so the defence can be built without reproducing the
attack.

### lojax

| mechanism | control | implemented in |
|---|---|---|
| firmware written from the running OS | BIOS write protection, flash-descriptor lockdown and SMM_BWP; the write itself is the event to alert on | `containment, netpolicy` |
| implant persists across OS reinstall | out-of-band SPI read against a vendor reference; never accept an OS scan as firmware evidence | `firmware_integrity` |
| boot-chain trust bypassed by a vulnerable bootloader | apply dbx revocation, verify Secure Boot state instead of assuming it, and anchor measurement in hardware | `firmware_integrity` |
| platform defences disabled by the bootkit | tamper protection with a management-side baseline; alert on local change | `findings, pillars` |
| evidence of the compromise destroyed by the implant | seal evidence in the vault before analysis, so a hostile host cannot edit what was already captured | `provenance, crypto, store` |

### moonbounce

| mechanism | control | implemented in |
|---|---|---|
| firmware written from the running OS | BIOS write protection, flash-descriptor lockdown and SMM_BWP; the write itself is the event to alert on | `containment, netpolicy` |
| implant persists across OS reinstall | out-of-band SPI read against a vendor reference; never accept an OS scan as firmware evidence | `firmware_integrity` |
| boot-chain trust bypassed by a vulnerable bootloader | apply dbx revocation, verify Secure Boot state instead of assuming it, and anchor measurement in hardware | `firmware_integrity` |
| platform defences disabled by the bootkit | tamper protection with a management-side baseline; alert on local change | `findings, pillars` |
| evidence of the compromise destroyed by the implant | seal evidence in the vault before analysis, so a hostile host cannot edit what was already captured | `provenance, crypto, store` |

### blacklotus

| mechanism | control | implemented in |
|---|---|---|
| firmware written from the running OS | BIOS write protection, flash-descriptor lockdown and SMM_BWP; the write itself is the event to alert on | `containment, netpolicy` |
| implant persists across OS reinstall | out-of-band SPI read against a vendor reference; never accept an OS scan as firmware evidence | `firmware_integrity` |
| boot-chain trust bypassed by a vulnerable bootloader | apply dbx revocation, verify Secure Boot state instead of assuming it, and anchor measurement in hardware | `firmware_integrity` |
| platform defences disabled by the bootkit | tamper protection with a management-side baseline; alert on local change | `findings, pillars` |
| evidence of the compromise destroyed by the implant | seal evidence in the vault before analysis, so a hostile host cannot edit what was already captured | `provenance, crypto, store` |


## Detection discipline

- A lead is an `Observation`, never a `Finding`. `fingerprints.observations()` returns
  observations, and a human supplies the benign-explanation adjudication that promotes one.
- Hits never claim identification. Family attribution requires the two-independent-upstream
  rule from `limitations.intel_trust`.
- Firmware claims need out-of-band evidence: an unnamed section found by an OS-mediated read
  is a lead about a possibly-forged blob, not firmware integrity (see `firmware_integrity`).
