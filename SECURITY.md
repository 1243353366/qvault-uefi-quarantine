# Security policy

This repository is a defensive forensics tool that **consumes hostile input by design**. It parses
firmware images, evidence stores and audit logs, and it never executes what it reads. No malware
samples are distributed here: the Project Zero dataset is metadata only, and the repository contains
zero `.efi`, `.bin`, `.rom` or `.fd` files.

Because the input is untrusted, the tool itself is an attack surface. That is the scope of this
policy.

## Reporting a vulnerability

Use **GitHub private vulnerability reporting** on this repository (Security → Report a vulnerability).
It opens a private advisory thread without needing an email address, and it is the only channel I
monitor.

There is **no bug bounty and no response SLA**. This is a prototype maintained by one person. I will
tell you what I actually did rather than promise a timeline, and I will credit you in the advisory
unless you ask me not to.

## In scope

- **Parsing hostile bytes**: unbounded allocation, quadratic or worse scanning, integer overflows in
  size fields, recursion on crafted nesting.
- **Evidence store**: path traversal, symlink following, TOCTOU between seal and read, permission
  bits that do not actually hold.
- **Audit chain**: forging or reordering entries without detection, truncation that reads as valid.
- **Key handling**: nonce reuse, key material in logs or `argv`, comparisons that leak through
  timing.
- **Denial behaviour**: a refusal that reveals whether a resource exists or a policy is set.
- **Availability**: an input that hangs or exhausts memory in a way a bounded reader should prevent.

## Out of scope

- The malware families discussed in the reports. They are not distributed here, and analysing them
  is not the purpose of this tool.
- Any claim that this software repairs, cleans or remediates infected firmware. It does not, and
  `report/ARCHITECTURAL_LIMITATIONS.md` says why at length.
- Findings that require the attacker to already control the host kernel. That is the documented host
  trust gap; it is a limit, not a bug.

## What is known and written down

The honest starting point for a reviewer: `report/TOOLING_RISK.md` lists every component that parses
untrusted input, the guard it has, and what that guard does not cover. `report/ARCHITECTURAL_LIMITATIONS.md`
lists the limits that no code change will close. `report/SECURITY_REPORT.md` grades the open findings.

Preferred disclosure window: 90 days, or sooner by agreement.
