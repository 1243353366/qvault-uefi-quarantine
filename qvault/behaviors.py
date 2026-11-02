"""Attacker behaviour mapped to the control that answers it, with the gap named.

The rule here: model the mitigation on the behaviour, not on a payload. Each entry records
what the behaviour is in ATT&CK terms, what it leaves behind as evidence, which control in
this repository answers it, how complete that answer is, and what it still cannot do.

Coverage is stated as one of three values, and `absent` is a normal value:

- ``implemented``  the control exists and is tested in this repository
- ``partial``      the control exists but cannot close the behaviour alone
- ``absent``       nothing here answers it; the behaviour is out of this boundary

Every row resolves to a real module and symbol, and a test enforces that, so this cannot
become a document that describes code which no longer exists.
"""

import importlib
from dataclasses import dataclass

IMPLEMENTED = "implemented"
PARTIAL = "partial"
ABSENT = "absent"
COVERAGE_STATES = (IMPLEMENTED, PARTIAL, ABSENT)


class BehaviourError(ValueError):
    """Raised when a behaviour entry would not resolve or is malformed."""


@dataclass(frozen=True)
class Behaviour:
    id: str
    family: str
    attck: str
    technique: str
    evidence: str
    behaviour: str
    control: str
    module: str
    symbol: str
    coverage: str
    limit: str
    source_bib: str


def _b(**kwargs) -> Behaviour:
    entry = Behaviour(**kwargs)
    if entry.coverage not in COVERAGE_STATES:
        raise BehaviourError(f"{entry.id}: unknown coverage {entry.coverage!r}")
    if not entry.limit:
        raise BehaviourError(f"{entry.id}: a control without a stated limit is a claim")
    return entry


#: Sources: ATT&CK page numbers in the report bibliography (44-54), each verified by title.
BEHAVIOURS: tuple[Behaviour, ...] = (
    _b(id="autostart-run-keys", family="persistence",
       attck="T1547.001", technique="Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
       evidence="Run/RunOnce values, Policies\\Explorer\\Run, Shell Folders redirection, startup shortcuts",
       behaviour="register a payload to run at logon, under the user's own token or the machine's",
       control="persistence.run_key / startup_folder / policies_run: read the autostart set and "
               "compare against the golden image rather than alerting on key writes",
       module="qvault.persistence", symbol="assess", coverage=IMPLEMENTED,
       limit="an offline image read only; a live registry read is a self-report and grades nothing",
       source_bib="44"),
    _b(id="autostart-boot-execute", family="persistence",
       attck="T1547.001",
       technique="BootExecute value under Session Manager (folded into T1547.001)",
       evidence="multistring BootExecute contents",
       behaviour="add a program to the boot-time pre-session list so it runs before the shell",
       control="persistence.boot_execute: strict equality against 'autocheck autochk *', which "
               "catches a payload appended to the default",
       module="qvault.persistence", symbol="_boot_execute", coverage=IMPLEMENTED,
       limit="chkdsk legitimately adds temporary entries; detection is not attribution",
       source_bib="44"),
    _b(id="autostart-service", family="persistence",
       attck="T1543.003", technique="Create or Modify System Process: Windows Service",
       evidence="Services key ImagePath, svchost Parameters\\ServiceDll, RunServicesOnce",
       behaviour="install a service or swap a ServiceDll so the payload runs as SYSTEM",
       control="persistence.service: flag a binary or ServiceDll outside System32 and require a "
               "signature per service",
       module="qvault.persistence", symbol="_service", coverage=IMPLEMENTED,
       limit="a signed malicious service, or a legitimate binary with a malicious config, passes",
       source_bib="50"),
    _b(id="autostart-scheduled-task", family="persistence",
       attck="T1053.005", technique="Scheduled Task/Job: Scheduled Task",
       evidence="System32\\Tasks XML, TaskCache\\Tree values, hidden flag, principal",
       behaviour="schedule the payload as a task so it survives reboot and runs as SYSTEM",
       control="persistence.scheduled_task: hidden flag, SYSTEM principal, writable command",
       module="qvault.persistence", symbol="_generic", coverage=IMPLEMENTED,
       limit="the TaskCache tree is full of legitimate tasks; volume is not evidence",
       source_bib="51"),
    _b(id="autostart-appinit", family="persistence",
       attck="T1546.010", technique="Event Triggered Execution: AppInit DLLs",
       evidence="AppInit_DLLs value, LoadAppInit_DLLs flag",
       behaviour="inject a DLL into every user32 process by populating AppInit_DLLs",
       control="persistence.appinit_dll: a populated value is unexpected on modern Windows",
       module="qvault.persistence", symbol="_appinit", coverage=IMPLEMENTED,
       limit="only observes the value; a DLL already loaded into running processes is not seen",
       source_bib="49"),
    _b(id="autostart-ifeo", family="persistence",
       attck="T1546.012", technique="Event Triggered Execution: Image File Execution Options Injection",
       evidence="IFEO Debugger value for a target image",
       behaviour="redirect a trusted image to an attacker binary, or gain a SYSTEM shell via "
                 "accessibility binaries",
       control="persistence.ifeo: alert on a Debugger value outside Program Files or on any "
               "security-relevant image",
       module="qvault.persistence", symbol="_ifeo", coverage=IMPLEMENTED,
       limit="appcompat shims set Debugger legitimately, so a value alone is not malicious",
       source_bib="53"),
    _b(id="autostart-wmi-subscription", family="persistence",
       attck="T1546.003", technique="Event Triggered Execution: WMI Event Subscription",
       evidence="root\\subscription filters, consumers and filter-to-consumer bindings",
       behaviour="persist filelessly by binding a consumer to a WMI event filter",
       control="none in this repository",
       module="qvault.persistence", symbol="MECHANISMS", coverage=ABSENT,
       limit="an autostart snapshot does not read the WMI repository; this is a known gap and "
             "is listed as one rather than inferred away",
       source_bib="52"),
    _b(id="hijack-dll-search-order", family="execution-hijack",
       attck="T1574.001", technique="Hijack Execution Flow: DLL",
       evidence="same-named DLL in the application directory or a writable PATH entry",
       behaviour="place a DLL where an application looks before the legitimate copy",
       control="persistence.dll_search_order: writable-directory shadowing beside a signed binary",
       module="qvault.persistence", symbol="_dll_search_order", coverage=IMPLEMENTED,
       limit="needs the install manifest to distinguish a shipped DLL from a planted one",
       source_bib="47"),
    _b(id="hide-rootkit", family="stealth",
       attck="T1014", technique="Rootkit",
       evidence="absent from the snapshot by construction",
       behaviour="hide files, processes and registry keys from the host's own view",
       control="no detection; the control is an out-of-band reference comparison",
       module="qvault.persistence", symbol="MECHANISMS", coverage=PARTIAL,
       limit="anything a rootkit hides is missing from the snapshot that would report it, so "
             "this is a reference-comparison problem, not a scan",
       source_bib="48"),
    _b(id="persist-bootkit", family="pre-os", attck="T1542.003", technique="Pre-OS Boot: Bootkit",
       evidence="MBR, VBR, EFI system partition, boot service prologues",
       behaviour="execute before the OS so the OS reports a clean system",
       control="firmware_integrity: measured boot with a hardware anchor, plus an out-of-band "
               "flash read against a golden reference",
       module="qvault.firmware_integrity", symbol="grade_for", coverage=PARTIAL,
       limit="requires hardware measurement; without an anchor the claim stays HYPOTHESIS at "
             "any number of sources",
       source_bib="45"),
    _b(id="persist-system-firmware", family="pre-os", attck="T1542.001",
       technique="Pre-OS Boot: System Firmware",
       evidence="SPI flash contents, firmware volumes, NVRAM variables",
       behaviour="implant the firmware so the OS-level picture is irrelevant",
       control="firmware_integrity anchor classes with a grade ceiling per anchor type",
       module="qvault.firmware_integrity", symbol="grade_for", coverage=PARTIAL,
       limit="an OS-mediated firmware read is UNKNOWN by design; only an out-of-band read "
             "supports a claim",
       source_bib="46"),
    _b(id="anti-forensics", family="anti-forensics", attck="T1070", technique="Indicator Removal",
       evidence="missing or altered logs, timestamps, and artefacts",
       behaviour="delete or alter the record so the investigation cannot reconstruct events",
       control="the vault's custody chain: content hashes, provenance pins and an append-only "
               "claim that is reported honestly rather than assumed",
       module="qvault.separation", symbol="assert_custody_claim", coverage=PARTIAL,
       limit="protects evidence already collected; it cannot prove what was deleted before "
             "collection, and a local filesystem is not WORM",
       source_bib="54"),
    _b(id="fileless-execution", family="execution", attck="T1059.001",
       technique="Command and Scripting Interpreter: PowerShell (as a carrier)",
       evidence="none on disk; process ancestry and script blocks at run time",
       behaviour="run in memory from a script host so nothing persists to be scanned",
       control="nothing here; process telemetry is an execution-time control",
       module="qvault.persistence", symbol="MECHANISMS", coverage=ABSENT,
       limit="a post-hoc filesystem snapshot cannot recover what never touched disk",
       source_bib="55"),
    _b(id="exploit-kernel", family="exploitation", attck="T1068",
       technique="Exploitation for Privilege Escalation (kernel)",
       evidence="crash artefacts, patchguard events, driver load anomalies",
       behaviour="exploit a kernel bug to escape the user boundary",
       control="none: out of this boundary by design",
       module="qvault.separation", symbol="DUTIES", coverage=ABSENT,
       limit="QVault observes persistence and integrity, not exploitation; claiming kernel "
             "exploit coverage would be a category error",
       source_bib="57"),
    _b(id="exploit-browser-sandbox", family="exploitation", attck="T1068",
       technique="Exploitation for Privilege Escalation (browser sandbox)",
       evidence="renderer-to-broker escape, token manipulation",
       behaviour="escape the browser sandbox to reach the user's full token",
       control="none: out of this boundary by design",
       module="qvault.separation", symbol="DUTIES", coverage=ABSENT,
       limit="not observable from firmware, disk or autostart evidence",
       source_bib="57"),
    _b(id="token-theft", family="credential", attck="T1134",
       technique="Access Token Manipulation",
       evidence="token duplication, impersonation, privilege assignment events",
       behaviour="steal or duplicate an admin token and act as SYSTEM",
       control="netpolicy: an identity claim without an attested anchor is untrusted regardless "
               "of the token presented",
       module="qvault.netpolicy", symbol="authorize_all", coverage=PARTIAL,
       limit="policy refuses the consequence, not the theft; the token is already stolen by the "
             "time policy sees it",
       source_bib="56"),
    _b(id="chain-of-trust-bypass", family="pre-os", attck="T1553.006",
       technique="Subvert Trust Controls: Code Signing Policy Modification",
       evidence="Secure Boot state, db/dbx contents, revocation of the boot manager",
       behaviour="weaken or bypass Secure Boot so an unsigned boot chain loads",
       control="firmware_integrity anchor classes; reported as a declared class, not a verified "
               "one",
       module="qvault.firmware_integrity", symbol="ANCHORS", coverage=PARTIAL,
       limit="QVault records the anchor class and refuses to promote on it; it does not verify "
             "Secure Boot itself",
       source_bib="58"),
)


def resolve(entry: Behaviour) -> object:
    """Import the module and fetch the symbol. A broken reference is an error, not a note."""
    if entry.coverage == ABSENT and entry.module.endswith(".persistence"):
        pass                                  # the gap rows still must point at something real
    module = importlib.import_module(entry.module)
    if not hasattr(module, entry.symbol):
        raise BehaviourError(f"{entry.id}: {entry.module}.{entry.symbol} does not exist")
    return getattr(module, entry.symbol)


def assert_resolves() -> None:
    for entry in BEHAVIOURS:
        _validate_shape(entry)
        resolve(entry)


def _validate_shape(entry: Behaviour) -> None:
    if entry.id != entry.id.strip() or " " in entry.id:
        raise BehaviourError(f"behaviour id {entry.id!r} must be a bare slug")
    if not entry.attck.startswith("T") or not entry.attck[1:5].isdigit():
        raise BehaviourError(f"{entry.id}: {entry.attck!r} is not an ATT&CK technique id")
    if not entry.source_bib.isdigit():
        raise BehaviourError(f"{entry.id}: source must be a bibliography number")
    if entry.coverage not in COVERAGE_STATES:
        raise BehaviourError(f"{entry.id}: unknown coverage {entry.coverage!r}")


def by_family() -> dict[str, list[Behaviour]]:
    families: dict[str, list[Behaviour]] = {}
    for entry in BEHAVIOURS:
        families.setdefault(entry.family, []).append(entry)
    return {family: sorted(items, key=lambda b: b.id) for family, items in sorted(families.items())}


def gaps() -> list[dict]:
    """Everything not fully answered here, stated as such."""
    return [{"id": b.id, "coverage": b.coverage, "limit": b.limit}
            for b in BEHAVIOURS if b.coverage != IMPLEMENTED]


def summary() -> dict:
    counts: dict[str, int] = {}
    for entry in BEHAVIOURS:
        counts[entry.coverage] = counts.get(entry.coverage, 0) + 1
    return {"behaviours": len(BEHAVIOURS), "by_coverage": dict(sorted(counts.items())),
            "families": sorted(by_family())}


assert_resolves()
