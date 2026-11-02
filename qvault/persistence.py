"""Autostart persistence as a mechanism-by-mechanism detection matrix.

Source: Daulaguphu, S. "11 Critical Malware Persistence Mechanisms You Should Be Familiar
With", tech-zealots.com, 7 April 2022 (bibliography 43).

Every mechanism in the source list becomes a descriptor: what it is, where it is seen, what
its benign twin is, what control removes it, and how to detect it. `assess()` then resolves
each descriptor to exactly one result class:

- ``detected``                 signals were found for this mechanism
- ``benign``                   present, no signals: consistent with its benign twin
- ``unknown_not_observable``   no snapshot can see it; the article lists it anyway
- ``not_observed``             observable, but this snapshot did not contain it

There is no CLEAN class, and ``CLEAN_STATES`` is empty on purpose. "not_observed" and
"unknown_not_observable" are different states and are never collapsed: one means we did not
look, the other means looking cannot work.

Read-only by construction: nothing here creates, modifies or enables an autostart entry.
"""

from dataclasses import dataclass
from typing import Callable

from . import findings as F
from . import grading as G
from . import separation as S

SOURCE = ("Daulaguphu, S. '11 Critical Malware Persistence Mechanisms You Should Be "
          "Familiar With', tech-zealots.com, 7 April 2022")

# --- result classes -------------------------------------------------------------------

DETECTED = "detected"
BENIGN = "benign"
UNKNOWN_NOT_OBSERVABLE = "unknown_not_observable"
NOT_OBSERVED = "not_observed"

RESULT_CLASSES = (DETECTED, BENIGN, UNKNOWN_NOT_OBSERVABLE, NOT_OBSERVED)

#: Deliberately empty. A persistence layer that can return CLEAN is a layer that has
#: confused "nothing found here" with "nothing here".
CLEAN_STATES: frozenset[str] = frozenset()

BOOT_EXECUTE_DEFAULT = "autocheck autochk *"

_HIVE_DEFAULT_ROOT = "system32\\config"


class PersistenceError(ValueError):
    """Raised when a snapshot or a descriptor is malformed."""


def assert_not_clean(state: str) -> str:
    """Guard for any code path that might invent a clean verdict for this layer."""
    if state in CLEAN_STATES or state.upper() == "CLEAN":
        raise PersistenceError(
            f"{state!r} is not a state this layer may report; autostart observation "
            f"cannot establish absence")
    return state


# --- snapshot model -------------------------------------------------------------------

@dataclass(frozen=True)
class AutostartEntry:
    """One artefact as observed. Described here, never created here."""

    mechanism: str
    name: str
    command: str = ""
    location: str = ""
    signed: bool | None = None
    hidden: bool = False


# --- signals --------------------------------------------------------------------------

@dataclass(frozen=True)
class Signal:
    id: str
    description: str
    benign: str
    control: str


SIGNALS: dict[str, Signal] = {
    "user_writable_location": Signal(
        "user_writable_location", "payload sits in a directory the user can write to",
        "installers run from Downloads; portable apps and updaters live in AppData",
        "alert on autostart execution from user-writable paths; keep software in "
        "Program Files"),
    "unsigned_binary": Signal(
        "unsigned_binary", "payload carries no valid signature",
        "in-house tools and fresh builds are unsigned by design",
        "require a signature for autostart registration; allowlist exceptions explicitly"),
    "lolbin_proxy": Signal(
        "lolbin_proxy", "a system binary launches on behalf of the entry",
        "some installers use rundll32 for a DLL entry point",
        "record the full command line for system-binary launches"),
    "encoded_command": Signal(
        "encoded_command", "command line carries an encoded blob",
        "deployment scripts occasionally encode arguments to survive quoting",
        "treat encoded autostart command lines as review-required; log decoded text"),
    "hidden_task": Signal(
        "hidden_task", "scheduled task is flagged hidden",
        "some vendor agents hide maintenance tasks from the console",
        "enumerate tasks by XML export, which surfaces the flag and principal"),
    "service_outside_system32": Signal(
        "service_outside_system32", "service binary or ServiceDll outside System32",
        "third-party services normally live under Program Files",
        "require signature and path for every service; alert on ServiceDll outside "
        "System32 in a shared svchost host"),
    "boot_execute_nonstandard": Signal(
        "boot_execute_nonstandard", "BootExecute is not the default value",
        "chkdsk and storage drivers schedule boot-time scans deliberately",
        "record the default per image and alert on any addition"),
    "hive_from_writable_path": Signal(
        "hive_from_writable_path", "a hive loads from outside System32\\config",
        "backup agents mount user hives for indexing",
        "alert on hivelist paths outside System32\\config"),
    "appinit_populated": Signal(
        "appinit_populated", "AppInit_DLLs is populated with loading enabled",
        "legacy accessibility and IME components used this mechanism",
        "treat as unexpected: it injects into every user32 process"),
    "dll_shadowing": Signal(
        "dll_shadowing", "same-named DLL sits ahead of the legitimate one",
        "portable apps ship their own DLLs beside the binary",
        "compare against the install manifest; prefer full-path or signed loading"),
    "ifeo_debugger": Signal(
        "ifeo_debugger", "an Image File Execution Options Debugger value redirects an image",
        "debuggers and application-compatibility shims set Debugger deliberately",
        "alert on Debugger values pointing outside Program Files, and on any value for a "
        "security-relevant image"),
}

_LOLBINS = ("rundll32", "regsvr32", "mshta", "powershell", "pwsh", "wscript", "cscript",
            "certutil", "msiexec")
_ENCODED_HINT = ("-enc", "-encodedcommand", "frombase64string")
_WRITABLE_HINTS = ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\users\\public\\",
                   "\\programdata\\", "%temp%", "%appdata%")


# --- detection predicates --------------------------------------------------------------
#
# A predicate is the mechanism's detection check. It is a function of one observed entry
# and returns the signal ids it found. Keeping them separate from the descriptor table is
# what makes "what it is" and "how we see it" reviewable in one place.

def _generic(entry: AutostartEntry) -> tuple[str, ...]:
    found: list[str] = []
    text = f"{entry.command} {entry.location}".lower()
    if any(hint in text for hint in _WRITABLE_HINTS):
        found.append("user_writable_location")
    if entry.signed is False:
        found.append("unsigned_binary")
    if any(b in entry.command.lower() for b in _LOLBINS):
        found.append("lolbin_proxy")
    if any(hint in entry.command.lower() for hint in _ENCODED_HINT):
        found.append("encoded_command")
    if entry.hidden:
        found.append("hidden_task")
    return tuple(found)


def _service(entry: AutostartEntry) -> tuple[str, ...]:
    found = list(_generic(entry))
    if entry.command and "system32" not in entry.command.lower():
        found.append("service_outside_system32")
    return tuple(found)


def _boot_execute(entry: AutostartEntry) -> tuple[str, ...]:
    """Exact comparison, after whitespace normalisation.

    A payload appended to the default keeps the default as a substring, so a containment
    test passes it. Equality is what "has any value beyond the default" means.
    """
    normalised = " ".join(entry.command.lower().split())
    return ("boot_execute_nonstandard",) if normalised != BOOT_EXECUTE_DEFAULT else ()


def _hive(entry: AutostartEntry) -> tuple[str, ...]:
    found = list(_generic(entry))
    if _HIVE_DEFAULT_ROOT not in f"{entry.location} {entry.command}".lower():
        found.append("hive_from_writable_path")
    return tuple(found)


def _appinit(entry: AutostartEntry) -> tuple[str, ...]:
    found = list(_generic(entry))
    if entry.command.strip():
        found.append("appinit_populated")
    return tuple(found)


def _ifeo(entry: AutostartEntry) -> tuple[str, ...]:
    """T1546.012: the Debugger value is what redirects the image, so it is the signal."""
    found = list(_generic(entry))
    if entry.command.strip() or "debugger" in f"{entry.location} {entry.command}".lower():
        found.append("ifeo_debugger")
    return tuple(found)


def _dll_search_order(entry: AutostartEntry) -> tuple[str, ...]:
    found = list(_generic(entry))
    if any(hint in f"{entry.command} {entry.location}".lower() for hint in _WRITABLE_HINTS):
        found.append("dll_shadowing")
    return tuple(found)


# --- mechanism descriptors --------------------------------------------------------------

@dataclass(frozen=True)
class Mechanism:
    id: str
    name: str
    observable_path: str
    benign_default: str
    control: str
    predicate: Callable[[AutostartEntry], tuple[str, ...]] | None
    observable: bool = True


def _m(*args, **kwargs) -> Mechanism:
    mech = Mechanism(*args, **kwargs)
    if mech.observable and mech.predicate is None:
        raise PersistenceError(f"mechanism {mech.id} is observable but has no predicate")
    if not mech.observable and mech.predicate is not None:
        raise PersistenceError(f"mechanism {mech.id} is not observable but has a predicate")
    return mech


_NOTHING_VISIBLE = "not observable from an autostart snapshot"
_NOT_APPLICABLE = "n/a: no autostart artefact exists to compare against"

MECHANISMS: dict[str, Mechanism] = {
    m.id: m for m in (
        _m("run_key", "Registry Run / RunOnce keys",
           "HKCU|HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run(Once)",
           "installers and updaters register here; signed vendor paths are the normal case",
           "compare against the golden image's autostart set and alert on new entries in a "
           "user-writable path, not on the key being written at all", _generic),
        _m("policies_run", "Policies\\Explorer\\Run",
           "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
           "group policy login scripts populate this key by design",
           "diff against the domain's declared policy; an entry with no matching GPO is "
           "the finding", _generic),
        _m("startup_folder", "Startup folders / Shell Folders redirection",
           "Start Menu\\Programs\\Startup; Explorer\\Shell Folders and User Shell Folders",
           "vendors ship startup shortcuts; users add their own",
           "treat a Shell Folders value pointing at a user-writable directory as the "
           "signal, since it relocates every startup shortcut", _generic),
        _m("scheduled_task", "Scheduled tasks",
           "C:\\Windows\\System32\\Tasks; Schedule\\TaskCache\\Tree",
           "Windows and most agents schedule maintenance tasks",
           "review for hidden flag, SYSTEM principal and a writable command; export task "
           "XML rather than reading the cache alone", _generic),
        _m("service", "Services and ServiceDll",
           "CurrentControlSet\\Services; svchost Parameters\\ServiceDll",
           "every driver and most agents are services; ServiceDll is how svchost works",
           "require signature and path per service; a ServiceDll outside System32 in a "
           "shared svchost host is the anomaly", _service),
        _m("boot_execute", "BootExecute (Session Manager)",
           "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute",
           "the default is exactly 'autocheck autochk *'; chkdsk schedules add entries "
           "legitimately and temporarily",
           "record the default per image and alert on any addition; boot-time changes are "
           "invisible to the running OS if malicious", _boot_execute),
        _m("hive_load", "Hive loading at boot (smss.exe)",
           "HKLM\\SYSTEM\\CurrentControlSet\\Control\\hivelist",
           "this key describes where hives live for every normal install",
           "alert on a hive path outside System32\\config, which is how a rogue hive loads "
           "before the shell exists", _hive),
        _m("bho", "Browser Helper Objects",
           "Explorer\\Browser Helper Objects",
           "toolbars and accessibility add-ons register BHOs deliberately",
           "enumerate BHO CLSIDs to InprocServer32 and require a valid signature", _generic),
        _m("appinit_dll", "AppInit_DLLs",
           "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
           "the key exists on every system and is empty; LoadAppInit_DLLs is 0",
           "treat a populated value with loading enabled as unexpected; modern Windows "
           "ships this disabled", _appinit),
        _m("dll_search_order", "DLL search order hijacking",
           "application directory; PATH; %TEMP%; current working directory",
           "portable applications ship their own DLLs beside the binary",
           "compare a signed binary's imports against its install manifest; a same-named "
           "DLL in a writable directory is the finding", _dll_search_order),
        _m("ifeo", "Image File Execution Options Debugger",
           "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution "
           "Options\\<image>\\Debugger",
           "debuggers and appcompat shims set Debugger on purpose; the key is not hostile "
           "by itself",
           "alert on a Debugger value outside Program Files and on any value set for a "
           "security-relevant image", _ifeo),
        _m("rootkit_hiding", "Rootkit hiding", _NOTHING_VISIBLE, _NOT_APPLICABLE,
           "out-of-band comparison: an offline image read or memory acquisition against a "
           "golden reference, since what a rootkit hides is absent from the snapshot that "
           "would report it", None, observable=False),
        _m("bootkit_boot", "Bootkit in MBR / bootloader", _NOTHING_VISIBLE, _NOT_APPLICABLE,
           "measured boot with a hardware anchor plus an out-of-band read of the boot "
           "chain; see qvault/firmware_integrity.py", None, observable=False),
        _m("fileless", "Fileless execution", _NOTHING_VISIBLE, _NOT_APPLICABLE,
           "process ancestry and script-block telemetry at execution time; a post-hoc "
           "filesystem snapshot cannot recover what never touched disk", None,
           observable=False),
    )
}


def assert_catalogue_integrity() -> None:
    """Every descriptor is complete, and result classes contain no clean verdict."""
    for mechanism in MECHANISMS.values():
        for field_name in ("id", "name", "observable_path", "benign_default", "control"):
            if not getattr(mechanism, field_name):
                raise PersistenceError(f"mechanism {mechanism.id} has no {field_name}")
        if mechanism.id != mechanism.id.strip():
            raise PersistenceError(f"mechanism id {mechanism.id!r} has whitespace")
    for state in RESULT_CLASSES:
        assert_not_clean(state)
    if RESULT_CLASSES.count(NOT_OBSERVED) != 1:
        raise PersistenceError("not_observed must be exactly one state")
    for key, signal in SIGNALS.items():
        if not (signal.benign and signal.control):
            raise PersistenceError(f"signal {key} lacks a benign reading or a control")


assert_catalogue_integrity()


# --- assessment -----------------------------------------------------------------------

def _group(entries) -> dict[str, list[AutostartEntry]]:
    grouped: dict[str, list[AutostartEntry]] = {}
    for entry in entries:
        if entry.mechanism not in MECHANISMS:
            # Coarse: the error names what was asked for, never what exists.
            raise PersistenceError("unknown mechanism requested")
        grouped.setdefault(entry.mechanism, []).append(entry)
    return grouped


def assess(entries, *, basis: str = "synthetic", attestation_state: str = "absent",
           scope: str = S.SYNTHETIC, isolated: bool = False,
           attested: bool = False) -> dict:
    """Resolve every mechanism to one result class. One row per mechanism, always."""
    S.assert_scope(scope, isolated=isolated, attested=attested)
    limit = G.ceiling(basis, attestation_state)      # validates basis and state
    grouped = _group(entries)

    matrix = []
    for mechanism in sorted(MECHANISMS.values(), key=lambda m: m.id):
        row = {
            "mechanism": mechanism.id,
            "name": mechanism.name,
            "observable": mechanism.observable,
            "benign_default": mechanism.benign_default,
            "control": mechanism.control,
        }
        if not mechanism.observable:
            row.update({
                "result": UNKNOWN_NOT_OBSERVABLE, "grade": F.UNKNOWN, "signals": [],
                "entries": len(grouped.get(mechanism.id, [])),
                "benign_readings": [mechanism.benign_default],
                "statement": (f"{mechanism.name} leaves no autostart artefact; this "
                              f"snapshot cannot confirm or exclude it"),
            })
            matrix.append(row)
            continue

        seen = grouped.get(mechanism.id, [])
        if not seen:
            row.update({
                "result": NOT_OBSERVED, "grade": F.UNKNOWN, "signals": [], "entries": 0,
                "benign_readings": [mechanism.benign_default],
                "statement": ("this snapshot contained no entry for this mechanism; that "
                              "is not evidence it is absent"),
            })
            matrix.append(row)
            continue

        signals = sorted({s for entry in seen for s in mechanism.predicate(entry)})
        detail = G.explain(basis=basis, signal_count=len(signals),
                           attestation_state=attestation_state)
        row.update({
            "result": DETECTED if signals else BENIGN,
            "grade": detail["grade"],
            "signals": signals,
            "entries": len(seen),
            "statement": (detail["reason"] if signals else
                          "present with no anomaly signals; consistent with its benign twin"),
            "benign_readings": [SIGNALS[s].benign for s in signals] or
                               [mechanism.benign_default],
        })
        matrix.append(row)

    return {
        "basis": basis,
        "attestation_state": attestation_state,
        "ceiling": limit,
        "matrix": matrix,
        "coverage": coverage(grouped.keys()),
        "result_classes": RESULT_CLASSES,
        "clean_state_available": False,
    }


def coverage(seen) -> dict:
    """Three states, never collapsed: observed, not observed, not observable."""
    seen = set(seen)
    return {
        "observed": sorted(m for m, d in MECHANISMS.items() if d.observable and m in seen),
        "not_observed": sorted(m for m, d in MECHANISMS.items()
                               if d.observable and m not in seen),
        "not_observable": sorted(m for m, d in MECHANISMS.items() if not d.observable),
        "statement": ("a mechanism that was not observed was not thereby shown to be "
                      "absent; only the locations actually read are covered"),
    }


def summarise(result: dict) -> dict:
    by_result: dict[str, int] = {}
    by_grade: dict[str, int] = {}
    for row in result["matrix"]:
        by_result[row["result"]] = by_result.get(row["result"], 0) + 1
        by_grade[row["grade"]] = by_grade.get(row["grade"], 0) + 1
    return {
        "basis": result["basis"],
        "attestation_state": result["attestation_state"],
        "ceiling": result["ceiling"],
        "by_result": dict(sorted(by_result.items())),
        "by_grade": dict(sorted(by_grade.items())),
        "mechanisms": len(result["matrix"]),
        "clean_state_available": result["clean_state_available"],
    }
