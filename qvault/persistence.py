"""Windows autostart surface: what an ASEP snapshot shows, and what it cannot.

Source: Daulaguphu, S. "11 Critical Malware Persistence Mechanisms You Should Be Familiar
With", tech-zealots.com, 7 April 2022.

This module is read-only by construction. It contains no code that creates, modifies or
enables an autostart entry; it takes a declarative snapshot and reports what the snapshot
shows, what each finding could benignly be, and which control removes the mechanism. The
defensive inversion of "write to Run" is "read Run and know what belongs there", which is
what this file does.

Three of the eleven mechanisms are marked not observable from a snapshot at all. Saying so
is the point: a rootkit, a bootkit and fileless code are listed in the source article and a
registry read cannot see any of them, so reporting "no entry found" for those would be a
false clean.
"""

import re
from dataclasses import dataclass, field

from . import findings as F
from . import separation as S

SOURCE = ("Daulaguphu, S. '11 Critical Malware Persistence Mechanisms You Should Be "
          "Familiar With', tech-zealots.com, 7 April 2022")

# --- mechanisms ----------------------------------------------------------------------

MECHANISMS: dict[str, dict] = {
    "run_key": {
        "title": "Registry Run / RunOnce keys",
        "location": "HKCU|HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run(Once)",
        "observable": True,
        "benign": "installers and updaters legitimately register here; signed vendor paths "
                  "under Program Files are the normal case",
        "control": "compare against the golden image's autostart set; alert on new entries "
                   "in a user-writable path rather than on the key being written at all",
    },
    "policies_run": {
        "title": "Policies\\Explorer\\Run",
        "location": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        "observable": True,
        "benign": "group policy login scripts can populate this key by design",
        "control": "diff against the domain's declared policy; an entry here with no "
                   "matching GPO is the finding, not the key's mere use",
    },
    "startup_folder": {
        "title": "Startup folders / Shell Folders redirection",
        "location": "Start Menu\\Programs\\Startup; Explorer\\Shell Folders and "
                    "User Shell Folders",
        "observable": True,
        "benign": "vendors ship startup shortcuts; users add their own",
        "control": "treat a Shell Folders value pointing at a user-writable directory as "
                   "the signal, since it relocates every startup shortcut",
    },
    "scheduled_task": {
        "title": "Scheduled tasks",
        "location": "C:\\Windows\\System32\\Tasks; "
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree",
        "observable": True,
        "benign": "Windows and most agents schedule maintenance tasks; the TaskCache tree "
                  "is full of legitimate entries on any normal system",
        "control": "review for hidden flag, SYSTEM principal, and a command in a "
                   "user-writable path; export task XML rather than reading the cache alone",
    },
    "service": {
        "title": "Services and ServiceDll",
        "location": "HKLM\\SYSTEM\\CurrentControlSet\\Services; svchost Parameters\\ServiceDll; "
                    "RunServicesOnce / Run\\Services",
        "observable": True,
        "benign": "every driver and most agents are services; ServiceDll is the normal "
                  "svchost mechanism, not a trick in itself",
        "control": "check ImagePath and ServiceDll against signed vendor paths; a ServiceDll "
                   "outside System32 under a shared svchost group is the anomaly",
    },
    "boot_execute": {
        "title": "BootExecute (Session Manager)",
        "location": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute",
        "observable": True,
        "benign": "the default is exactly 'autocheck autochk *'; chkdsk schedules can add "
                  "entries legitimately and temporarily",
        "control": "record the default and alert on any addition; require a maintenance "
                   "ticket for a non-default value because normal operation never needs one",
    },
    "hive_load": {
        "title": "Hive loading at boot (smss.exe)",
        "location": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\hivelist",
        "observable": True,
        "benign": "this key describes where hives live for every normal install",
        "control": "alert on a hive path outside System32\\config, which is how a rogue hive "
                   "gets loaded before the shell exists",
    },
    "bho": {
        "title": "Browser Helper Objects",
        "location": "HKLM|HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\"
                    "Browser Helper Objects",
        "observable": True,
        "benign": "toolbars and accessibility add-ons register BHOs deliberately",
        "control": "enumerate BHO CLSIDs to their InprocServer32 path and require a valid "
                   "signature; the mechanism is legacy, so new BHOs are rare and notable",
    },
    "appinit_dll": {
        "title": "AppInit_DLLs",
        "location": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
        "observable": True,
        "benign": "the key exists on every system and is empty; LoadAppInit_DLLs is 0",
        "control": "treat any populated value with LoadAppInit_DLLs=1 as unexpected; modern "
                   "Windows ships with this disabled by default",
    },
    "dll_search_order": {
        "title": "DLL search order hijacking",
        "location": "application directory; PATH; %TEMP%; current working directory",
        "observable": True,
        "benign": "portable applications legitimately ship their own DLLs beside the binary",
        "control": "compare each signed binary's imported DLLs against its install manifest; "
                   "a same-named DLL in a writable directory beside a signed EXE is the finding",
    },
    "rootkit_hiding": {
        "title": "Rootkit hiding",
        "location": "kernel; no registry location",
        "observable": False,
        "benign": "n/a: not observable from an autostart snapshot",
        "control": "out-of-band comparison: an offline image read or memory acquisition "
                   "against a golden reference, since anything a rootkit hides is absent "
                   "from the very snapshot that would report it",
    },
    "bootkit_boot": {
        "title": "Bootkit in MBR / bootloader",
        "location": "MBR, VBR, EFI system partition",
        "observable": False,
        "benign": "n/a: not observable from an autostart snapshot",
        "control": "measured boot with a hardware anchor, plus an out-of-band read of the "
                   "boot chain; see qvault/firmware_integrity.py",
    },
    "fileless": {
        "title": "Fileless execution",
        "location": "memory only; script host or macro entry point",
        "observable": False,
        "benign": "n/a: no autostart artefact by definition",
        "control": "process ancestry and script-block telemetry at execution time; a "
                   "post-hoc filesystem snapshot cannot recover what never touched disk",
    },
}

# --- signals -------------------------------------------------------------------------

@dataclass(frozen=True)
class Signal:
    id: str
    description: str
    benign: str
    control: str


SIGNALS: dict[str, Signal] = {
    "user_writable_location": Signal(
        "user_writable_location",
        "the payload sits in a directory the user can write to",
        "installers run from Downloads; portable apps and updaters live in AppData",
        "alert on execution from user-writable paths for autostart entries, and keep "
        "software in Program Files"),
    "unsigned_binary": Signal(
        "unsigned_binary",
        "the payload carries no valid signature",
        "in-house tools and freshly compiled binaries are unsigned by design",
        "require a signature for anything registered as an autostart entry; allowlist the "
        "exceptions explicitly rather than tolerating unsigned by default"),
    "lolbin_proxy": Signal(
        "lolbin_proxy",
        "the entry launches a system binary rather than the payload directly",
        "some legitimate installers use rundll32 for DLL entry points",
        "record the full command line for system-binary launches; a proxy with a "
        "user-writable argument is the finding"),
    "encoded_command": Signal(
        "encoded_command",
        "the command line carries an encoded or obfuscated blob",
        "rare legitimate deployment scripts encode arguments to survive quoting",
        "treat encoded autostart command lines as requiring review; log the decoded text "
        "rather than the blob"),
    "hidden_task": Signal(
        "hidden_task",
        "the scheduled task is flagged hidden",
        "some vendor agents hide their maintenance tasks from the console",
        "enumerate tasks by XML export, which surfaces the hidden flag and the principal"),
    "service_outside_system32": Signal(
        "service_outside_system32",
        "a service binary or ServiceDll sits outside System32",
        "third-party services are normally under Program Files",
        "require signature and path for every service; alert when a shared svchost host "
        "loads a ServiceDll from outside System32"),
    "boot_execute_nonstandard": Signal(
        "boot_execute_nonstandard",
        "BootExecute carries an entry beyond the default",
        "chkdsk and some storage drivers schedule boot-time scans deliberately",
        "record the default value per image and alert on any addition; a boot-time "
        "modification is invisible to the running OS if it is malicious"),
    "hive_from_writable_path": Signal(
        "hive_from_writable_path",
        "a hive is loaded from outside System32\\config",
        "some backup agents mount user hives for indexing",
        "alert on hivelist paths outside System32\\config; a rogue hive loads before the "
        "shell exists"),
    "appinit_populated": Signal(
        "appinit_populated",
        "AppInit_DLLs is populated with loading enabled",
        "legacy accessibility and IME components used this mechanism",
        "treat as unexpected on modern Windows; it injects into every user32 process"),
    "dll_shadowing": Signal(
        "dll_shadowing",
        "a same-named DLL sits in a writable directory ahead of the legitimate one",
        "portable apps ship their own DLLs next to the binary",
        "compare against the install manifest and prefer full-path or signed DLL loading"),
}

# --- snapshot model ------------------------------------------------------------------

#: What each collection basis is worth. Reading a live host through itself is a self
#: report: it cannot support a graded persistence finding, which is the host trust gap
#: applied here rather than restated.
BASIS_CLASSES: dict[str, tuple[str, ...]] = {
    "synthetic": (S.SELF_REPORT,),
    "live_host": (S.SELF_REPORT,),
    "offline_image": (S.INDEPENDENT_MEASUREMENT,),
    "attested_image": (S.INDEPENDENT_MEASUREMENT, S.HARDWARE_ANCHOR),
}


class PersistenceError(ValueError):
    """Raised when a snapshot or a catalogue entry is malformed."""


@dataclass(frozen=True)
class AutostartEntry:
    """One autostart artefact as observed. Never created here, only described."""

    mechanism: str
    name: str
    command: str = ""
    location: str = ""
    signed: bool | None = None
    hidden: bool = False


_USER_WRITABLE = re.compile(
    r"(\\AppData\\|\\Temp\\|\\Downloads\\|\\Users\\Public\\|\\ProgramData\\|"
    r"\\Windows\\Temp\\|%temp%|%appdata%)", re.IGNORECASE)
#: The only normal value. An extra entry appended to it still contains the default text,
#: so the check is equality after whitespace normalisation, not a substring test.
BOOT_EXECUTE_DEFAULT = "autocheck autochk *"

_LOLBINS = ("rundll32", "regsvr32", "mshta", "powershell", "pwsh", "wscript", "cscript",
            "certutil", "msiexec", "cmd.exe")
_ENCODED = re.compile(r"(-enc(odedcommand)?\b|-e\s+[A-Za-z0-9+/=]{40,}|\bfrombase64string)", re.IGNORECASE)


def _signals_for(entry: AutostartEntry) -> list[str]:
    found: list[str] = []
    command = entry.command or ""
    if _USER_WRITABLE.search(command) or _USER_WRITABLE.search(entry.location or ""):
        found.append("user_writable_location")
    if entry.signed is False:
        found.append("unsigned_binary")
    if any(bin_name in command.lower() for bin_name in _LOLBINS):
        found.append("lolbin_proxy")
    if _ENCODED.search(command):
        found.append("encoded_command")
    if entry.hidden:
        found.append("hidden_task")
    if entry.mechanism == "service" and command and "system32" not in command.lower():
        found.append("service_outside_system32")
    if entry.mechanism == "boot_execute":
        if " ".join(command.lower().split()) != BOOT_EXECUTE_DEFAULT:
            found.append("boot_execute_nonstandard")
    if entry.mechanism == "hive_load" and "system32\\config" not in (entry.location or "").lower():
        found.append("hive_from_writable_path")
    if entry.mechanism == "appinit_dll" and command.strip():
        found.append("appinit_populated")
    return found


def _ceiling_for(basis: str | tuple[str, ...]) -> str | None:
    classes = BASIS_CLASSES[basis] if isinstance(basis, str) else tuple(basis)
    return S.grade_ceiling(classes)


def assess(entries, *, basis: str = "synthetic",
           scope: str = S.SYNTHETIC, isolated: bool = False,
           attested: bool = False) -> dict:
    """Grade the observable footprint of each entry, and state the coverage honestly."""
    if basis not in BASIS_CLASSES:
        raise PersistenceError(f"unknown basis {basis!r}; known: {sorted(BASIS_CLASSES)}")
    S.assert_scope(scope, isolated=isolated, attested=attested)

    ceiling = _ceiling_for(basis)
    observations, seen = [], set()

    for entry in entries:
        if entry.mechanism not in MECHANISMS:
            raise PersistenceError(f"unknown mechanism {entry.mechanism!r}")
        meta = MECHANISMS[entry.mechanism]
        seen.add(entry.mechanism)

        if not meta["observable"]:
            observations.append({
                "mechanism": entry.mechanism, "name": entry.name, "grade": F.UNKNOWN,
                "signals": [], "observable": False,
                "statement": (
                    f"{meta['title']} is not observable from an autostart snapshot; this "
                    f"entry cannot be confirmed or excluded here"),
                "benign": meta["benign"], "control": meta["control"],
            })
            continue

        signals = _signals_for(entry)
        if not signals:
            grade = F.UNKNOWN
            statement = ("no anomaly signals; this is consistent with legitimate software "
                         "and is not evidence of anything")
        else:
            proposed = F.HYPOTHESIS if len(signals) == 1 else F.INFERRED
            if ceiling is None:
                grade = F.UNKNOWN
                statement = (
                    f"{len(signals)} signal(s) seen, but a {basis} read cannot support a "
                    f"persistence finding: the subject reported its own state")
            else:
                grade = S.cap_grade(proposed, ceiling)
                statement = (f"{len(signals)} signal(s) under a {basis} basis "
                             f"(ceiling {ceiling})")

        observations.append({
            "mechanism": entry.mechanism, "name": entry.name, "grade": grade,
            "signals": signals, "observable": True, "statement": statement,
            "benign": [SIGNALS[s].benign for s in signals] or [meta["benign"]],
            "hostile_when": ("weighed together with an out-of-band reference: signals "
                             "alone describe a shape, not an actor"),
            "control": meta["control"],
        })

    return {
        "basis": basis,
        "ceiling": ceiling,
        "observations": sorted(observations, key=lambda o: (o["mechanism"], o["name"])),
        "coverage": coverage(seen),
    }


def coverage(seen: set[str]) -> dict:
    """What this snapshot did and did not look at. Absence is never reported as clean."""
    return {
        "observed": sorted(m for m in MECHANISMS if m in seen),
        "not_observed": sorted(m for m, v in MECHANISMS.items()
                               if v["observable"] and m not in seen),
        "not_observable": sorted(m for m, v in MECHANISMS.items() if not v["observable"]),
        "statement": ("a mechanism that was not observed was not thereby shown to be "
                      "absent; only the locations actually read are covered"),
    }


def summarise(result: dict) -> dict:
    grades: dict[str, int] = {}
    for observation in result["observations"]:
        grades[observation["grade"]] = grades.get(observation["grade"], 0) + 1
    return {
        "basis": result["basis"], "ceiling": result["ceiling"],
        "by_grade": dict(sorted(grades.items())),
        "entries": len(result["observations"]),
        "never_claim_clean": True,
    }


def assert_catalogue_integrity() -> None:
    """Every mechanism states a source-derived control and a benign twin, or it is out."""
    for key, meta in MECHANISMS.items():
        for required in ("title", "location", "observable", "benign", "control"):
            if required not in meta:
                raise PersistenceError(f"mechanism {key} is missing {required}")
        if meta["observable"] and not meta["benign"]:
            raise PersistenceError(f"mechanism {key} has no benign explanation")
    for key, signal in SIGNALS.items():
        if not (signal.benign and signal.control):
            raise PersistenceError(f"signal {key} lacks a benign reading or a control")


assert_catalogue_integrity()
