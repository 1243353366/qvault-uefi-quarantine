"""What feeds each detection: telemetry sources, and the hunting content built on them.

A detection without a named evidence source is an opinion. This module records, for every
mechanism in `persistence.py`, which telemetry would carry the evidence (Sysmon events,
Windows security events, EDR fields) and which published Sigma family covers the same
behaviour. Where no host-visible telemetry exists, it says so instead of leaving the row
blank.

Sources verified by reading them, not recalled:
- Sysmon event semantics from the Microsoft Sysinternals documentation.
- Sigma rule identifiers from the SigmaHQ repository, one real rule per family cited.
- ATT&CK v20 detection model, whose vocabulary is Detection Strategy / Analytics / Data
  Components (the older "Data Sources" framing no longer applies).
"""

from dataclasses import dataclass

from . import persistence as P


class TelemetryError(ValueError):
    """Raised when a mapping would claim evidence that no source can deliver."""


@dataclass(frozen=True)
class EvidenceSource:
    id: str
    product: str
    channel: str
    event_ids: tuple[str, ...]
    fields: tuple[str, ...]
    notes: str
    source_bib: str


SYSMON = "Microsoft-Windows-Sysmon/Operational"
SECURITY = "Security"
SYSTEM = "System"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"

SOURCES: dict[str, EvidenceSource] = {
    s.id: s for s in (
        EvidenceSource("sysmon_process", "Sysmon", SYSMON, ("1",),
                       ("Image", "CommandLine", "ParentImage", "User"),
                       "process creation with full command line, the base for ancestry signals",
                       "59"),
        EvidenceSource("sysmon_image_load", "Sysmon", SYSMON, ("7",),
                       ("ImageLoaded", "Signed", "Signature", "Image"),
                       "image load with signature state, which is how DLL shadowing shows up",
                       "59"),
        EvidenceSource("sysmon_file_create", "Sysmon", SYSMON, ("11",),
                       ("TargetFilename", "Image"),
                       "file creation, used for startup shortcuts and task files",
                       "59"),
        EvidenceSource("sysmon_registry_set", "Sysmon", SYSMON, ("13",),
                       ("TargetObject", "Details", "Image"),
                       "registry value set: the single most useful event for autostart keys",
                       "59"),
        EvidenceSource("sysmon_registry_key", "Sysmon", SYSMON, ("12", "14"),
                       ("TargetObject", "Image"),
                       "key create/delete and rename, for hives and key relocation",
                       "59"),
        EvidenceSource("sysmon_wmi", "Sysmon", SYSMON, ("19", "20", "21"),
                       ("Operation", "EventNamespace", "Name", "Destination"),
                       "WMI filter, consumer and binding registration: permanent subscriptions",
                       "59"),
        EvidenceSource("security_task", "Windows Security", SECURITY, ("4698", "4699", "4700", "4702"),
                       ("SubjectUserName", "TaskName", "TaskContent"),
                       "task creation and change with the XML body, including the hidden flag",
                       "60"),
        EvidenceSource("system_service", "Windows System", SYSTEM, ("7045",),
                       ("ServiceName", "ImagePath", "ServiceType", "AccountName"),
                       "service installation, the event that accompanies a new service binary",
                       "60"),
        EvidenceSource("security_process", "Windows Security", SECURITY, ("4688",),
                       ("NewProcessName", "CommandLine", "CreatorProcessName", "TokenElevationType"),
                       "process creation when Sysmon is not deployed, weaker but universal",
                       "60"),
        EvidenceSource("powershell_scriptblock", "PowerShell", POWERSHELL, ("4104",),
                       ("ScriptBlockText", "ScriptBlockId"),
                       "deobfuscated script text, which is what encoded command lines hide",
                       "61"),
        EvidenceSource("tpm_event_log", "TPM / firmware", "TCG log", (),
                       ("PCR", "Event type", "Digest"),
                       "measured boot log: the only evidence here that is not the OS's own account",
                       "62"),
    )
}

#: mechanism id -> evidence source ids. Every mechanism in the catalogue appears, including
#: the ones with no source, so a blank is a recorded decision rather than an omission.
MECHANISM_SOURCES: dict[str, tuple[str, ...]] = {
    "run_key": ("sysmon_registry_set",),
    "policies_run": ("sysmon_registry_set",),
    "startup_folder": ("sysmon_file_create", "sysmon_registry_set"),
    "scheduled_task": ("security_task", "sysmon_registry_set", "sysmon_file_create"),
    "service": ("system_service", "sysmon_registry_set", "sysmon_registry_key"),
    "boot_execute": ("sysmon_registry_set",),
    "hive_load": ("sysmon_registry_key", "sysmon_registry_set"),
    "bho": ("sysmon_registry_set",),
    "appinit_dll": ("sysmon_registry_set",),
    "dll_search_order": ("sysmon_image_load", "sysmon_file_create"),
    "ifeo": ("sysmon_registry_set",),
    # No host-visible telemetry exists for these three; see NO_TELEMETRY_REASON.
    "rootkit_hiding": (),
    "bootkit_boot": (),
    "fileless": ("sysmon_process", "powershell_scriptblock"),
}


@dataclass(frozen=True)
class SigmaFamily:
    mechanism: str
    title: str
    rule_id: str
    path: str
    logsource_category: str
    note: str


#: Real rules from SigmaHQ, read from the repository. These are hunting content, not
#: dependencies: a deployment may use different rules for the same behaviour.
SIGMA: tuple[SigmaFamily, ...] = (
    SigmaFamily("run_key", "Suspicious PowerShell In Registry Run Keys",
                "8d85cf08-bf97-4260-ba49-986a2a65129c",
                "rules/windows/registry/registry_set/registry_set_powershell_in_run_keys.yml",
                "registry_set", "matches a script host in a Run key, the shape QVault reports "
                               "as lolbin_proxy plus user_writable_location"),
    SigmaFamily("run_key", "Add Debugger Entry To AeDebug For Persistence",
                "092af964-4233-4373-b4ba-d86ea2890288",
                "rules/windows/registry/registry_set/registry_set_aedebug_persistence.yml",
                "registry_set", "Debugger-value persistence outside IFEO, which is why the "
                               "mechanism family is wider than one key"),
)

#: Mechanisms no telemetry source can carry, with where the answer does come from instead.
NO_TELEMETRY = {
    "rootkit_hiding": ("a rootkit conceals its own artefacts from the telemetry agent; only a "
                       "cross-view differential from outside the host can see it"),
    "bootkit_boot": ("the boot chain runs before any agent; the evidence is the measured boot "
                     "log and an out-of-band flash read"),
}

#: Mechanisms with telemetry, but no persistence artefact: the evidence is execution-time only.
EXECUTION_TIME_ONLY = {
    "fileless": ("no autostart artefact exists, so the trace is process ancestry and script "
                 "blocks at run time; a post-hoc snapshot cannot see it"),
}


def sources_for(mechanism: str) -> list[str]:
    if mechanism not in MECHANISM_SOURCES:
        raise TelemetryError(f"no telemetry mapping for mechanism {mechanism!r}")
    return list(MECHANISM_SOURCES[mechanism])


def sources(mechanism: str) -> list[EvidenceSource]:
    return [SOURCES[s] for s in sources_for(mechanism)]


def mechanisms_without_host_evidence() -> list[str]:
    return sorted(m for m, s in MECHANISM_SOURCES.items() if not s)


def blind_spots() -> list[dict]:
    """What the telemetry plane cannot tell you, stated per mechanism."""
    return [{"mechanism": m, "reason": r} for m, r in sorted(NO_TELEMETRY.items())]


def assert_complete() -> None:
    """Every mechanism mapped, every mapping resolvable, every claim falsifiable."""
    missing = sorted(set(P.MECHANISMS) - set(MECHANISM_SOURCES))
    if missing:
        raise TelemetryError(f"mechanisms with no telemetry mapping: {missing}")
    extra = sorted(set(MECHANISM_SOURCES) - set(P.MECHANISMS))
    if extra:
        raise TelemetryError(f"telemetry mapping names unknown mechanisms: {extra}")

    for mechanism, ids in MECHANISM_SOURCES.items():
        for source_id in ids:
            if source_id not in SOURCES:
                raise TelemetryError(f"{mechanism} cites unknown source {source_id!r}")
        if not ids and mechanism not in NO_TELEMETRY:
            raise TelemetryError(f"{mechanism} has no evidence and no stated reason")

    for source in SOURCES.values():
        for event_id in source.event_ids:
            if not event_id.isdigit():
                raise TelemetryError(f"{source.id}: event id {event_id!r} is not numeric")
        if not source.fields:
            raise TelemetryError(f"{source.id} names no fields to look at")
        if not source.source_bib.isdigit():
            raise TelemetryError(f"{source.id} has no bibliography reference")

    for rule in SIGMA:
        if len(rule.rule_id) != 36 or rule.rule_id.count("-") != 4:
            raise TelemetryError(f"sigma rule id {rule.rule_id!r} is not a UUID")
        if rule.mechanism not in MECHANISMS_KEYED:
            raise TelemetryError(f"sigma rule {rule.rule_id} names unknown mechanism")

    if set(NO_TELEMETRY) != set(mechanisms_without_host_evidence()):
        raise TelemetryError("NO_TELEMETRY and the empty mappings disagree")
    for mechanism in EXECUTION_TIME_ONLY:
        if not MECHANISM_SOURCES.get(mechanism):
            raise TelemetryError(f"{mechanism} is execution-time only but maps to no source")
        if mechanism in NO_TELEMETRY:
            raise TelemetryError(f"{mechanism} cannot be both invisible and execution-time only")


MECHANISMS_KEYED = set(P.MECHANISMS)

assert_complete()
