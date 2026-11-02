# Autostart surface: what a snapshot shows

Source: Daulaguphu, S. "11 Critical Malware Persistence Mechanisms You Should Be Familiar
With", tech-zealots.com, 7 April 2022.

`qvault/persistence.py` implements the article's mechanisms as *detection*. It contains no
code that creates, modifies or enables an autostart entry. The defensive inversion of each
technique is "read the location, know what belongs there, alert on the difference", and
that is what the module does.

## The eleven mechanisms

| Mechanism | Where it lives | Signal we look for |
|-----------|----------------|--------------------|
| Run / RunOnce keys | `...\CurrentVersion\Run(Once)` | payload in a user-writable path, unsigned |
| Policies\Explorer\Run | `...\Policies\Explorer\Run` | entry with no matching GPO |
| Startup folders | Start Menu Startup; Shell Folders | Shell Folders pointing at a writable directory |
| Scheduled tasks | `System32\Tasks`, `TaskCache\Tree` | hidden flag, SYSTEM principal, writable payload |
| Services / ServiceDll | `CurrentControlSet\Services` | binary or ServiceDll outside System32 |
| BootExecute | `Session Manager\BootExecute` | any value other than `autocheck autochk *` |
| Hive loading | `Control\hivelist` | hive outside `System32\config` |
| Browser Helper Objects | `Explorer\Browser Helper Objects` | unsigned BHO DLL |
| AppInit_DLLs | `...\Windows\AppInit_DLLs` | populated with loading enabled |
| DLL search order hijack | app dir, PATH, %TEMP% | same-named DLL ahead of the signed original |
| Rootkit / bootkit / fileless | kernel, boot chain, memory | **not observable here** |

## Three of them are marked, not detected

Rootkits, bootkits and fileless execution are in the source list, and none of them leaves an
autostart artefact that a snapshot can see. Anything a rootkit hides is absent from the very
snapshot that would report it. The module returns `UNKNOWN` with the statement "not
observable from an autostart snapshot" rather than an empty signal list, because an empty
list reads as innocence.

Their controls are out of band: an offline image read against a golden reference for a
rootkit, measured boot with a hardware anchor for a bootkit (`firmware_integrity.py`), and
execution-time ancestry telemetry for fileless code. None of these are achievable after the
fact on a dead image.

## Grading

Findings are graded by the collection basis, not by how suspicious the entry looks:

| Basis | Evidence class | Ceiling |
|-------|----------------|---------|
| `synthetic` | self_report | none: no graded finding |
| `live_host` | self_report | none: the subject reported its own state |
| `offline_image` | independent_measurement | CORROBORATED |
| `attested_image` | independent + hardware anchor | CONFIRMED |

One signal proposes `HYPOTHESIS`, two or more propose `INFERRED`, and the ceiling caps the
result. A live registry read is a self-report and yields no graded finding at all, which is
the host trust gap applied to persistence: a compromised host's autostart list is the
compromised host's account of itself.

`attested_image` does not promote anything. A ceiling is a limit, not a target, and there
is a test asserting exactly that.

## Never "clean"

`coverage()` separates three states: `observed`, `not_observed` (an observable mechanism
the snapshot did not read) and `not_observable` (a mechanism no snapshot can read). The
statement attached says a mechanism that was not observed was not thereby shown to be
absent. `summarise()` carries `never_claim_clean: True` and the word CLEAN appears nowhere.

## Benign twins

Every observation carries at least one benign explanation, because most of these locations
are populated on a healthy machine:

- `Run` holds OneDrive, Teams, and every updater.
- `TaskCache\Tree` is full of maintenance tasks.
- `ServiceDll` is how svchost works, not a trick.
- Startup shortcuts are what the folder is for.

A signed vendor binary under `Program Files` produces no signals and the statement "not
evidence of anything". Accusing normal software would destroy the instrument faster than
missing an implant would.

## Tests

`qvault/tests/test_persistence.py`, 30 tests, covering the catalogue, the unobservable
three, each signal, the basis ceilings, coverage honesty, and the refusals.
