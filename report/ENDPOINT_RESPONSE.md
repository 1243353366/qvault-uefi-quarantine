# Endpoint response: crushing a suspected keylogger

Release **0.16.0**. Tools `response/crush-klog.sh` and `response/Crush-Klog.ps1`, tests
`qvault/tests/test_response_scripts.py`.

Suspend, isolate, quarantine and de-persist a suspected software keylogger, reversibly. Dry run is the
default; `--apply` / `-Apply` is required to change anything; every applied action is recorded and a
`RESTORE` script is generated that puts the machine back.

The point is containment without destruction. Nothing is deleted, the system clock is never touched,
and a failed step is reported as failed rather than assumed to have worked.

## Order, and why the order is the design

1. **Evidence first.** Hashes, a read-only copy of the binary, live sockets, the persistence inventory
   and per-process metadata are all captured before any mutation. After suspension the socket map is
   gone and the process metadata starts decaying.
2. **Suspend, children first.** Depth-first post-order. A watchdog is usually the child of the thing it
   protects, so suspending the parent first frees the watchdog to put the Run key back within seconds.
3. **De-persist after suspension.** Same reason: a dead process cannot re-create its own autostart
   entry, while a live one recreates it faster than the operator can delete it.
4. **Quarantine by rename**, not deletion: `app` becomes `app.quarantined`, and system directories are
   refused outright so containment cannot turn into destruction.
5. **Network block**, by recorded destination where sockets were captured, and by executable path for
   the quarantined copy.
6. **Read-only containment** on the quarantined tree, so a resumed process cannot rewrite its own logs.

## The reversibility contract

`RESTORE.sh` / `RESTORE.ps1` is generated on every applied run and is idempotent: resume the suspended
processes, remove the firewall rules, rename the directories back, re-enable the units and services,
restore the crontab from its verbatim copy, reload the filter drivers. Restore uses the **recorded**
absolute paths rather than `$HOME` or `$env:USERPROFILE`, because a restore run by a different operator
would otherwise put a profile entry back in the wrong profile.

## Chain of custody

`report.txt`, `events.jsonl` (UTC, one line per phase), `evidence/hashes.txt`, the read-only binary
copy, `persistence/entries.*` and `MANIFEST.sha256` covering every artefact except itself. The clock is
recorded and not modified, which is what makes the timestamps worth anything later.

## What was wrong with the draft, and what changed

| Draft behaviour                                              | Why it fails                                                                                                                              | Shipped behaviour                                                                                         |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Tree built breadth-first, then the outer array reversed      | Suspends the root first, freeing the watchdog to respawn                                                                                  | Depth-first post-order, children before parents                                                           |
| `"$t.exe"` appended to a target that already ended in `.exe` | Looks for `klog.exe.exe`, silently matches nothing                                                                                        | Suffix appended only when absent                                                                          |
| Firewall step used `roots[0]`'s filename for every rule      | Rules bind to the wrong executable for all but the first target                                                                           | Each renamed directory supplies its own executable                                                        |
| `fltmc filters` parsed at split index `[2]`                  | Column padding moves the name; silently finds no filter or the wrong one                                                                  | Split on whitespace runs, name at index 0, header skipped                                                 |
| `-TimeWarp` skewed the system clock                          | Rewrites file timestamps and breaks event correlation: destroys the timeline the run exists to preserve                                   | Parameter kept and **refused by name**, with the reason                                                   |
| Report written only on the success path                      | A dry run, a refusal or a crash left no record at all                                                                                     | Written from a `finally` block on every exit path                                                         |
| Rename attempted without checking the directory              | `C:\Program Files` or `/usr/bin` renamed would be destruction, not containment                                                            | System and shared program directories refused before any rename                                           |
| `/proc/pid/exe` trusted as the target                        | For an interpreted implant that is `python` or `bash`: the tool would look for "bash" in persistence and copy the interpreter as evidence | Interpreter detected, real script resolved from the command line, interpreter recorded and never modified |
| Restore rebuilt autostart under `$HOME`                      | A restore under another account restores into the wrong profile                                                                           | Recorded absolute path used                                                                               |
| Linux: no restore path at all                                | Reversibility was the stated premise and the Linux half had none                                                                          | `RESTORE.sh` generated, tested end to end                                                                 |

Two of these were found by running the tool, not by reading it: the self-match (the tool's own command
line contains the target string, so `pgrep -f` matched the tool and it tried to suspend itself) and the
interpreter resolution, which produced a live false positive on `debug-shell.service` because the
matched "name" was `bash`.

## Testing status, stated plainly

| Component        | Status                                                                                                                                                                                                                                                                                                                         |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `crush-klog.sh`  | **Executed end to end**: decoy planted, dry run verified side-effect-free, apply verified to suspend (state `T`), quarantine, and move persistence; `RESTORE.sh` verified to resume, rename back and restore the autostart entry under a different `HOME`.                                                                     |
| `Crush-Klog.ps1` | **Parsed by PowerShell 7.4.6**; `Get-OrderedTree` and `Test-PathHit` are executed out of the shipped file by the test suite. Everything Windows-specific (CIM, registry, `fltmc`, `New-NetFirewallRule`, `NtSuspendProcess`) is **reviewed, not run**: there is no Windows host here. Treat first use as a supervised dry run. |

That asymmetry is not hidden in a footnote because it is the one thing an examiner will ask about.

## Limits

- **A kernel-mode keylogger is not touched.** No user-mode action removes a driver; the filter-driver
  step is best-effort and a failure is reported, not hidden.
- **Protected processes (PPL) do not suspend.** The script reports the failure and the process keeps
  running.
- **Renaming can fail while the image is mapped.** On Windows the directory may be locked even with the
  process suspended; the step reports `FAILED` and the run exits `3` (partial).
- **A suspended process keeps its open sockets.** Suspension stops execution, not the existing
  connection state; the firewall rules bind to paths, so they bite on restart.
- **Level 4 capture is out of scope.** Physical interception and firmware-level capture produce no
  endpoint telemetry at all, which is the same boundary the input-capture tiers describe.
- **This tool does not prove the process was a keylogger.** It contains a suspect. Judging whether the
  observation adds up is the grading problem: two telemetry planes, innocent explanations excluded on
  the record, and no "clean" verdict from an absence of signals.

## Use

```bash
./response/crush-klog.sh klog              # report only
sudo ./response/crush-klog.sh klog --apply # contain
sudo <run dir>/RESTORE.sh                  # put it back
```

```powershell
.\Crush-Klog.ps1 -Target klog            # report only
.\Crush-Klog.ps1 -Target klog -Apply     # contain, elevated
<run dir>\RESTORE.ps1                    # put it back, elevated
```

Exit codes: `0` complete, `1` nothing matched, `2` refused (no elevation, or `-TimeWarp`), `3` partial,
`4` unexpected failure. A partial run is the normal outcome on a hardened host, and it is reported as
partial rather than rounded up to success.

Input-capture techniques are classified per MITRE ATT&CK
[T1056](https://attack.mitre.org/techniques/T1056/); the tier model and its coverage limits are the
subject of the input-capture page.
