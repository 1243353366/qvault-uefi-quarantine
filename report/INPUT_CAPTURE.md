# Input capture: four tiers, and why the tier is not the danger

Release **0.18.0**. Module `qvault/inputcapture.py`, tests `qvault/tests/test_inputcapture.py`.

A collection mechanism can only capture what its observation point can see. That makes the observation point the useful axis for classifying input capture, and it makes **severity a separate axis**: a browser-side session thief at level 1 routinely inflicts more damage than a crude kernel keylogger at level 3, because an authenticated cookie is worth more than a paragraph of typing. This page keeps the two apart everywhere.

## The four tiers

| Level | Observation point | What it sees                                                        | Coverage from a host-resident observer                                     |
| ----- | ----------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| 1     | application       | browser forms, credential APIs, clipboard, GUI text, session tokens | partial: only visible if the application or a browser extension reports it |
| 2     | os                | keyboard hooks and input APIs used by ordinary processes            | observable: OS-level input APIs and the processes using them               |
| 3     | privileged        | drivers, kernel modules, deeper operating-system compromise         | partial: a driver install is visible; a kernel-resident hook may not be    |
| 4     | external          | physical interception, or compromised hardware or firmware          | unobservable from the host: needs external instrumentation                 |

Level 4 is listed rather than quietly omitted. Anything that reads input before it reaches the machine - or inside compromised firmware - leaves no endpoint telemetry, so this project cannot detect it and does not pretend to. Confirming it needs external instrumentation, the same reasoning that makes an off-host SPI read the ground truth in the acquisition doctrine.

## Techniques, by observation point

| Technique                | Level | Planes that can see it               | Impact |
| ------------------------ | ----- | ------------------------------------ | ------ |
| `form_grabbing`          | 1     | endpoint_api, network                | high   |
| `credential_api_hooking` | 1     | endpoint_api, process                | high   |
| `session_theft`          | 1     | endpoint_api, network                | high   |
| `clipboard_monitoring`   | 1     | endpoint_api, process                | medium |
| `gui_capture`            | 1     | endpoint_api, permission             | medium |
| `keylogging`             | 2     | device_access, endpoint_api, process | medium |
| `driver_keylogger`       | 3     | driver, process, registry            | high   |
| `external_interception`  | 4     | none: no endpoint signal exists      | high   |

Keylogging is one row, not the category. Form grabbing, credential-API hooking, session theft and clipboard monitoring are cheaper to run and often worth more, which is why they are first-class here.

## Grading rules

| Rule                          | Consequence                                                                                                           |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Two distinct telemetry planes | `CORROBORATED`; one plane, however many signals, is `INFERRED`                                                        |
| Innocent explanations         | every listed category must be excluded on the record before corroboration; excluding the convenient one is not enough |
| Confirmation                  | `CONFIRMED` is never returned: passive telemetry corroborates, it cannot confirm                                      |
| No findings                   | `UNKNOWN`, never clean; the caveat names level 4 and application dependence                                           |
| Aggregation                   | the case grade is the **weakest** technique, not the strongest                                                        |

## The innocent explanations that must be excluded first

| Category              | Why it produces the same signals                                         |
| --------------------- | ------------------------------------------------------------------------ |
| `accessibility_tool`  | screen readers and switch access read input and screen content by design |
| `keyboard_utility`    | macro, remapping and hotkey tools hook the keyboard API                  |
| `remote_support`      | support and remote-desktop agents capture input and screen by design     |
| `vendor_input_driver` | a signed vendor driver may legitimately own the input stack              |

An API hook is not a finding. Accessibility software reads input and screen content by design; macro and remapping tools hook the keyboard; remote-support agents do both. The report asks the analyst to exclude each category, and records that they did.

## Signals worth correlating

Per MITRE ATT&CK's input-capture techniques, the signals a defender can actually collect are: keyboard-monitoring API activity from a process with no user interface, non-UI processes touching input devices, unauthorised driver installation, suspicious registry modification of input handlers, unexpected input-monitoring permission grants on macOS, and correlation between input access, process creation and unusual outbound traffic. Each maps to a plane in the table above, and the plane, not the count, decides corroboration.

## A bug this module found in itself

The first version computed the case grade with `min` over grade ranks. Because the ranks run from `CONFIRMED` at zero, that returned the **strongest** technique: a case with one corroborated and one merely inferred technique reported `CORROBORATED` overall. A test that expected the weakest grade caught it. This is the specific error a report cannot afford, since it upgrades a claim by arithmetic rather than evidence.

## Defensibility

What an examiner can rely on: the tier is an observation point with a stated coverage; the impact axis is separate and cannot be inflated by the tier; corroboration needs two planes; innocent categories are enumerated and must be excluded on the record; the case grade cannot exceed the weakest technique; `CONFIRMED` and "clean" are unreachable, including for an empty case.

What is not attempted: detection of level 4, and detection of anything on a host whose kernel is already compromised. `qvault/report/THREAT_INTEL.md` covers how such a finding is packaged for filing, with hash-verified artefacts and a required competing explanation.

## Techniques per tier

- **Level 1** (application): `form_grabbing`, `credential_api_hooking`, `session_theft`, `clipboard_monitoring`, `gui_capture`
- **Level 2** (os): `keylogging`
- **Level 3** (privileged): `driver_keylogger`
- **Level 4** (external): `external_interception`
