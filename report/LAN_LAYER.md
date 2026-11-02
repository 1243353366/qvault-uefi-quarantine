# LAN layer: integrity, lateral movement, graded containment

QVault is not a network intrusion detection system. It is a cross-layer trust and
containment system, and this layer adds the network relationship view to firmware,
endpoint and evidence provenance.

Implementation: `qvault/lan.py`. Tests: `qvault/tests/test_lan.py`. Capability: **P8**.

## Why a LAN is a different unit of analysis

A LAN is a communication environment, not a single compromised machine. Malware operating
across it depends on discovery, authentication, reachable services, shared infrastructure
and implicit trust. Each dependency is a containment opportunity, and none of them is a
property of one host.

The question this layer answers is not "is this packet malicious". It is:

> Is this device behaving inconsistently with its authenticated identity, even when its
> own operating system is compromised?

## Three rules that shape the design

**1. A BSSID is a label, not an identity.** It can be copied, so authorisation binds to a
certificate fingerprint or keyed device identity. `Device.identity_key` never returns a
wireless label, and a device with no authenticated identity raises rather than falling
back to an address.

| Layer                            | What it protects                           |
| -------------------------------- | ------------------------------------------ |
| WPA3 / 802.1X                    | association and authentication             |
| BSSID                            | which AP interface was used (context only) |
| VLAN                             | logical segmentation                       |
| ACL / firewall                   | permitted traffic between devices          |
| Mutual TLS + device certificates | endpoint identity                          |
| Firmware integrity               | trust in the infrastructure itself         |

**2. Metadata over content.** Source, destination, timing, volume, service, DNS name and
endpoint process events are enough to reason about relationships. TLS interception is not
a requirement, and is not implemented.

**3. Containment is graded, device-scoped, and refused when unenforceable.** A step that
affects more than one device, or that pushes material to other hosts, is refused by
`assert_narrow()`. Containment that propagates is an outbreak.

## The six functions

| Function                        | What it does                                                                                     |
| ------------------------------- | ------------------------------------------------------------------------------------------------ |
| `Device` / roles                | inventory with authenticated identity and least-privilege service policy                         |
| `build_baseline` / `deviations` | normal peer and service relationships; new peer, new service, first contact                      |
| `discovery_anomalies`           | mdns, llmnr, netbios, ssdp, upnp: an unsanctioned *response* is a claim of authority over a name |
| `lateral_movement`              | east-west service use correlated with authentication failures, graded by independent layers      |
| `infrastructure_integrity`      | router, AP, switch, DNS, DHCP attestation and identity strength                                  |
| `containment_plan`              | graded ladder, with refusals naming the plane that cannot be trusted                             |

## Grading: independence, not volume

`lateral_movement()` counts distinct *kinds* of observation — network, authentication,
authentication-after-failure, role violation. One layer is a lead (`HYPOTHESIS`), two is a
suspicion (`INFERRED`), three reaches `CORROBORATED`. Duplicated flows collapse before
counting, so a sensor logging a flow six times, or a replayed record, cannot manufacture
agreement.

## The research question: identity inconsistency

`identity_inconsistency()` fuses layers and refuses to answer without an anchor that does
not ask the device:

| Evidence                                        | Verdict                                     |
| ----------------------------------------------- | ------------------------------------------- |
| Endpoint indicators only                        | insufficient                                |
| LAN deviation + endpoint, no firmware anchor    | unverified (`no_firmware_anchor` gap)       |
| LAN deviation + endpoint + firmware attestation | inconsistent with identity (`CORROBORATED`) |

That last row is the only shape that survives a compromised OS, because every other layer
is authored by the suspect.

## Graded containment ladder

| Step              | Effect                                         | Reversible | Blast radius |
| ----------------- | ---------------------------------------------- | ---------- | ------------ |
| observe           | more logging for the device and peers          | yes        | 1            |
| restrict_egress   | block internet egress, keep LAN                | yes        | 1            |
| microsegment      | per-device ACL denying lateral services        | yes        | 1            |
| revoke_credential | revoke at the issuer                           | no         | 1            |
| isolate_port      | disable switch port or quarantine VLAN         | yes        | 1            |
| physical          | power off, escalate to out-of-band acquisition | no         | 1            |

`containment_plan()` removes any switch-dependent step when the switch plane is untrusted,
and names the alternatives instead. Asking a compromised switch to quarantine an attacker
makes the attacker the jailer.

Forbidden as containment: credentials, keys, configuration, agent binaries and policy
bundles pushed to other hosts.

## Honest limits

- **No live capture in this repository.** The layer consumes flows, auth events and
  discovery events from existing sensors; it does not sniff, and does not intercept TLS.
- **Enforcement-plane trust is declared, not measured.** `containment_plan()` honours the
  operator's assertion about the switch. Nothing verifies it, which is why the refusal path
  exists.
- **Role policy is a starting point.** Installers, backup windows and monitoring agents
  routinely violate role purity, so every deviation carries a benign reading and none of
  them is a verdict.
- **Infrastructure attestation inherits P5's gap.** Without an out-of-band anchor, a router
  or AP cannot be shown to be running its vendor image.
