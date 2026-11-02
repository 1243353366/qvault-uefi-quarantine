"""Add P8 (LAN integrity) to the capability ledger and update the counts that follow."""

import pathlib

# --- 1. the pillar itself -------------------------------------------------
p = pathlib.Path('qvault/pillars.py')
s = p.read_text()

p8 = '''
    {
        "id": "P8",
        "name": "LAN integrity and lateral movement - roles, identity, discovery, graded containment",
        "requirements": [
            {"req": "device identity bound to an authenticated credential, not a wireless label",
             "module": "lan", "symbol": "Device", "test": "qvault/tests/test_lan.py",
             "status": IMPLEMENTED, "required": True, "limit": ""},
            {"req": "per-role least-privilege service policy with out-of-role detection",
             "module": "lan", "symbol": "out_of_role", "test": "qvault/tests/test_lan.py",
             "status": IMPLEMENTED, "required": True, "limit": ""},
            {"req": "traffic baseline and deviation reporting with a benign reading per entry",
             "module": "lan", "symbol": "deviations", "test": "qvault/tests/test_lan.py",
             "status": IMPLEMENTED, "required": True, "limit": ""},
            {"req": "local discovery monitoring (mdns, llmnr, netbios, ssdp, upnp)",
             "module": "lan", "symbol": "discovery_anomalies", "test": "qvault/tests/test_lan.py",
             "status": IMPLEMENTED, "required": True, "limit": ""},
            {"req": "east-west correlation graded by independent layers, not volume",
             "module": "lan", "symbol": "lateral_movement", "test": "qvault/tests/test_lan.py",
             "status": IMPLEMENTED, "required": True, "limit": ""},
            {"req": "network infrastructure integrity (router, AP, switch, DNS, DHCP)",
             "module": "lan", "symbol": "infrastructure_integrity", "test": "qvault/tests/test_lan.py",
             "status": PARTIAL, "required": True,
             "limit": "inherits P5: attestation depends on an out-of-band anchor most fleets lack"},
            {"req": "graded, device-scoped containment that refuses an untrusted enforcement plane",
             "module": "lan", "symbol": "containment_plan", "test": "qvault/tests/test_lan.py",
             "status": IMPLEMENTED, "required": True,
             "limit": "plane trust is declared by the operator, not measured"},
            {"req": "cross-layer verdict: behaviour inconsistent with authenticated identity",
             "module": "lan", "symbol": "identity_inconsistency", "test": "qvault/tests/test_lan.py",
             "status": IMPLEMENTED, "required": True,
             "limit": "no live capture in this repo; metadata comes from existing sensors"},
        ],
    },
'''

anchor = ']\n\n\n#: Requirements that cannot currently be met'
if anchor in s:
    s = s.replace(anchor, p8 + anchor, 1)
else:
    # append before the closing bracket of PILLARS
    idx = s.index('\n]\n', s.index('PILLARS = ['))
    s = s[:idx] + '\n' + p8 + s[idx:]

p.write_text(s)

# --- 2. counts that assumed seven ----------------------------------------
t = pathlib.Path('qvault/tests/test_pillars_revoke_budgets.py')
ts = t.read_text()
ts = ts.replace('def test_all_seven_pillars_are_present():\n    assert [p["id"] for p in P.PILLARS] == ["P1", "P2", "P3", "P4", "P5", "P6", "P7"]',
                'def test_all_eight_pillars_are_present():\n    assert [p["id"] for p in P.PILLARS] == ["P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8"]')
ts = ts.replace('assert sum(out["counts"].values()) == 7', 'assert sum(out["counts"].values()) == len(P.PILLARS)')
t.write_text(ts)

sm = pathlib.Path('tools/smoke.py')
ss = sm.read_text()
ss = ss.replace('check("seven capabilities traced", audit["counts"]["GAP"] + audit["counts"]["PARTIAL"]\n      + audit["counts"]["IMPLEMENTED"] == 7, str(audit["counts"]))',
                'check("every capability traced", audit["counts"]["GAP"] + audit["counts"]["PARTIAL"]\n      + audit["counts"]["IMPLEMENTED"] == 8, str(audit["counts"]))')
sm.write_text(ss)
print("P8 added; counts updated")
