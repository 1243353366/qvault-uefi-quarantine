"""The trust boundaries, as enforcement rather than documentation.

Six gaps, and only some of them are closable in code. A host-mediated read cannot prove
the host; what code can do is refuse the stronger conclusion and say which evidence class
would support it. That refusal is the subject of these tests.
"""
import pytest

from qvault import findings as F
from qvault import netpolicy as N
from qvault import separation as S


# --- ceilings -----------------------------------------------------------------------

@pytest.mark.parametrize("classes,expected", [
    ([S.SELF_REPORT], None),
    ([S.PEER_CLAIM], F.HYPOTHESIS),
    ([S.INDEPENDENT_MEASUREMENT], F.CORROBORATED),
    ([S.SIGNED_MANIFEST], F.CORROBORATED),
    ([S.HARDWARE_ANCHOR], F.CONFIRMED),
    ([S.SELF_REPORT, S.HARDWARE_ANCHOR], F.CONFIRMED),
    ([S.SELF_REPORT, S.PEER_CLAIM], F.HYPOTHESIS),
])
def test_ceiling_is_the_best_class_present(classes, expected):
    assert S.grade_ceiling(classes) == expected


def test_a_self_report_supports_no_conclusion_at_all():
    with pytest.raises(S.EvidenceCeilingError) as err:
        S.assert_claim_supported(F.HYPOTHESIS, [S.SELF_REPORT], what="firmware integrity")
    assert "no evidence class" in str(err.value)


def test_no_evidence_never_supports_a_claim():
    with pytest.raises(S.EvidenceCeilingError):
        S.assert_claim_supported(F.HYPOTHESIS, [])


def test_host_mediated_read_cannot_confirm_firmware_integrity():
    """The headline gap: the scanner runs on the machine it is judging."""
    with pytest.raises(S.EvidenceCeilingError) as err:
        S.assert_claim_supported(F.CONFIRMED, [S.INDEPENDENT_MEASUREMENT],
                                 what="firmware integrity")
    message = str(err.value)
    assert "CONFIRMED" in message and "CORROBORATED" in message
    assert "stronger evidence class" in message


def test_out_of_band_measurement_supports_corroboration_but_not_confirmation():
    assert S.assert_claim_supported(F.CORROBORATED, [S.INDEPENDENT_MEASUREMENT])["supported"]
    with pytest.raises(S.EvidenceCeilingError):
        S.assert_claim_supported(F.CONFIRMED, [S.INDEPENDENT_MEASUREMENT])


def test_hardware_anchor_supports_confirmation():
    assert S.assert_claim_supported(F.CONFIRMED, [S.HARDWARE_ANCHOR])["ceiling"] == F.CONFIRMED


def test_volume_of_one_class_is_not_a_stronger_class():
    with pytest.raises(S.EvidenceCeilingError) as err:
        S.assert_claim_supported(F.CONFIRMED,
                                 [S.INDEPENDENT_MEASUREMENT] * 50)
    assert "volume" in str(err.value)


def test_unknown_evidence_class_is_a_declaration_error():
    with pytest.raises(S.SeparationError):
        S.grade_ceiling(["vibes"])


# --- pipeline separation ------------------------------------------------------------

def test_one_identity_cannot_both_observe_and_verify():
    conflicts = S.pipeline_conflicts({S.ACQUISITION: "host-a", S.VERIFICATION: "host-a"})
    assert conflicts and "judging what it observed" in conflicts[0]["reason"]


def test_analyst_does_not_verify_its_own_parsing():
    conflicts = S.pipeline_conflicts({S.ANALYSIS: "host-b", S.VERIFICATION: "host-b"})
    assert conflicts


def test_holder_does_not_certify_the_evidence_it_holds():
    conflicts = S.pipeline_conflicts({S.STORAGE: "host-c", S.VERIFICATION: "host-c"})
    assert conflicts


def test_distinct_identities_are_accepted():
    assignment = {S.ACQUISITION: "acq-1", S.ANALYSIS: "lab-2",
                  S.STORAGE: "vault-3", S.VERIFICATION: "ver-4"}
    assert S.assert_pipeline_separated(assignment)["separated"]


def test_full_pipeline_on_one_host_is_refused():
    with pytest.raises(S.SeparationError) as err:
        S.assert_pipeline_separated({role: "the-laptop" for role in S.ROLES})
    assert "the-laptop" in str(err.value)


def test_unknown_role_cannot_be_smuggled_into_a_pipeline():
    with pytest.raises(S.SeparationError):
        S.pipeline_conflicts({S.ACQUISITION: "a", "grading": "b"})


# --- storage ------------------------------------------------------------------------

def test_custody_cannot_be_claimed_on_a_local_filesystem():
    with pytest.raises(S.CustodyClaimError) as err:
        S.assert_custody_claim(S.NOT_WORM)
    assert "rewrite history" in str(err.value)
    assert "object-lock" in str(err.value)


@pytest.mark.parametrize("storage", [S.WORM_EMULATED, S.WORM])
def test_object_lock_storage_supports_the_claim(storage):
    assert S.assert_custody_claim(storage)["supported"]


def test_unknown_storage_class_is_refused_rather_than_assumed_worm():
    with pytest.raises(S.SeparationError):
        S.assert_custody_claim("probably_fine")


# --- scope --------------------------------------------------------------------------

def test_synthetic_fixtures_need_no_isolation():
    assert S.assert_scope(S.SYNTHETIC)["isolation_required"] is False


@pytest.mark.parametrize("isolated,attested", [(False, False), (True, False), (False, True)])
def test_live_capture_is_refused_until_isolated_and_attested(isolated, attested):
    with pytest.raises(S.ScopeError) as err:
        S.assert_scope(S.LIVE_CAPTURE, isolated=isolated, attested=attested)
    assert "outside the supported scope" in str(err.value)


def test_live_capture_is_allowed_on_an_isolated_attested_path():
    assert S.assert_scope(S.LIVE_CAPTURE, isolated=True, attested=True)["attested"]


# --- oracle-safe denials ------------------------------------------------------------

@pytest.mark.parametrize("policy,denied", [
    ("managed", {"resource": "retention", "requested": 999}),
    ("ambiguous", {"resource": "egress"}),
    ("untrusted", {"resource": "egress"}),
    ("hostile", {"resource": "egress"}),
])
def test_an_unprivileged_caller_learns_nothing_about_resources(policy, denied):
    """A refusal for a real resource must be indistinguishable from a made-up one.

    A permitted request still returns allowed: the caller has to know whether to proceed.
    What must not leak is *why* something was refused, and whether it exists at all.
    """
    d = N.Decision(policy=policy, trust=policy)
    known = N.authorize(d, **denied)
    unknown = N.authorize(d, "some_resource_that_does_not_exist")
    assert known == unknown, "the refusal must not distinguish missing from forbidden"


def test_an_unprivileged_refusal_names_no_rule_and_no_resource():
    d = N.Decision(policy="untrusted", trust=N.UNTRUSTED)
    answer = N.authorize(d, "custody", shares=0)
    blob = repr(answer)
    for leak in ("DENY_", "custody", "egress", "share", "INSUFFICIENT"):
        assert leak not in blob, leak
    assert answer["denial"] == "refused"


def test_an_unprivileged_allow_carries_no_detail():
    d = N.Decision(policy="managed", trust=N.MANAGED)
    assert N.authorize(d, "egress") == {"allowed": True}


def test_a_principal_without_a_deployment_grant_still_gets_the_coarse_answer():
    for principal in (N.Principal(), N.Principal(name="x", role=""),
                      N.Principal(name="", role="analysis", sees_detail=True)):
        answer = N.authorize(N.Decision(policy="untrusted", trust=N.UNTRUSTED), "egress",
                             principal=principal)
        assert answer["denial"] == "refused"


def test_an_operating_principal_sees_the_reason_and_the_remedy():
    operator = N.Principal(name="analyst", role="analysis", sees_detail=True)
    answer = N.authorize(N.Decision(policy="untrusted", trust=N.UNTRUSTED), "egress",
                         principal=operator)
    assert answer["denials"][0]["code"] == N.DENY_EGRESS
    assert answer["denials"][0]["remedy"]


def test_bulk_results_do_not_count_denials_for_unprivileged_callers():
    d = N.Decision(policy="untrusted", trust=N.UNTRUSTED)
    answer = N.authorize_all(d, {"egress": {}, "write": {}, "retention": {"requested": 99}})
    assert answer == {"allowed": False, "denial": "refused"}
