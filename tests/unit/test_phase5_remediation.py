"""Unit tests for Phase 5 Minimum-Blast-Radius Remediation Analysis."""

from uuid import uuid4

from acsa.inventory.models import Component
from acsa.reachability.models import ReachabilityAnalysis, ReachabilityState
from acsa.remediation.candidates import (
    CandidateGenerator,
    select_minimum_safe_version,
)
from acsa.remediation.models import (
    CandidateStatus,
    ClosureStatus,
    DependencyContext,
    DependencyRelation,
    EvidenceConfidence,
    RemediationCandidate,
    RemediationStrategy,
)
from acsa.remediation.ranking import RemediationRanker
from acsa.verdict.vocabulary import Verdict
from acsa.vulnerability.models import ApplicabilityStatus, Finding, Vulnerability


def make_vuln(
    vuln_id: str = "GHSA-1111-2222-3333",
    fixed_versions: list[str] | None = None,
    affected_ranges: list[str] | None = None,
    vulnerable_symbols: list[str] | None = None,
) -> Vulnerability:
    """Helper to construct Vulnerability instance."""
    return Vulnerability(
        id=vuln_id,
        aliases=[],
        summary="Test advisory",
        details="Details about test flaw",
        severity="HIGH",
        affected_ranges=affected_ranges or ["<1.2.0"],
        fixed_versions=fixed_versions or ["1.2.0"],
        vulnerable_symbols=vulnerable_symbols or [],
        database_specific={},
    )


def make_finding(
    pkg_name: str = "lodash",
    version: str = "4.17.19",
    verdict: Verdict = Verdict.PROVEN_EXPOSURE,
    vulnerability: Vulnerability | None = None,
    vulnerable_symbols: list[str] | None = None,
) -> Finding:
    """Helper to construct Finding instance."""
    vuln = vulnerability or make_vuln(
        vuln_id="GHSA-29mw-wpgm-hmr9",
        fixed_versions=["4.17.21"],
        affected_ranges=["<4.17.21"],
        vulnerable_symbols=vulnerable_symbols or ["template"],
    )
    comp = Component(
        id=str(uuid4()),
        name=pkg_name,
        version=version,
        purl=f"pkg:npm/{pkg_name}@{version}",
        ecosystem="npm",
    )
    sym = vuln.vulnerable_symbols[0] if vuln.vulnerable_symbols else "API"
    reach = ReachabilityAnalysis(
        status=ReachabilityState.REACHABLE,
        target_symbol=sym,
        entry_point="server.js:10",
        call_site="app.js:42",
        evidence_path=[f"app.js -> call to {sym}"],
    )
    return Finding(
        id=str(uuid4()),
        vulnerability=vuln,
        component=comp,
        verdict=verdict,
        applicability_status=ApplicabilityStatus.AFFECTED,
        reachability=reach,
        confidence=0.95,
    )


# -------------------------------------------------------------------------
# Test 1: Direct upgrade candidate
# -------------------------------------------------------------------------
def test_direct_upgrade_candidate() -> None:
    """Direct dependency upgrade produces DIRECT_UPGRADE with explicit dimensions and HIGH confidence."""
    finding = make_finding(pkg_name="lodash", version="4.17.19")
    dep_ctx = DependencyContext(
        package_name="lodash",
        current_version="4.17.19",
        relation=DependencyRelation.DIRECT,
        is_used_in_code=True,
        has_contradictions=False,
        manifest_file="package.json",
        lockfile="package-lock.json",
        declared_constraint="^4.17.19",
    )

    candidates = CandidateGenerator.generate_candidates(finding, dep_ctx, [finding.vulnerability])
    assert len(candidates) >= 1

    cand = candidates[0]
    assert cand.strategy == RemediationStrategy.DIRECT_UPGRADE
    assert cand.current_version == "4.17.19"
    assert cand.target_version == "4.17.21"
    assert cand.version_impact == "PATCH"
    assert cand.closure_status == ClosureStatus.PROVEN_CLOSED
    assert cand.confidence_level == EvidenceConfidence.HIGH
    assert cand.lockfile_action == "LOCKFILE_REGENERATION_REQUIRED"
    assert "package.json" in cand.files_changed
    assert "package-lock.json" not in cand.files_changed  # Lockfile requires regeneration, not fake diff
    assert "lodash" in cand.dependencies_affected
    assert cand.api_impact == "NONE"


# -------------------------------------------------------------------------
# Test 2: Transitive upgrade candidate
# -------------------------------------------------------------------------
def test_transitive_upgrade_candidate() -> None:
    """Transitive dependency upgrade produces TRANSITIVE_OVERRIDE via package.json."""
    vuln = make_vuln(vuln_id="GHSA-c2qf-rxjj-qqgw", fixed_versions=["5.7.2"], affected_ranges=["<5.7.2"])
    finding = make_finding(pkg_name="semver", version="5.7.0", verdict=Verdict.PROVEN_AFFECTED, vulnerability=vuln)
    dep_ctx = DependencyContext(
        package_name="semver",
        current_version="5.7.0",
        relation=DependencyRelation.TRANSITIVE,
        parent_package=None,
        is_used_in_code=False,
        has_contradictions=False,
        lockfile="package-lock.json",
    )

    candidates = CandidateGenerator.generate_candidates(finding, dep_ctx, [vuln])
    assert len(candidates) >= 1

    cand = candidates[0]
    assert cand.strategy == RemediationStrategy.TRANSITIVE_OVERRIDE
    assert cand.target_version == "5.7.2"
    assert "package.json" in cand.files_changed
    assert cand.api_impact == "NONE"
    assert cand.lockfile_action == "LOCKFILE_REGENERATION_REQUIRED"


# -------------------------------------------------------------------------
# Test 3: Parent dependency candidate
# -------------------------------------------------------------------------
def test_parent_dependency_candidate() -> None:
    """When a parent package introduces a vulnerable transitive dependency, propose PARENT_UPGRADE."""
    vuln = make_vuln(vuln_id="GHSA-1234", fixed_versions=["0.2.1"], affected_ranges=["<0.2.1"])
    finding = make_finding(pkg_name="minimist", version="0.0.8", verdict=Verdict.PROVEN_AFFECTED, vulnerability=vuln)
    dep_ctx = DependencyContext(
        package_name="minimist",
        current_version="0.0.8",
        relation=DependencyRelation.TRANSITIVE,
        parent_package="mkdirp",
        is_used_in_code=False,
        has_contradictions=False,
        lockfile="package-lock.json",
    )

    candidates = CandidateGenerator.generate_candidates(finding, dep_ctx, [vuln])
    parent_cands = [c for c in candidates if c.strategy == RemediationStrategy.PARENT_UPGRADE]
    assert len(parent_cands) == 1

    pc = parent_cands[0]
    assert pc.target_version == "0.2.1"
    assert pc.confidence_level == EvidenceConfidence.MEDIUM
    assert pc.lockfile_action == "LOCKFILE_REGENERATION_REQUIRED"
    assert "mkdirp" in pc.dependencies_affected
    assert "minimist" in pc.dependencies_affected


# -------------------------------------------------------------------------
# Test 4: Unused dependency removal
# -------------------------------------------------------------------------
def test_unused_dependency_removal() -> None:
    """Provably unused declared dependency produces REMOVE_DEPENDENCY candidate."""
    finding = make_finding(pkg_name="unused-lib", version="1.0.0", verdict=Verdict.PROVEN_AFFECTED)
    dep_ctx = DependencyContext(
        package_name="unused-lib",
        current_version="1.0.0",
        relation=DependencyRelation.UNUSED,
        is_used_in_code=False,
        has_contradictions=False,
        manifest_file="package.json",
        declared_constraint="^1.0.0",
    )

    candidates = CandidateGenerator.generate_candidates(finding, dep_ctx, [finding.vulnerability])
    assert len(candidates) == 1
    cand = candidates[0]
    assert cand.strategy == RemediationStrategy.REMOVE_DEPENDENCY
    assert cand.target_version is None
    assert cand.version_impact == "NONE"
    assert cand.closure_status == ClosureStatus.PROVEN_CLOSED
    assert cand.confidence_level == EvidenceConfidence.HIGH
    assert cand.api_impact == "NONE"


# -------------------------------------------------------------------------
# Test 5: Multiple advisories affecting one package
# -------------------------------------------------------------------------
def test_multiple_advisories_affecting_one_package() -> None:
    """When multiple advisories affect a package, safe version satisfies ALL advisories."""
    adv1 = make_vuln(vuln_id="GHSA-1", fixed_versions=["1.2.0"], affected_ranges=["<1.2.0"])
    adv2 = make_vuln(vuln_id="GHSA-2", fixed_versions=["1.3.0"], affected_ranges=["<1.3.0"])

    safe_ver = select_minimum_safe_version(current_version="1.0.0", advisories=[adv1, adv2])
    # 1.2.0 satisfies adv1 but is vulnerable to adv2 (<1.3.0) -> must select 1.3.0
    assert safe_ver == "1.3.0"


# -------------------------------------------------------------------------
# Test 5b: Express multiple advisories (reject 4.19.2, select 4.20.0)
# -------------------------------------------------------------------------
def test_express_multiple_advisories_rejects_4_19_2() -> None:
    """Verify that 4.19.2 is rejected against GHSA-qw6h-vgh9-j6wx (<4.20.0), selecting 4.20.0."""
    adv_redirect = make_vuln(
        vuln_id="GHSA-qw6h-vgh9-j6wx",
        fixed_versions=["4.20.0", "5.0.0"],
        affected_ranges=[">=0 <4.20.0", ">=5.0.0-alpha.1 <5.0.0"],
    )
    adv_pollution = make_vuln(
        vuln_id="GHSA-rv95-896h-c2vc",
        fixed_versions=["4.19.2", "5.0.0-beta.3"],
        affected_ranges=[">=0 <4.19.2", ">=5.0.0-alpha.1 <5.0.0-beta.3"],
    )

    from acsa.remediation.candidates import is_version_safe_against_advisories

    # 4.19.2 is NOT safe against adv_redirect!
    is_safe_419, reason = is_version_safe_against_advisories("4.19.2", [adv_redirect, adv_pollution])
    assert not is_safe_419
    assert "GHSA-qw6h-vgh9-j6wx" in str(reason)

    # 4.20.0 is safe against BOTH!
    is_safe_420, _ = is_version_safe_against_advisories("4.20.0", [adv_redirect, adv_pollution])
    assert is_safe_420

    # Minimum safe version must be 4.20.0 (not 4.19.2, and not jumping to 5.0.0)
    selected = select_minimum_safe_version("4.16.0", [adv_redirect, adv_pollution])
    assert selected == "4.20.0"


# -------------------------------------------------------------------------
# Test 6: Minimum safe version selection (not blindly latest)
# -------------------------------------------------------------------------
def test_minimum_safe_version_selection() -> None:
    """Select minimum non-vulnerable version, avoiding major breaking version jumps."""
    adv = make_vuln(vuln_id="GHSA-express", fixed_versions=["4.20.0", "5.0.0"], affected_ranges=["<4.20.0"])
    safe_ver = select_minimum_safe_version(current_version="4.16.4", advisories=[adv])
    assert safe_ver == "4.20.0"


# -------------------------------------------------------------------------
# Test 7: Candidate that does NOT resolve all advisories must be rejected
# -------------------------------------------------------------------------
def test_candidate_not_resolving_all_advisories_rejected() -> None:
    """A proposed candidate that leaves any known advisory open is rejected."""
    adv1 = make_vuln(vuln_id="GHSA-1", fixed_versions=["1.2.0"], affected_ranges=["<1.2.0"])
    adv2 = make_vuln(vuln_id="GHSA-2", fixed_versions=["1.3.0"], affected_ranges=["<1.3.0"])

    cand = RemediationCandidate(
        strategy=RemediationStrategy.DIRECT_UPGRADE,
        package_name="test-pkg",
        current_version="1.0.0",
        target_version="1.2.0",  # Vulnerable to adv2!
        files_changed=["package.json"],
        dependencies_affected=["test-pkg"],
    )
    finding = make_finding(pkg_name="test-pkg", version="1.0.0", vulnerability=adv1)

    is_valid, reason = CandidateGenerator.validate_candidate(cand, finding, [adv1, adv2])
    assert not is_valid
    assert "fails advisory check" in reason


# -------------------------------------------------------------------------
# Test 8: Candidate that does NOT close proven exposure path must be rejected
# -------------------------------------------------------------------------
def test_candidate_not_closing_proven_exposure_path_rejected() -> None:
    """In PROVEN_EXPOSURE, REMOVE_DEPENDENCY or unrelated API replacement is rejected."""
    finding = make_finding(
        pkg_name="lodash",
        version="4.17.19",
        verdict=Verdict.PROVEN_EXPOSURE,
        vulnerable_symbols=["template"],
    )

    # Candidate attempting to remove a dependency that is actively called
    cand_remove = RemediationCandidate(
        strategy=RemediationStrategy.REMOVE_DEPENDENCY,
        package_name="lodash",
        current_version="4.17.19",
        target_version=None,
    )
    is_valid, reason = CandidateGenerator.validate_candidate(cand_remove, finding, [finding.vulnerability])
    assert not is_valid
    assert "actively called" in reason

    # Candidate API replacement targeting wrong symbol 'trim' instead of 'template'
    cand_api_wrong = RemediationCandidate(
        strategy=RemediationStrategy.API_REPLACEMENT,
        package_name="lodash",
        current_version="4.17.19",
        target_version=None,
        reason="Replace usage of trim function",
    )
    is_valid2, reason2 = CandidateGenerator.validate_candidate(cand_api_wrong, finding, [finding.vulnerability])
    assert not is_valid2
    assert "does not target proven vulnerable symbol" in reason2


# -------------------------------------------------------------------------
# Test 9: Contradictory inventory prevents unsafe automatic recommendation
# -------------------------------------------------------------------------
def test_contradictory_inventory_prevents_unsafe_automatic_recommendation() -> None:
    """Contradictory inventory blocks automated remediation to prevent unsafe fixes."""
    finding = make_finding(pkg_name="conflicted-pkg", version="1.0.0", verdict=Verdict.CONTRADICTORY)
    dep_ctx = DependencyContext(
        package_name="conflicted-pkg",
        current_version="1.0.0",
        relation=DependencyRelation.DIRECT,
        has_contradictions=True,
    )

    candidates = CandidateGenerator.generate_candidates(finding, dep_ctx, [finding.vulnerability])
    assert len(candidates) == 1
    cand = candidates[0]
    assert cand.strategy == RemediationStrategy.NO_SAFE_CANDIDATE
    assert cand.status == CandidateStatus.CONTRADICTION_BLOCKED
    assert cand.confidence_level == EvidenceConfidence.LOW
    assert cand.closure_status == ClosureStatus.REQUIRES_VERIFICATION
    assert "Contradictory inventory" in cand.reason


# -------------------------------------------------------------------------
# Test 10: UNKNOWN finding does not receive a falsely confident remediation
# -------------------------------------------------------------------------
def test_unknown_finding_does_not_receive_falsely_confident_remediation() -> None:
    """Findings with UNKNOWN verdict receive candidates labeled REQUIRES_CONFIRMATION with lowered confidence."""
    finding = make_finding(pkg_name="express", version="4.16.4", verdict=Verdict.UNKNOWN)
    dep_ctx = DependencyContext(
        package_name="express",
        current_version="4.16.4",
        relation=DependencyRelation.DIRECT,
        is_used_in_code=True,
    )

    candidates = CandidateGenerator.generate_candidates(finding, dep_ctx, [finding.vulnerability])
    assert len(candidates) >= 1
    cand = candidates[0]
    assert cand.status == CandidateStatus.REQUIRES_CONFIRMATION
    assert cand.confidence_level == EvidenceConfidence.LOW
    assert cand.closure_status == ClosureStatus.REQUIRES_VERIFICATION
    assert "UNKNOWN" in cand.reason


# -------------------------------------------------------------------------
# Test 11: No safe candidate when no fixed version exists
# -------------------------------------------------------------------------
def test_no_safe_candidate_when_no_fixed_version() -> None:
    """When upstream advisory intelligence reports no fixed version, return NO_SAFE_CANDIDATE."""
    vuln_unfixed = make_vuln(vuln_id="GHSA-unfixed", fixed_versions=[], affected_ranges=[">=0"])
    finding = make_finding(pkg_name="unfixed-lib", version="1.0.0", vulnerability=vuln_unfixed)
    dep_ctx = DependencyContext(
        package_name="unfixed-lib",
        current_version="1.0.0",
        relation=DependencyRelation.DIRECT,
        is_used_in_code=True,
    )

    candidates = CandidateGenerator.generate_candidates(finding, dep_ctx, [vuln_unfixed])
    assert len(candidates) == 1
    cand = candidates[0]
    assert cand.strategy == RemediationStrategy.NO_SAFE_CANDIDATE
    assert cand.status == CandidateStatus.NO_SAFE_CANDIDATE
    assert cand.target_version is None


# -------------------------------------------------------------------------
# Test 12: Ranking prefers lower blast radius without numeric scores
# -------------------------------------------------------------------------
def test_ranking_prefers_lower_blast_radius() -> None:
    """Direct patch upgrade is preferred over major upgrade and API code rewrites."""
    patch_cand = RemediationCandidate(
        strategy=RemediationStrategy.DIRECT_UPGRADE,
        package_name="lodash",
        current_version="4.17.19",
        target_version="4.17.21",
        files_changed=["package.json"],
        dependencies_affected=["lodash"],
        version_impact="PATCH",
        api_impact="NONE",
        closure_status=ClosureStatus.PROVEN_CLOSED,
        confidence_level=EvidenceConfidence.HIGH,
        closed_advisories_count=1,
        total_advisories_count=1,
        closed_paths_count=1,
        total_paths_count=1,
        reason="Patch release",
    )
    api_cand = RemediationCandidate(
        strategy=RemediationStrategy.API_REPLACEMENT,
        package_name="lodash",
        current_version="4.17.19",
        target_version=None,
        files_changed=["app.js"],
        dependencies_affected=[],
        version_impact="NONE",
        api_impact="SIGNIFICANT",
        closure_status=ClosureStatus.PROVEN_CLOSED,
        confidence_level=EvidenceConfidence.MEDIUM,
        closed_advisories_count=1,
        total_advisories_count=1,
        closed_paths_count=1,
        total_paths_count=1,
        reason="Rewrite call site",
    )

    ranked = RemediationRanker.rank_candidates([api_cand, patch_cand])
    assert ranked[0].strategy == RemediationStrategy.DIRECT_UPGRADE
    assert ranked[0].status == CandidateStatus.ACCEPTED

    explanation = RemediationRanker.generate_explanation(ranked[0], alternatives=ranked)
    assert "Patch release" in explanation
    assert "Application source files changed: 0" in explanation
    assert "Package dependencies affected: 1" in explanation
    assert "vs API_REPLACEMENT" in explanation
    # Confirm no arbitrary numeric score appears
    assert "0.10" not in explanation
    assert "0.75" not in explanation
