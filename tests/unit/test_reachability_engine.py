"""Unit tests for static reachability engine across realistic JS/TS fixtures."""

from pathlib import Path

from acsa.inventory.models import Component
from acsa.reachability.models import ReachabilityState
from acsa.reachability.service import ReachabilityService
from acsa.verdict.vocabulary import Verdict
from acsa.vulnerability.models import ApplicabilityStatus, Finding, Vulnerability

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "reachability"


def test_fixture_1_direct_reachable() -> None:
    """Fixture 1: Direct reachability from HTTP route to lodash.template produces REACHABLE."""
    repo_path = FIXTURES_DIR / "direct_reachable"

    vuln = Vulnerability(
        id="GHSA-29mw-wpgm-hmr9",
        summary="Prototype Pollution in lodash",
        vulnerable_symbols=["template"],
        affected_ranges=["< 4.17.21"],
        fixed_versions=["4.17.21"],
    )
    comp = Component(name="lodash", version="4.17.19", ecosystem="npm")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        verdict=Verdict.POTENTIALLY_AFFECTED,
        applicability_status=ApplicabilityStatus.AFFECTED,
    )

    service = ReachabilityService()
    findings, evidence, _graph = service.analyze_findings(repo_path, [finding])

    assert len(findings) == 1
    res = findings[0].reachability
    assert res is not None
    assert res.status == ReachabilityState.REACHABLE
    assert res.target_symbol == "template"
    assert res.entry_point is not None
    assert "src/server.js:6" in res.entry_point
    assert res.call_site is not None
    assert "src/server.js:7" in res.call_site
    assert len(res.evidence_path) >= 2
    assert res.confidence >= 0.9
    assert len(evidence) >= 1
    assert evidence[0].data["vulnerable_symbol"] == "template"


def test_fixture_2_imported_unused() -> None:
    """Fixture 2: Imported package without invocation of vulnerable symbol produces NOT_REACHABLE."""
    repo_path = FIXTURES_DIR / "imported_unused"

    vuln = Vulnerability(
        id="GHSA-29mw-wpgm-hmr9",
        summary="Prototype Pollution in lodash.template",
        vulnerable_symbols=["template"],
        affected_ranges=["< 4.17.21"],
        fixed_versions=["4.17.21"],
    )
    comp = Component(name="lodash", version="4.17.19", ecosystem="npm")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        verdict=Verdict.POTENTIALLY_AFFECTED,
        applicability_status=ApplicabilityStatus.AFFECTED,
    )

    service = ReachabilityService()
    findings, _evidence, _graph = service.analyze_findings(repo_path, [finding])

    assert len(findings) == 1
    res = findings[0].reachability
    assert res is not None
    assert res.status == ReachabilityState.NOT_REACHABLE
    assert res.target_symbol == "template"
    assert res.confidence >= 0.9


def test_fixture_3_unknown_dynamic() -> None:
    """Fixture 3: Dynamic computed property access on vulnerable package produces UNKNOWN (UNKNOWN != SAFE)."""
    repo_path = FIXTURES_DIR / "unknown_dynamic"

    vuln = Vulnerability(
        id="GHSA-29mw-wpgm-hmr9",
        summary="Prototype Pollution in lodash",
        vulnerable_symbols=["template"],
        affected_ranges=["< 4.17.21"],
        fixed_versions=["4.17.21"],
    )
    comp = Component(name="lodash", version="4.17.19", ecosystem="npm")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        verdict=Verdict.POTENTIALLY_AFFECTED,
        applicability_status=ApplicabilityStatus.AFFECTED,
    )

    service = ReachabilityService()
    findings, _evidence, _graph = service.analyze_findings(repo_path, [finding])

    assert len(findings) == 1
    res = findings[0].reachability
    assert res is not None
    assert res.status == ReachabilityState.UNKNOWN
    assert res.uncertainty_reason is not None
    assert "Dynamic" in res.uncertainty_reason or "computed" in res.uncertainty_reason.lower()


def test_fixture_4_multi_hop() -> None:
    """Fixture 4: Multi-hop invocation through local helper module produces REACHABLE."""
    repo_path = FIXTURES_DIR / "multi_hop"

    vuln = Vulnerability(
        id="GHSA-29mw-wpgm-hmr9",
        summary="Prototype Pollution in lodash.template",
        vulnerable_symbols=["template"],
        affected_ranges=["< 4.17.21"],
        fixed_versions=["4.17.21"],
    )
    comp = Component(name="lodash", version="4.17.19", ecosystem="npm")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        verdict=Verdict.POTENTIALLY_AFFECTED,
        applicability_status=ApplicabilityStatus.AFFECTED,
    )

    service = ReachabilityService()
    findings, _evidence, _graph = service.analyze_findings(repo_path, [finding])

    assert len(findings) == 1
    res = findings[0].reachability
    assert res is not None
    assert res.status == ReachabilityState.REACHABLE
    assert res.target_symbol == "template"
    assert res.entry_point is not None
    assert res.call_site is not None
    assert "src/utils/template_helper.js:4" in res.call_site
    # Verify evidence path has steps spanning route and helper
    assert len(res.evidence_path) >= 2


def test_fixture_5_no_symbol_data() -> None:
    """Fixture 5: Advisory providing no usable vulnerable symbol data produces UNKNOWN (no invented symbols)."""
    repo_path = FIXTURES_DIR / "no_symbol_data"

    vuln = Vulnerability(
        id="GHSA-xvch-5gv4-984h",
        summary="Prototype Pollution in minimist",
        vulnerable_symbols=[],  # No symbol data from advisory
        affected_ranges=["< 0.2.1"],
        fixed_versions=["0.2.1"],
    )
    comp = Component(name="minimist", version="0.0.8", ecosystem="npm")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        verdict=Verdict.POTENTIALLY_AFFECTED,
        applicability_status=ApplicabilityStatus.AFFECTED,
    )

    service = ReachabilityService()
    findings, _evidence, _graph = service.analyze_findings(repo_path, [finding])

    assert len(findings) == 1
    res = findings[0].reachability
    assert res is not None
    assert res.status == ReachabilityState.UNKNOWN
    assert res.target_symbol is None
    assert res.uncertainty_reason is not None
    assert "no usable vulnerable symbol" in res.uncertainty_reason


def test_unimported_package_is_not_reachable() -> None:
    """Package present in manifest/lockfile but never imported anywhere is NOT_REACHABLE."""
    repo_path = FIXTURES_DIR / "direct_reachable"

    vuln = Vulnerability(
        id="GHSA-fake-id",
        summary="Some vulnerability in axios",
        vulnerable_symbols=["get"],
    )
    comp = Component(name="axios", version="0.21.1", ecosystem="npm")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        verdict=Verdict.POTENTIALLY_AFFECTED,
        applicability_status=ApplicabilityStatus.AFFECTED,
    )

    service = ReachabilityService()
    findings, _evidence, _graph = service.analyze_findings(repo_path, [finding])

    assert len(findings) == 1
    res = findings[0].reachability
    assert res is not None
    assert res.status == ReachabilityState.NOT_REACHABLE
    assert res.confidence >= 0.9


def test_generic_word_symbol_produces_unknown_reachability_not_not_reachable() -> None:
    """Regression test: when finding has generic word 'the' as vulnerable symbol, reachability is UNKNOWN (not NOT_REACHABLE)."""
    repo_path = FIXTURES_DIR / "direct_reachable"

    vuln = Vulnerability(
        id="GHSA-c2qf-rxjj-qqgw",
        summary="semver Regular Expression Denial of Service",
        vulnerable_symbols=["the"],  # Simulating stale or bad extraction
        affected_ranges=["< 5.7.2"],
    )
    comp = Component(name="semver", version="5.7.0", ecosystem="npm")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        verdict=Verdict.POTENTIALLY_AFFECTED,
        applicability_status=ApplicabilityStatus.AFFECTED,
    )

    service = ReachabilityService()
    findings, _evidence, _graph = service.analyze_findings(repo_path, [finding])

    assert len(findings) == 1
    res = findings[0].reachability
    assert res is not None
    # Crucial assertion: generic word 'the' must NEVER yield NOT_REACHABLE with target_symbol='the'
    assert res.status == ReachabilityState.UNKNOWN
    assert res.target_symbol is None
    assert res.uncertainty_reason is not None
    assert "no usable vulnerable symbol" in res.uncertainty_reason

