"""Integration tests executing the complete ACSA pipeline across all 6 Phase 4 fixtures."""

from pathlib import Path
from unittest.mock import MagicMock

from acsa.context.service import ContextService
from acsa.evidence.graph import EvidenceGraph
from acsa.ingestion.service import IngestionService
from acsa.reachability.service import ReachabilityService
from acsa.verdict.service import EvidenceFusionService
from acsa.verdict.vocabulary import Verdict
from acsa.vulnerability.models import ApplicabilityStatus, VulnerabilityScanResult
from acsa.vulnerability.service import VulnerabilityService

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "phase4"


def run_pipeline_on_repo(
    repo_path: Path, mock_client: MagicMock
) -> tuple[VulnerabilityScanResult, EvidenceGraph]:
    """Helper to run the full 5-phase ACSA pipeline on a test repository."""
    ingest_service = IngestionService()
    ingest_result = ingest_service.ingest_repository(repo_path)

    vuln_service = VulnerabilityService(client=mock_client)
    scan_result = vuln_service.scan_inventory(
        ingest_result.inventory, repository_path=str(repo_path)
    )

    reach_service = ReachabilityService()
    findings_reach, reach_ev, graph = reach_service.analyze_findings(
        repo_path, scan_result.findings
    )

    ctx_service = ContextService()
    findings_ctx, ctx_ev = ctx_service.analyze_findings(
        repo_path, findings_reach, graph=graph
    )

    intermediate = scan_result.model_copy(
        update={
            "findings": findings_ctx,
            "evidence": list(scan_result.evidence) + reach_ev + ctx_ev,
            "reachability_evaluated": True,
            "context_evaluated": True,
        }
    )

    fusion_service = EvidenceFusionService()
    final_result = fusion_service.enrich_scan_result(intermediate, graph=graph)
    return final_result, graph


def test_fixture_1_confirmed_exposure() -> None:
    """Fixture 1: HTTP route -> request body template -> lodash.template produces PROVEN_EXPOSURE."""
    repo_path = FIXTURES_DIR / "confirmed_exposure"
    mock_client = MagicMock()
    mock_client.query_batch.return_value = {
        ("npm", "lodash", "4.17.19"): ["GHSA-29mw-wpgm-hmr9"]
    }
    mock_client.get_vulnerability.return_value = {
        "id": "GHSA-29mw-wpgm-hmr9",
        "summary": "Prototype Pollution in lodash",
        "affected": [
            {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
                "ecosystem_specific": {"affected_functions": ["template"]},
            }
        ],
    }

    result, graph = run_pipeline_on_repo(repo_path, mock_client)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.verdict == Verdict.PROVEN_EXPOSURE
    assert f.context is not None
    assert f.context.source is not None
    assert f.context.source.expression == "req.body.template"
    assert f.context.entry_point == "POST /render"
    assert "lodash.template" in (f.context.sink or "")
    assert result.proven_exposure_count == 1

    # Verify full evidence path in EvidenceGraph
    verdict_node_id = f"verdict:{f.id}"
    assert graph.get_node(verdict_node_id) is not None
    assert graph.has_path("art:package-lock.json", verdict_node_id)


def test_fixture_2_reachable_no_attacker_control() -> None:
    """Fixture 2: Reachable from route with static constant produces POTENTIALLY_AFFECTED."""
    repo_path = FIXTURES_DIR / "reachable_no_attacker_control"
    mock_client = MagicMock()
    mock_client.query_batch.return_value = {
        ("npm", "lodash", "4.17.19"): ["GHSA-29mw-wpgm-hmr9"]
    }
    mock_client.get_vulnerability.return_value = {
        "id": "GHSA-29mw-wpgm-hmr9",
        "summary": "Prototype Pollution in lodash",
        "affected": [
            {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
                "ecosystem_specific": {"affected_functions": ["template"]},
            }
        ],
    }

    result, _graph = run_pipeline_on_repo(repo_path, mock_client)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.verdict == Verdict.POTENTIALLY_AFFECTED
    assert f.context is not None
    assert f.context.status.value == "NOT_ESTABLISHED"
    assert result.potentially_affected_count == 1


def test_fixture_3_affected_symbol_not_reachable() -> None:
    """Fixture 3: Affected package bundled but vulnerable template() not called produces PROVEN_AFFECTED."""
    repo_path = FIXTURES_DIR / "affected_symbol_not_reachable"
    mock_client = MagicMock()
    mock_client.query_batch.return_value = {
        ("npm", "lodash", "4.17.19"): ["GHSA-29mw-wpgm-hmr9"]
    }
    mock_client.get_vulnerability.return_value = {
        "id": "GHSA-29mw-wpgm-hmr9",
        "summary": "Prototype Pollution in lodash",
        "affected": [
            {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
                "ecosystem_specific": {"affected_functions": ["template"]},
            }
        ],
    }

    result, _graph = run_pipeline_on_repo(repo_path, mock_client)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.verdict == Verdict.PROVEN_AFFECTED
    assert f.reachability is not None
    assert f.reachability.status.value == "NOT_REACHABLE"
    assert result.proven_affected_count == 1


def test_fixture_4_unknown_dynamic_flow() -> None:
    """Fixture 4: Dynamic property access on request produces UNKNOWN."""
    repo_path = FIXTURES_DIR / "unknown_dynamic_flow"
    mock_client = MagicMock()
    mock_client.query_batch.return_value = {
        ("npm", "lodash", "4.17.19"): ["GHSA-29mw-wpgm-hmr9"]
    }
    mock_client.get_vulnerability.return_value = {
        "id": "GHSA-29mw-wpgm-hmr9",
        "summary": "Prototype Pollution in lodash",
        "affected": [
            {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
                "ecosystem_specific": {"affected_functions": ["template"]},
            }
        ],
    }

    result, _graph = run_pipeline_on_repo(repo_path, mock_client)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.verdict == Verdict.UNKNOWN
    assert f.context is not None
    assert f.context.status.value == "UNKNOWN"
    assert "Dynamic property access" in (f.context.uncertainty_reason or "")
    assert "Runtime observation" in (f.context.missing_evidence or "")
    assert "Dynamic property access" in (f.uncertainty_reason or "")
    assert "Runtime observation" in (f.missing_evidence or "")
    assert result.unknown_count == 1


def test_fixture_5_contradictory_inventory() -> None:
    """Fixture 5: lockfile 4.17.21 (safe) vs sbom 4.17.19 (affected) produces CONTRADICTORY."""
    repo_path = FIXTURES_DIR / "contradictory_inventory"
    mock_client = MagicMock()
    # Batch query receives both 4.17.21 and 4.17.19
    mock_client.query_batch.return_value = {
        ("npm", "lodash", "4.17.21"): ["GHSA-29mw-wpgm-hmr9"],
        ("npm", "lodash", "4.17.19"): ["GHSA-29mw-wpgm-hmr9"],
    }
    mock_client.get_vulnerability.return_value = {
        "id": "GHSA-29mw-wpgm-hmr9",
        "summary": "Prototype Pollution in lodash",
        "affected": [
            {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
                "ecosystem_specific": {"affected_functions": ["template"]},
            }
        ],
    }

    result, _graph = run_pipeline_on_repo(repo_path, mock_client)
    assert len(result.findings) >= 2
    for f in result.findings:
        assert f.verdict == Verdict.CONTRADICTORY
        assert "Contradictory inventory observations" in (f.notes or "")
    assert result.contradictory_count >= 2


def test_fixture_6_version_not_affected() -> None:
    """Fixture 6: lodash 4.17.21 fixed version produces PROVEN_NOT_AFFECTED."""
    repo_path = FIXTURES_DIR / "version_not_affected"
    mock_client = MagicMock()
    mock_client.query_batch.return_value = {
        ("npm", "lodash", "4.17.21"): ["GHSA-29mw-wpgm-hmr9"],
    }
    mock_client.get_vulnerability.return_value = {
        "id": "GHSA-29mw-wpgm-hmr9",
        "summary": "Prototype Pollution in lodash",
        "affected": [
            {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
                "ecosystem_specific": {"affected_functions": ["template"]},
            }
        ],
    }

    result, _graph = run_pipeline_on_repo(repo_path, mock_client)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.applicability_status == ApplicabilityStatus.NOT_AFFECTED
    assert f.verdict == Verdict.PROVEN_NOT_AFFECTED
    assert f.verdict.is_safe
    assert result.proven_not_affected_count == 1
