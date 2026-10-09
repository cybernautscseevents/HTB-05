"""Integration tests for Phase 7 Dynamic Probe Planning API endpoints."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from acsa.api.app import app
from acsa.probe.models import ProbeEvaluationStatus, ProbeType
from acsa.verdict.vocabulary import Verdict

client = TestClient(app)
FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "phase4"


@patch("acsa.vulnerability.service.OSVClient")
def test_api_probe_plan_endpoint(mock_client_cls: MagicMock) -> None:
    """Test POST /api/v1/probes/plan produces structured ProbePlanReport for unknown/uncertain fixtures."""
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
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

    # Fixture 4 has unknown dynamic flow
    target = FIXTURES_DIR / "unknown_dynamic_flow"
    response = client.post(
        "/api/v1/probes/plan",
        json={"repository_path": str(target)},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["repository_path"] == str(target)
    assert data["total_unknown_findings"] >= 1
    assert data["total_probes_generated"] >= 1
    assert len(data["probes"]) >= 1

    probe = data["probes"][0]
    assert probe["probe_type"] in (
        ProbeType.HTTP_INPUT_TO_SINK.value,
        ProbeType.SYMBOL_INVOCATION.value,
    )
    assert probe["target_component"] == "lodash"
    assert "uncertainty_reason" in probe
    assert "missing_evidence" in probe
    assert "required_observation" in probe
    assert "safety_constraints" in probe
    assert len(probe["safety_constraints"]) >= 4


def test_api_probe_plan_path_traversal_blocked() -> None:
    """Test POST /api/v1/probes/plan blocks path traversal attacks."""
    response = client.post(
        "/api/v1/probes/plan",
        json={"repository_path": "../../../../../etc/passwd"},
    )
    assert response.status_code in (400, 404)


def test_api_probe_evaluate_endpoint() -> None:
    """Test POST /api/v1/probes/evaluate evaluates empirical observation and returns ProbeEvaluation."""
    probe_payload = {
        "probe_id": "probe-test-123",
        "finding_id": "finding-test-456",
        "probe_type": "HTTP_INPUT_TO_SINK",
        "target_component": "lodash",
        "target_symbol": "template",
        "entry_point": "POST /render",
        "input_source": "req.body.template",
        "uncertainty_reason": "Dynamic helper propagation",
        "missing_evidence": "Runtime observation of data flow",
        "required_observation": "Observe req.body.template reaching lodash.template",
        "success_condition": "Execution of template with body argument observed",
        "failure_condition": "Request completes without template invocation",
        "safety_constraints": ["Do not execute untrusted scripts"],
        "expected_verdict_if_confirmed": "PROVEN_EXPOSURE",
        "expected_verdict_if_not_confirmed": "PROVEN_AFFECTED",
        "priority_rank": 1,
        "status": "PENDING",
        "created_at": "2026-10-09T00:00:00Z",
        "metadata": {},
    }

    obs_payload = {
        "probe_id": "probe-test-123",
        "finding_id": "finding-test-456",
        "observed": True,
        "evidence_payload": {"trace": "req.body.template -> lodash.template"},
        "observed_at": "2026-10-09T00:01:00Z",
        "observer_notes": "Runtime trace captured during integration test run",
    }

    response = client.post(
        "/api/v1/probes/evaluate",
        json={
            "probe": probe_payload,
            "observation": obs_payload,
            "original_verdict": "UNKNOWN",
        },
    )

    assert response.status_code == 200
    eval_data = response.json()

    assert eval_data["probe_id"] == "probe-test-123"
    assert eval_data["finding_id"] == "finding-test-456"
    assert eval_data["evaluation_status"] == ProbeEvaluationStatus.CONFIRMED.value
    assert eval_data["original_verdict"] == Verdict.UNKNOWN.value
    assert eval_data["resolved_verdict"] == Verdict.PROVEN_EXPOSURE.value
    assert "CONFIRMED" in eval_data["rationale"]
