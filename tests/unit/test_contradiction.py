"""Unit tests for Contradiction and TrustAssessment models (Novelty 3)."""

import pytest
from pydantic import ValidationError

from acsa.evidence.models import EvidenceSource
from acsa.inventory.models import Contradiction, TrustAssessment


def test_contradiction_model_creation() -> None:
    """Test modeling of conflicting package versions across sources."""
    contra = Contradiction(
        component_name="debug",
        field_name="version",
        conflicting_sources=[
            EvidenceSource.PACKAGE_JSON,
            EvidenceSource.PACKAGE_LOCK,
            EvidenceSource.CYCLONEDX_SBOM,
        ],
        source_values={
            "package_json": "^4.3.1",
            "package_lock": "4.3.4",
            "cyclonedx_sbom": "2.6.9",
        },
        description="Declared version specifier differs radically from generated SBOM component.",
        severity="high",
    )
    assert contra.component_name == "debug"
    assert contra.resolved is False
    assert contra.source_values["cyclonedx_sbom"] == "2.6.9"
    assert len(contra.conflicting_sources) == 3


def test_trust_assessment_score_bounds() -> None:
    """Trust score must strictly be between 0.0 and 1.0."""
    assessment = TrustAssessment(
        component_name="debug",
        trust_score=0.45,
        evaluated_sources=[EvidenceSource.PACKAGE_JSON, EvidenceSource.PACKAGE_LOCK],
        has_contradictions=True,
        confidence_summary="Discrepancy detected between lockfile and SBOM.",
    )
    assert assessment.trust_score == 0.45
    assert assessment.has_contradictions is True

    with pytest.raises(ValidationError):
        TrustAssessment(
            component_name="debug",
            trust_score=1.5,
            evaluated_sources=[],
            confidence_summary="Invalid",
        )
