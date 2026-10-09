"""Unit tests for RemediationCandidate and RemediationDecision models (Novelty 2)."""

import pytest
from pydantic import ValidationError

from acsa.remediation.models import RemediationCandidate, RemediationDecision


def test_remediation_candidate_creation() -> None:
    """Verify attributes of a remediation candidate."""
    cand = RemediationCandidate(
        finding_ids=["finding-101"],
        strategy_type="minimal_patch",
        target_component="minimist",
        current_version="1.2.5",
        proposed_version="1.2.6",
        blast_radius_score=0.15,
        breaking_change_risk="low",
        description="Patch regex without changing public API surface.",
    )
    assert cand.blast_radius_score == 0.15
    assert cand.strategy_type == "minimal_patch"
    assert cand.target_component == "minimist"


def test_blast_radius_score_bounds() -> None:
    """Blast radius score must strictly be between 0.0 and 1.0."""
    with pytest.raises(ValidationError):
        RemediationCandidate(
            finding_ids=["f1"],
            strategy_type="major_upgrade",
            target_component="lib",
            current_version="1.0.0",
            blast_radius_score=-0.2,
            description="Invalid blast score",
        )


def test_minimum_blast_radius_selection_behavior() -> None:
    """Demonstrate selection of lowest blast-radius fix between alternative options."""
    patch_fix = RemediationCandidate(
        finding_ids=["f1"],
        strategy_type="minimal_patch",
        target_component="express",
        current_version="4.17.1",
        proposed_version="4.17.2",
        blast_radius_score=0.1,
        breaking_change_risk="low",
        description="Point release closing prototype injection.",
    )
    major_upgrade = RemediationCandidate(
        finding_ids=["f1"],
        strategy_type="major_upgrade",
        target_component="express",
        current_version="4.17.1",
        proposed_version="5.0.0",
        blast_radius_score=0.85,
        breaking_change_risk="high",
        description="Major version rewrite requiring application router changes.",
    )

    candidates = [major_upgrade, patch_fix]
    # Smallest blast radius fix chosen
    optimal = min(candidates, key=lambda c: c.blast_radius_score)
    assert optimal.id == patch_fix.id
    assert optimal.strategy_type == "minimal_patch"

    decision = RemediationDecision(
        finding_id="f1",
        selected_candidate=optimal,
        rationale="Selected patch fix with lowest blast radius (0.10 vs 0.85).",
        approved=True,
    )
    assert decision.selected_candidate is not None
    assert decision.selected_candidate.blast_radius_score == 0.1
