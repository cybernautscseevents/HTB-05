"""Unit tests for ACSA foundation domain models."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from acsa.evidence.models import EvidenceSource
from acsa.ingestion.models import Repository, RepositorySnapshot
from acsa.inventory.models import Component, Dependency
from acsa.verdict.vocabulary import Verdict
from acsa.verification.models import ProofArtifact, VerificationResult
from acsa.vulnerability.models import Finding, Vulnerability


def test_repository_model_instantiation() -> None:
    """Test Repository model with standard and default attributes."""
    repo = Repository(name="acme/service", default_branch="main", ecosystem="npm")
    assert repo.name == "acme/service"
    assert repo.ecosystem == "npm"
    assert repo.default_branch == "main"
    assert repo.id is not None


def test_repository_snapshot_model() -> None:
    """Test RepositorySnapshot model attributes."""
    now = datetime.now(UTC)
    snapshot = RepositorySnapshot(
        repository_id="repo-123",
        commit_hash="abc123def456",
        snapshot_path="/tmp/snapshots/repo-123",
        created_at=now,
    )
    assert snapshot.repository_id == "repo-123"
    assert snapshot.commit_hash == "abc123def456"
    assert snapshot.snapshot_path == "/tmp/snapshots/repo-123"


def test_component_and_dependency_models() -> None:
    """Test Component and Dependency models validation."""
    comp = Component(
        name="semver",
        version="7.5.2",
        purl="pkg:npm/semver@7.5.2",
        ecosystem="npm",
        source_provenance=[EvidenceSource.PACKAGE_JSON, EvidenceSource.PACKAGE_LOCK],
    )
    assert comp.name == "semver"
    assert comp.version == "7.5.2"
    assert EvidenceSource.PACKAGE_LOCK in comp.source_provenance

    dep = Dependency(
        name="semver",
        version_constraint="^7.5.0",
        resolved_version="7.5.2",
        dependency_type="direct",
    )
    assert dep.name == "semver"
    assert dep.resolved_version == "7.5.2"


def test_vulnerability_and_finding_models() -> None:
    """Test Vulnerability and Finding models validation."""
    vuln = Vulnerability(
        id="GHSA-test-1234",
        summary="Prototype pollution in test-lib",
        affected_ranges=["< 1.2.3"],
        fixed_versions=["1.2.3"],
        vulnerable_symbols=["merge", "clone"],
    )
    assert vuln.id == "GHSA-test-1234"
    assert "merge" in vuln.vulnerable_symbols

    comp = Component(name="test-lib", version="1.2.0")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        verdict=Verdict.POTENTIALLY_AFFECTED,
        confidence=0.8,
    )
    assert finding.verdict == Verdict.POTENTIALLY_AFFECTED
    assert finding.confidence == 0.8
    assert finding.vulnerability.id == "GHSA-test-1234"


def test_verification_result_and_proof_artifact_models() -> None:
    """Test VerificationResult and ProofArtifact models."""
    res = VerificationResult(
        finding_id="find-1",
        candidate_id="cand-1",
        prior_verdict=Verdict.PROVEN_EXPOSURE,
        post_verdict=Verdict.PROVEN_NOT_AFFECTED,
        path_closed=True,
    )
    assert res.path_closed is True
    assert res.prior_verdict == Verdict.PROVEN_EXPOSURE
    assert res.post_verdict == Verdict.PROVEN_NOT_AFFECTED

    proof = ProofArtifact(
        verification_result_id=res.id,
        before_evidence_graph_digest="a" * 64,
        after_evidence_graph_digest="b" * 64,
        proof_summary="Verified call path severed after patch.",
    )
    assert proof.is_verified is True
    assert proof.before_evidence_graph_digest == "a" * 64


def test_extra_fields_forbidden() -> None:
    """Ensure strict validation forbids undeclared fields on domain models."""
    with pytest.raises(ValidationError):
        Repository(name="foo", unexpected_field="disallowed")  # type: ignore[call-arg]
