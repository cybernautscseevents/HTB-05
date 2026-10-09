"""Unit tests for Evidence models and provenance sources."""

import pytest
from pydantic import ValidationError

from acsa.evidence.models import Evidence, EvidenceEdge, EvidenceNode, EvidenceSource


def test_evidence_source_enum_members() -> None:
    """Verify supported evidence sources."""
    assert EvidenceSource.PACKAGE_JSON.value == "package_json"
    assert EvidenceSource.PACKAGE_LOCK.value == "package_lock"
    assert EvidenceSource.CYCLONEDX_SBOM.value == "cyclonedx_sbom"
    assert EvidenceSource.SPDX_SBOM.value == "spdx_sbom"
    assert EvidenceSource.SOURCE_AST.value == "source_ast"
    assert EvidenceSource.CALL_GRAPH.value == "call_graph"
    assert EvidenceSource.DYNAMIC_PROBE.value == "dynamic_probe"


def test_evidence_model_validation() -> None:
    """Verify Evidence model attributes and defaults."""
    ev = Evidence(
        source=EvidenceSource.SOURCE_AST,
        description="Observed require('lodash/template') in server.js:14",
        confidence=0.95,
        location="server.js:14",
    )
    assert ev.confidence == 0.95
    assert ev.source == EvidenceSource.SOURCE_AST
    assert ev.id is not None


def test_evidence_confidence_bounds() -> None:
    """Confidence must strictly be between 0.0 and 1.0."""
    with pytest.raises(ValidationError):
        Evidence(
            source=EvidenceSource.MANUAL_ASSERTION,
            description="Invalid confidence",
            confidence=1.5,
        )

    with pytest.raises(ValidationError):
        Evidence(
            source=EvidenceSource.MANUAL_ASSERTION,
            description="Negative confidence",
            confidence=-0.1,
        )


def test_evidence_node_and_edge_models() -> None:
    """Verify node and edge model definitions."""
    node = EvidenceNode(
        id="app.js:evalCode",
        node_type="app_function",
        label="evalCode",
        properties={"file": "app.js", "line": 42},
    )
    assert node.id == "app.js:evalCode"
    assert node.properties["line"] == 42

    edge = EvidenceEdge(
        source="app.js:evalCode",
        target="vm2:NodeVM",
        relationship="instantiates",
        weight=1.0,
    )
    assert edge.source == "app.js:evalCode"
    assert edge.relationship == "instantiates"
