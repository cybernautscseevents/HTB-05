"""Pytest configuration and behavioral test fixtures."""

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from acsa.api.app import app
from acsa.evidence.graph import EvidenceGraph
from acsa.evidence.models import EvidenceEdge, EvidenceNode


@pytest.fixture
def api_client() -> Generator[TestClient, None, None]:
    """Test client for ACSA FastAPI application."""
    with TestClient(app) as client:
        yield client


@pytest.fixture
def sample_graph() -> EvidenceGraph:
    """Fixture providing a minimal directed graph for testing graph algorithms."""
    graph = EvidenceGraph()
    n1 = EvidenceNode(id="entry", node_type="entry_point", label="POST /api/upload")
    n2 = EvidenceNode(id="handler", node_type="route_handler", label="handleUpload")
    n3 = EvidenceNode(id="lib_call", node_type="app_function", label="processData")
    n4 = EvidenceNode(id="vuln_sym", node_type="vulnerable_symbol", label="template.compile")

    graph.add_node(n1)
    graph.add_node(n2)
    graph.add_node(n3)
    graph.add_node(n4)

    graph.add_edge(EvidenceEdge(source="entry", target="handler", relationship="routes_to"))
    graph.add_edge(EvidenceEdge(source="handler", target="lib_call", relationship="calls"))
    graph.add_edge(EvidenceEdge(source="lib_call", target="vuln_sym", relationship="invokes"))

    return graph
