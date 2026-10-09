"""Unit tests for EvidenceGraph traversal, pathfinding, and deterministic hashing."""

from acsa.evidence.graph import EvidenceGraph
from acsa.evidence.models import EvidenceEdge, EvidenceNode


def test_evidence_graph_add_and_counts(sample_graph: EvidenceGraph) -> None:
    """Verify node and edge counts in sample graph."""
    assert sample_graph.node_count == 4
    assert sample_graph.edge_count == 3
    assert sample_graph.get_node("entry") is not None
    assert sample_graph.get_node("nonexistent") is None


def test_graph_outgoing_and_incoming_edges(sample_graph: EvidenceGraph) -> None:
    """Verify retrieval of directional edges."""
    outgoing = sample_graph.get_outgoing_edges("handler")
    assert len(outgoing) == 1
    assert outgoing[0].target == "lib_call"

    incoming = sample_graph.get_incoming_edges("vuln_sym")
    assert len(incoming) == 1
    assert incoming[0].source == "lib_call"


def test_has_path_bfs_reachability(sample_graph: EvidenceGraph) -> None:
    """Verify directed reachability between entry point and vulnerable symbol."""
    assert sample_graph.has_path("entry", "vuln_sym") is True
    assert sample_graph.has_path("entry", "lib_call") is True
    # Reverse direction is false
    assert sample_graph.has_path("vuln_sym", "entry") is False


def test_find_all_paths_enumeration(sample_graph: EvidenceGraph) -> None:
    """Verify complete path trace from entry point to vulnerable symbol."""
    paths = sample_graph.find_all_paths("entry", "vuln_sym")
    assert len(paths) == 1
    assert paths[0] == ["entry", "handler", "lib_call", "vuln_sym"]


def test_path_severance_detection() -> None:
    """Demonstrate how graph reflects severed call paths (core to Proof-Carrying Remediation)."""
    graph = EvidenceGraph()
    n1 = EvidenceNode(id="route", node_type="entry_point", label="/api")
    n2 = EvidenceNode(id="sanitizer", node_type="guard", label="validateInput")
    n3 = EvidenceNode(id="vuln", node_type="vulnerable_symbol", label="eval")

    graph.add_node(n1)
    graph.add_node(n2)
    graph.add_node(n3)

    # Initial exposed path
    graph.add_edge(EvidenceEdge(source="route", target="vuln", relationship="direct_call"))
    assert graph.has_path("route", "vuln") is True

    # Sever the path
    remediated_graph = EvidenceGraph()
    remediated_graph.add_node(n1)
    remediated_graph.add_node(n2)
    remediated_graph.add_node(n3)
    remediated_graph.add_edge(EvidenceEdge(source="route", target="sanitizer", relationship="calls"))
    assert remediated_graph.has_path("route", "vuln") is False


def test_graph_deterministic_digest() -> None:
    """Verify that digest() produces reproducible SHA-256 independent of insertion order."""
    g1 = EvidenceGraph()
    g1.add_node(EvidenceNode(id="A", node_type="fn", label="FuncA"))
    g1.add_node(EvidenceNode(id="B", node_type="fn", label="FuncB"))
    g1.add_edge(EvidenceEdge(source="A", target="B", relationship="calls"))

    g2 = EvidenceGraph()
    # Insert in reverse order
    g2.add_node(EvidenceNode(id="B", node_type="fn", label="FuncB"))
    g2.add_node(EvidenceNode(id="A", node_type="fn", label="FuncA"))
    g2.add_edge(EvidenceEdge(source="A", target="B", relationship="calls"))

    assert g1.digest() == g2.digest()
    assert len(g1.digest()) == 64

    # Altering the graph changes the digest
    g3 = EvidenceGraph()
    g3.add_node(EvidenceNode(id="A", node_type="fn", label="FuncA"))
    assert g3.digest() != g1.digest()
