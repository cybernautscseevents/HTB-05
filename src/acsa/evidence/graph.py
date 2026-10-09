"""EvidenceGraph representation for reachability, context, and exposure paths."""

import hashlib
import json
from collections import deque
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from acsa.evidence.models import EvidenceEdge, EvidenceNode


class EvidenceGraph(BaseModel):
    """Directed graph model representing relationships between application entry points,

    code components, dependencies, and vulnerable symbols.
    """

    model_config = ConfigDict(extra="forbid")

    nodes: dict[str, EvidenceNode] = Field(
        default_factory=dict,
        description="Lookup mapping of node ID to EvidenceNode",
    )
    edges: list[EvidenceEdge] = Field(
        default_factory=list,
        description="Collection of directed edges connecting evidence nodes",
    )

    def add_node(self, node: EvidenceNode) -> None:
        """Add an EvidenceNode to the graph."""
        self.nodes[node.id] = node

    def add_edge(self, edge: EvidenceEdge) -> None:
        """Add an EvidenceEdge connecting existing or planned nodes."""
        self.edges.append(edge)

    def get_node(self, node_id: str) -> EvidenceNode | None:
        """Retrieve a node by its identifier."""
        return self.nodes.get(node_id)

    def get_outgoing_edges(self, node_id: str) -> list[EvidenceEdge]:
        """Return all edges originating from node_id."""
        return [edge for edge in self.edges if edge.source == node_id]

    def get_incoming_edges(self, node_id: str) -> list[EvidenceEdge]:
        """Return all edges terminating at node_id."""
        return [edge for edge in self.edges if edge.target == node_id]

    def has_path(self, source_id: str, target_id: str) -> bool:
        """Check via BFS whether a directed path exists from source_id to target_id."""
        if source_id == target_id:
            return source_id in self.nodes

        visited: set[str] = {source_id}
        queue: deque[str] = deque([source_id])

        # Precompute adjacency list for fast traversal
        adj: dict[str, list[str]] = {}
        for edge in self.edges:
            adj.setdefault(edge.source, []).append(edge.target)

        while queue:
            curr = queue.popleft()
            for neighbor in adj.get(curr, []):
                if neighbor == target_id:
                    return True
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        return False

    def find_all_paths(
        self, source_id: str, target_id: str, max_depth: int = 15
    ) -> list[list[str]]:
        """Find all directed simple paths from source_id to target_id up to max_depth."""
        adj: dict[str, list[str]] = {}
        for edge in self.edges:
            adj.setdefault(edge.source, []).append(edge.target)

        paths: list[list[str]] = []

        def dfs(current: str, target: str, current_path: list[str], visited: set[str]) -> None:
            if len(current_path) > max_depth:
                return
            if current == target:
                paths.append(list(current_path))
                return
            for neighbor in adj.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    current_path.append(neighbor)
                    dfs(neighbor, target, current_path, visited)
                    current_path.pop()
                    visited.remove(neighbor)

        visited_set: set[str] = {source_id}
        dfs(source_id, target_id, [source_id], visited_set)
        return paths

    def digest(self) -> str:
        """Compute a deterministic SHA-256 fingerprint of the graph structure.

        Used in Proof-Carrying Remediation to generate cryptographic before/after digests.
        """
        sorted_nodes = sorted(
            [{"id": n.id, "type": n.node_type, "label": n.label} for n in self.nodes.values()],
            key=lambda x: x["id"],
        )
        sorted_edges = sorted(
            [{"src": e.source, "dst": e.target, "rel": e.relationship} for e in self.edges],
            key=lambda x: (x["src"], x["dst"], x["rel"]),
        )
        payload: dict[str, Any] = {
            "nodes": sorted_nodes,
            "edges": sorted_edges,
        }
        canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def compute_deterministic_digest(self) -> str:
        """Alias for digest() for deterministic cryptographic fingerprinting."""
        return self.digest()

    @property
    def node_count(self) -> int:
        """Return the total number of nodes."""
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        """Return the total number of edges."""
        return len(self.edges)
