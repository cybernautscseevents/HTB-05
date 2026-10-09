import logging
from typing import TYPE_CHECKING

from acsa.core.symbols import is_defensible_symbol
from acsa.evidence.graph import EvidenceGraph
from acsa.evidence.models import Evidence, EvidenceSource
from acsa.reachability.local_resolution import LocalModuleResolver
from acsa.reachability.models import (
    ParsedSourceFile,
    ReachabilityAnalysis,
    ReachabilityState,
)

if TYPE_CHECKING:
    from acsa.vulnerability.models import Finding

logger = logging.getLogger(__name__)


class ReachabilityEngine:
    """Evaluates whether an application's executable paths can reach a vulnerable package/symbol."""

    def __init__(self, local_resolver: LocalModuleResolver) -> None:
        self.local_resolver = local_resolver

    def evaluate_reachability(
        self,
        finding: Finding,
        parsed_files: dict[str, ParsedSourceFile],
        graph: EvidenceGraph,
    ) -> tuple[ReachabilityAnalysis, list[Evidence]]:
        """Evaluate static reachability for an individual vulnerability finding.

        Returns:
            Tuple of (ReachabilityAnalysis, list[Evidence])
        """
        pkg_name = finding.component.name
        # Sanitize and validate vulnerable symbols: generic words like 'the' must never be accepted
        raw_symbols = finding.vulnerability.vulnerable_symbols or []
        vulnerable_symbols = [s for s in raw_symbols if is_defensible_symbol(s)]

        # 1. Applicability prerequisite check
        if str(finding.applicability_status) != "AFFECTED":
            return (
                ReachabilityAnalysis(
                    status=ReachabilityState.NOT_REACHABLE,
                    target_symbol=vulnerable_symbols[0] if vulnerable_symbols else None,
                    uncertainty_reason="Advisory is not applicable to installed version",
                    confidence=1.0,
                ),
                [],
            )

        # 2. Advisory symbol availability check
        # Invariant: If the advisory does NOT provide a defensible vulnerable symbol, do not invent one.
        # Generic words like 'the' or keywords must NEVER be treated as vulnerable symbols.
        # REACHABILITY = UNKNOWN (UNKNOWN != SAFE)
        if not vulnerable_symbols:
            return (
                ReachabilityAnalysis(
                    status=ReachabilityState.UNKNOWN,
                    target_symbol=None,
                    uncertainty_reason="Advisory provides no usable vulnerable symbol/function data",
                    confidence=0.5,
                ),
                [],
            )

        # 3. Check if the package is imported anywhere in the repository
        importing_files: list[str] = []
        for file_path, parsed in parsed_files.items():
            for imp in parsed.imports:
                if not imp.is_local:
                    if imp.module_name == pkg_name or imp.module_name.startswith(f"{pkg_name}/"):
                        if file_path not in importing_files:
                            importing_files.append(file_path)

        if not importing_files:
            # Package is in lockfile / dependencies, but never imported in source code
            return (
                ReachabilityAnalysis(
                    status=ReachabilityState.NOT_REACHABLE,
                    target_symbol=vulnerable_symbols[0],
                    confidence=0.95,
                    uncertainty_reason=None,
                    metadata={"imported": False, "importing_files": []},
                ),
                [],
            )

        # 4. Check for dynamic property access or reflection on this package
        for file_path in importing_files:
            parsed = parsed_files[file_path]
            # Check for dynamic calls on this package
            package_aliases: set[str] = set()
            for imp in parsed.imports:
                if (imp.module_name == pkg_name or imp.module_name.startswith(f"{pkg_name}/")) and imp.alias:
                    package_aliases.add(imp.alias)

            for cs in parsed.call_sites:
                if cs.is_dynamic and cs.callee_object in package_aliases:
                    reason = f"Dynamic computed property access on package object '{cs.callee_object}' at {cs.location}"
                    return (
                        ReachabilityAnalysis(
                            status=ReachabilityState.UNKNOWN,
                            target_symbol=vulnerable_symbols[0],
                            call_site=str(cs.location),
                            uncertainty_reason=reason,
                            confidence=0.4,
                            metadata={"dynamic_call": cs.raw_expression},
                        ),
                        [],
                    )

            if parsed.has_dynamic_constructs:
                for d_reason in parsed.dynamic_construct_reasons:
                    if pkg_name in d_reason or any(a in d_reason for a in package_aliases):
                        return (
                            ReachabilityAnalysis(
                                status=ReachabilityState.UNKNOWN,
                                target_symbol=vulnerable_symbols[0],
                                uncertainty_reason=d_reason,
                                confidence=0.4,
                            ),
                            [],
                        )

        # 5. Search for reachability path to any vulnerable symbol via EvidenceGraph
        entry_nodes = [
            n for n in graph.nodes.values() if n.node_type == "entry_point"
        ]

        # Prioritize concrete routes (POST, GET, etc.), http handlers, cli entries, middleware, then exports
        entry_nodes.sort(
            key=lambda n: (
                0 if n.properties.get("entry_type") == "route" else
                1 if n.properties.get("entry_type") == "http_handler" else
                2 if n.properties.get("entry_type") == "cli_entry" else
                3 if n.properties.get("entry_type") == "middleware" else 4
            )
        )

        for sym in vulnerable_symbols:
            sym_node_id = f"sym:{pkg_name}:{sym}"
            if sym_node_id not in graph.nodes:
                continue

            for ep_node in entry_nodes:
                if graph.has_path(ep_node.id, sym_node_id):
                    paths = graph.find_all_paths(ep_node.id, sym_node_id, max_depth=15)
                    if paths:
                        best_path = paths[0]
                        analysis, evidence = self._build_reachable_result(
                            finding=finding,
                            target_symbol=sym,
                            path_node_ids=best_path,
                            graph=graph,
                        )
                        return analysis, evidence

        # Also check direct file invocation if no formal entry points but direct call exists
        for sym in vulnerable_symbols:
            sym_node_id = f"sym:{pkg_name}:{sym}"
            if sym_node_id not in graph.nodes:
                continue
            for imp_file in importing_files:
                file_node_id = f"file:{imp_file}"
                if graph.has_path(file_node_id, sym_node_id):
                    paths = graph.find_all_paths(file_node_id, sym_node_id, max_depth=15)
                    if paths:
                        analysis, evidence = self._build_reachable_result(
                            finding=finding,
                            target_symbol=sym,
                            path_node_ids=paths[0],
                            graph=graph,
                        )
                        return analysis, evidence

        # 6. Package is imported, but no vulnerable symbol was called or imported
        return (
            ReachabilityAnalysis(
                status=ReachabilityState.NOT_REACHABLE,
                target_symbol=vulnerable_symbols[0],
                confidence=0.95,
                uncertainty_reason=None,
                metadata={
                    "imported": True,
                    "importing_files": importing_files,
                    "evaluated_symbols": vulnerable_symbols,
                },
            ),
            [],
        )

    def _build_reachable_result(
        self,
        finding: Finding,
        target_symbol: str,
        path_node_ids: list[str],
        graph: EvidenceGraph,
    ) -> tuple[ReachabilityAnalysis, list[Evidence]]:
        """Construct structured ReachabilityAnalysis and Evidence objects from a graph path."""
        entry_point_str: str | None = None
        call_site_str: str | None = None
        readable_steps: list[str] = []

        for node_id in path_node_ids:
            node = graph.get_node(node_id)
            if not node:
                continue

            if node.node_type == "entry_point":
                loc = f"{node.properties.get('file_path')}:{node.properties.get('line_number')}"
                entry_point_str = f"{loc} ({node.label})"
                readable_steps.append(f"{loc} ({node.label})")

            elif node.node_type == "source_file":
                readable_steps.append(f"{node.properties.get('file_path')}")

            elif node.node_type == "app_function":
                loc = f"{node.properties.get('file_path')}:{node.properties.get('line_number')}"
                readable_steps.append(f"{loc} ({node.label})")

            elif node.node_type == "dependency_call":
                loc = f"{node.properties.get('file_path')}:{node.properties.get('line_number')}"
                call_site_str = loc
                readable_steps.append(f"{loc} -> {node.label}")

            elif node.node_type == "vulnerable_symbol":
                readable_steps.append(f"{finding.component.name}.{node.label}()")

        # Deduplicate consecutive identical steps
        dedup_steps: list[str] = []
        for step in readable_steps:
            if not dedup_steps or dedup_steps[-1] != step:
                dedup_steps.append(step)

        # Generate verifiable Evidence objects
        ev_id = f"ev-reach-{finding.vulnerability.id}-{finding.component.name}"
        ev = Evidence(
            id=ev_id,
            source=EvidenceSource.CALL_GRAPH,
            description=(
                f"Static call graph proves executable path from entry point "
                f"'{entry_point_str}' to vulnerable symbol '{finding.component.name}.{target_symbol}()'"
            ),
            confidence=0.95,
            data={
                "vulnerability_id": finding.vulnerability.id,
                "component": finding.component.name,
                "version": finding.component.version,
                "vulnerable_symbol": target_symbol,
                "entry_point": entry_point_str,
                "call_site": call_site_str,
                "evidence_path": dedup_steps,
                "graph_digest": graph.digest(),
            },
            location=call_site_str or entry_point_str,
        )

        analysis = ReachabilityAnalysis(
            status=ReachabilityState.REACHABLE,
            target_symbol=target_symbol,
            entry_point=entry_point_str,
            call_site=call_site_str,
            evidence_path=dedup_steps,
            uncertainty_reason=None,
            confidence=0.95,
            evidence_ids=[ev.id],
            metadata={
                "graph_digest": graph.digest(),
                "node_count": len(path_node_ids),
            },
        )
        return analysis, [ev]
