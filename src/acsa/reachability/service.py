import logging
from pathlib import Path
from typing import TYPE_CHECKING

from acsa.core.symbols import is_defensible_symbol
from acsa.evidence.graph import EvidenceGraph
from acsa.evidence.models import Evidence
from acsa.reachability.discovery import SourceDiscovery
from acsa.reachability.engine import ReachabilityEngine
from acsa.reachability.graph_builder import ReachabilityGraphBuilder
from acsa.reachability.local_resolution import LocalModuleResolver
from acsa.reachability.models import ParsedSourceFile
from acsa.reachability.parser import JavaScriptSourceParser

if TYPE_CHECKING:
    from acsa.vulnerability.models import Finding, VulnerabilityScanResult

logger = logging.getLogger(__name__)


class ReachabilityService:
    """Orchestrates source discovery, static parsing, call-graph construction, and reachability determination."""

    def __init__(
        self,
        discovery: SourceDiscovery | None = None,
        parser: JavaScriptSourceParser | None = None,
    ) -> None:
        self.discovery = discovery or SourceDiscovery()
        self.parser = parser or JavaScriptSourceParser()

    def analyze_findings(
        self,
        repository_path: Path,
        findings: list[Finding],
    ) -> tuple[list[Finding], list[Evidence], EvidenceGraph]:
        """Execute reachability analysis over a list of findings against repository source code.

        Returns:
            Tuple of (enriched_findings, new_evidence_records, constructed_evidence_graph)
        """
        # 1. Discover all source files
        discovered_rel_files = self.discovery.discover_source_files(repository_path)
        logger.debug("Discovered %d source files for reachability analysis", len(discovered_rel_files))

        # 2. Parse source files safely
        parsed_files: dict[str, ParsedSourceFile] = {}
        for rel_file in discovered_rel_files:
            content = self.discovery.read_source_content(repository_path, rel_file)
            parsed = self.parser.parse_source(rel_file, content)
            parsed_files[rel_file] = parsed

        # 3. Setup local resolver and graph builder
        local_resolver = LocalModuleResolver(set(discovered_rel_files))
        graph_builder = ReachabilityGraphBuilder(local_resolver)

        # Collect target vulnerable symbols per package (filtering non-defensible prose)
        targets: dict[str, list[str]] = {}
        for f in findings:
            if f.vulnerability.vulnerable_symbols:
                valid_syms = [s for s in f.vulnerability.vulnerable_symbols if is_defensible_symbol(s)]
                if valid_syms:
                    targets.setdefault(f.component.name, []).extend(valid_syms)
        # Deduplicate
        for k in targets:
            targets[k] = list(dict.fromkeys(targets[k]))

        # 4. Construct EvidenceGraph
        graph = graph_builder.build_graph(parsed_files, targets)

        # 5. Evaluate reachability for each finding
        engine = ReachabilityEngine(local_resolver)
        enriched_findings: list[Finding] = []
        new_evidence: list[Evidence] = []

        for f in findings:
            analysis, ev_list = engine.evaluate_reachability(f, parsed_files, graph)

            # Combine evidence IDs
            combined_evidence_ids = list(f.evidence_ids)
            for ev in ev_list:
                if ev.id not in combined_evidence_ids:
                    combined_evidence_ids.append(ev.id)
                new_evidence.append(ev)

            updated_finding = f.model_copy(
                update={
                    "reachability": analysis,
                    "evidence_ids": combined_evidence_ids,
                }
            )
            enriched_findings.append(updated_finding)

        return enriched_findings, new_evidence, graph

    def enrich_scan_result(
        self,
        scan_result: VulnerabilityScanResult,
        repository_path: Path,
    ) -> VulnerabilityScanResult:
        """Enrich a Phase 2 VulnerabilityScanResult with Phase 3 reachability intelligence."""
        enriched_findings, new_evidence, _graph = self.analyze_findings(
            repository_path=repository_path,
            findings=scan_result.findings,
        )

        all_evidence = list(scan_result.evidence) + new_evidence

        return scan_result.model_copy(
            update={
                "findings": enriched_findings,
                "evidence": all_evidence,
                "reachability_evaluated": True,
            }
        )
