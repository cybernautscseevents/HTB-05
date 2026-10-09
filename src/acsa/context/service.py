from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from acsa.context.analyzer import ContextAnalyzer
from acsa.evidence.graph import EvidenceGraph
from acsa.evidence.models import Evidence
from acsa.reachability.discovery import SourceDiscovery
from acsa.reachability.models import ParsedSourceFile
from acsa.reachability.parser import JavaScriptSourceParser

if TYPE_CHECKING:
    from acsa.vulnerability.models import Finding

logger = logging.getLogger(__name__)


class ContextService:
    """Orchestrates Phase 4 context and attacker-controlled data flow analysis."""

    def __init__(
        self,
        discovery: SourceDiscovery | None = None,
        parser: JavaScriptSourceParser | None = None,
        analyzer: ContextAnalyzer | None = None,
    ) -> None:
        self.discovery = discovery or SourceDiscovery()
        self.parser = parser or JavaScriptSourceParser()
        self.analyzer = analyzer or ContextAnalyzer()

    def analyze_findings(
        self,
        repository_path: Path,
        findings: list[Finding],
        parsed_files: dict[str, ParsedSourceFile] | None = None,
        source_contents: dict[str, str] | None = None,
        graph: EvidenceGraph | None = None,
    ) -> tuple[list[Finding], list[Evidence]]:
        """Evaluate context and attacker control for a collection of reachability-evaluated findings."""
        # 1. Discover and load source contents if not provided
        if source_contents is None:
            source_contents = {}
            rel_files = self.discovery.discover_source_files(repository_path)
            for rf in rel_files:
                source_contents[rf] = self.discovery.read_source_content(repository_path, rf)

        # 2. Parse source files if not provided
        if parsed_files is None:
            parsed_files = {}
            for rf, content in source_contents.items():
                parsed_files[rf] = self.parser.parse_source(rf, content)

        if graph is None:
            graph = EvidenceGraph()

        enriched_findings: list[Finding] = []
        new_evidence: list[Evidence] = []

        for f in findings:
            analysis, ev_list = self.analyzer.evaluate_context(
                finding=f,
                parsed_files=parsed_files,
                source_contents=source_contents,
                graph=graph,
            )

            # Combine evidence IDs
            combined_evidence_ids = list(f.evidence_ids)
            for ev in ev_list:
                if ev.id not in combined_evidence_ids:
                    combined_evidence_ids.append(ev.id)
                new_evidence.append(ev)

            updated_finding = f.model_copy(
                update={
                    "context": analysis,
                    "evidence_ids": combined_evidence_ids,
                }
            )
            enriched_findings.append(updated_finding)

        return enriched_findings, new_evidence
