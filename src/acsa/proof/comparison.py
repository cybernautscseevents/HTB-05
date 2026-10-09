"""Comparison engine for evaluating deltas between BEFORE and AFTER evidence graphs."""

from acsa.evidence.graph import EvidenceGraph
from acsa.proof.models import EvidenceSnapshot, ProofComparison
from acsa.verdict.vocabulary import Verdict


class ProofComparisonEngine:
    """Computes fine-grained, evidence-grounded deltas between BEFORE and AFTER states."""

    @classmethod
    def compare(
        cls,
        before: EvidenceSnapshot,
        after: EvidenceSnapshot,
        before_graph: EvidenceGraph | None = None,
        after_graph: EvidenceGraph | None = None,
    ) -> ProofComparison:
        """Compare BEFORE and AFTER snapshots and evidence graphs to explain why verdicts changed."""
        comp = before.component

        # 1. Advisories delta
        resolved_advs: list[str] = []
        remaining_advs: list[str] = []

        for adv in before.advisories:
            after_app = after.vulnerability_applicability.get(adv)
            if adv not in after.advisories or after_app == "NOT_AFFECTED":
                resolved_advs.append(adv)
            else:
                remaining_advs.append(adv)

        # 2. Vulnerable symbol closure
        # Symbol is closed if:
        # a) Version is NOT_AFFECTED (symbol in patched package is no longer vulnerable)
        # b) Call sites to vulnerable symbol in source code were removed/replaced
        # c) After reachability is NOT_REACHABLE while before was REACHABLE
        vulnerable_symbol_closed = False
        if resolved_advs and not remaining_advs and after.verdict == Verdict.PROVEN_NOT_AFFECTED:
            vulnerable_symbol_closed = True
        elif after.reachability_state == "NOT_REACHABLE":
            vulnerable_symbol_closed = True
        elif before.vulnerable_call_sites and not after.vulnerable_call_sites:
            vulnerable_symbol_closed = True
        elif not before.vulnerable_call_sites and not after.vulnerable_call_sites:
            # If no call sites existed in the first place (e.g. unused or non-reachable)
            vulnerable_symbol_closed = True

        # 3. Exposure path severance
        exposure_path_severed = False
        before_nodes_count = len(before_graph.nodes) if before_graph else 0
        after_nodes_count = len(after_graph.nodes) if after_graph else 0
        before_edges_count = len(before_graph.edges) if before_graph else 0
        after_edges_count = len(after_graph.edges) if after_graph else 0

        # Graph-based path severance check
        if before_graph and after_graph and before.entry_points and before.vulnerable_symbols:
            has_before_path = False
            has_after_path = False
            for ep in before.entry_points:
                for sym in before.vulnerable_symbols:
                    if before_graph.has_path(ep, sym):
                        has_before_path = True
                    if after_graph.has_path(ep, sym):
                        has_after_path = True

            if has_before_path and not has_after_path:
                exposure_path_severed = True
            elif not has_before_path and not has_after_path:
                exposure_path_severed = True
        elif before.call_paths and not after.call_paths:
            exposure_path_severed = True
        elif before.verdict == Verdict.PROVEN_EXPOSURE and after.verdict != Verdict.PROVEN_EXPOSURE:
            exposure_path_severed = True
        elif before.verdict in (Verdict.PROVEN_AFFECTED, Verdict.PROVEN_NOT_AFFECTED):
            exposure_path_severed = True

        # 4. Construct human-readable delta explanation
        explanation_lines: list[str] = []
        if before.version != after.version:
            explanation_lines.append(
                f"Component '{comp}' version changed: {before.version or 'unversioned'} -> {after.version or 'unversioned'}."
            )
        else:
            explanation_lines.append(f"Component '{comp}' version remained {before.version or 'unversioned'}.")

        if resolved_advs:
            explanation_lines.append(
                f"Resolved {len(resolved_advs)}/{len(before.advisories)} advisories: {', '.join(resolved_advs)}."
            )
        if remaining_advs:
            explanation_lines.append(
                f"Remaining unresolved advisories: {', '.join(remaining_advs)}."
            )

        if vulnerable_symbol_closed:
            explanation_lines.append(
                "Vulnerable symbol data flow severed or verified safe in post-remediation analysis."
            )
        else:
            explanation_lines.append(
                "Vulnerable symbol remains actively exposed or unverified."
            )

        if exposure_path_severed:
            explanation_lines.append(
                "Pre-remediation attacker-to-vulnerable-symbol exposure path is absent in post-remediation evidence graph."
            )
        else:
            explanation_lines.append(
                "Exposure path was not provably severed in post-remediation evidence graph."
            )

        explanation_lines.append(
            f"Verdict transition: {before.verdict.value} -> {after.verdict.value}."
        )

        return ProofComparison(
            component=comp,
            before_version=before.version,
            after_version=after.version,
            before_advisories=before.advisories,
            after_advisories=after.advisories,
            resolved_advisories=resolved_advs,
            remaining_advisories=remaining_advs,
            before_verdict=before.verdict,
            after_verdict=after.verdict,
            vulnerable_symbol_closed=vulnerable_symbol_closed,
            exposure_path_severed=exposure_path_severed,
            graph_nodes_before=before_nodes_count,
            graph_nodes_after=after_nodes_count,
            graph_edges_before=before_edges_count,
            graph_edges_after=after_edges_count,
            delta_explanation=" ".join(explanation_lines),
        )
