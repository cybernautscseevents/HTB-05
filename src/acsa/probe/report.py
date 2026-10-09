"""Formatting and presentation engine for Uncertainty-Guided Dynamic Probe Plans."""

from acsa.probe.models import ProbePlanReport, ProbeSpecification


class ProbeReportGenerator:
    """Renders human-readable, actionable dynamic probe specifications and summaries."""

    @classmethod
    def render_probe(cls, probe: ProbeSpecification) -> str:
        """Render an individual probe specification card."""
        lines = [
            "=" * 60,
            "ACSA UNCERTAINTY-GUIDED DYNAMIC PROBE",
            "=" * 60,
            f"Rank: #{probe.priority_rank} | Type: {probe.probe_type.value}",
            f"Finding: {probe.finding_id}",
            f"Component: {probe.target_component}",
            "",
            "WHY UNKNOWN:",
            f"  {probe.uncertainty_reason}",
            "",
            "MISSING EVIDENCE:",
            f"  {probe.missing_evidence}",
            "",
            "TARGET:",
            f"  Entry Point:  {probe.entry_point or 'N/A'}",
            f"  Target Sink:  {probe.target_symbol or 'N/A'}",
            f"  Input Source: {probe.input_source or 'N/A'}",
            "",
            "REQUIRED OBSERVATION:",
            f"  {probe.required_observation}",
            "",
            "POTENTIAL VERDICT TRANSITIONS:",
            f"  If confirmed:    {probe.expected_verdict_if_confirmed.value}",
            f"  If not observed: {probe.expected_verdict_if_not_confirmed.value}",
            "",
            "SAFETY CONSTRAINTS:",
        ]
        for sc in probe.safety_constraints:
            lines.append(f"  - {sc}")

        lines.append("=" * 60)
        return "\n".join(lines)

    @classmethod
    def render_report(cls, report: ProbePlanReport) -> str:
        """Render a full repository probe planning report."""
        lines = [
            "=" * 60,
            "ACSA DYNAMIC PROBE PLANNING REPORT",
            "=" * 60,
            f"Repository: {report.repository_path}",
            f"Unknown Findings Identified: {report.total_unknown_findings}",
            f"Total Probes Planned:        {report.total_probes_generated}",
            "",
            "Probes by Type:",
        ]

        for pt, count in sorted(report.probes_by_type.items()):
            lines.append(f"  - {pt}: {count}")

        lines.append("")
        for probe in report.probes:
            lines.append(cls.render_probe(probe))
            lines.append("")

        lines.append("SUMMARY:")
        lines.append(f"  {report.summary}")
        lines.append("=" * 60)

        return "\n".join(lines)
