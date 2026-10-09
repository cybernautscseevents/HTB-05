"""Command-line interface for ACSA (Artifact-Centric Security Analysis)."""

from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from acsa.core.config import get_settings

app = typer.Typer(
    name="acsa",
    help="ACSA — Artifact-Centric Security Analysis: Evidence-driven software supply chain security.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def version_callback(value: bool) -> None:
    """Print the ACSA CLI version and exit."""
    if value:
        console.print("[bold blue]ACSA[/bold blue] version [green]0.1.0[/green]")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-v",
            help="Show the version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """ACSA CLI root callback."""


@app.command(name="version")
def show_version() -> None:
    """Display version information for ACSA."""
    console.print("[bold blue]ACSA[/bold blue] (Artifact-Centric Security Analysis) [green]v0.1.0[/green]")


@app.command(name="status")
def status() -> None:
    """Display current system foundation status and configured pipeline phases."""
    settings = get_settings()

    table = Table(title="ACSA Foundation & Pipeline Status")
    table.add_column("Pipeline Phase", style="cyan", no_wrap=True)
    table.add_column("Focus", style="magenta")
    table.add_column("Status", style="green")

    table.add_row("Phase 0", "Engineering Foundation, Domain Models & CLI", "[bold green]Ready[/bold green]")
    table.add_row("Phase 1", "Ingestion (manifest, lockfile, SBOM)", "[bold green]Ready[/bold green]")
    table.add_row("Phase 2", "Inventory Truth + OSV Advisory Matching", "[bold green]Ready[/bold green]")
    table.add_row("Phase 3", "Reachability (AST, Import/Call Graph)", "[bold green]Ready[/bold green]")
    table.add_row("Phase 4", "Context & Multi-Source Evidence Fusion", "[bold green]Ready[/bold green]")
    table.add_row("Phase 5", "Minimum-Blast-Radius Remediation Analysis", "[bold green]Ready[/bold green]")
    table.add_row("Phase 6", "Proof-Carrying Verification & PR Attestation", "[yellow]Planned[/yellow]")

    console.print(table)
    console.print(f"\n[dim]Environment: {settings.env} | Service: {settings.service_name}[/dim]")


@app.command(name="ingest")
def ingest(
    repository_path: Annotated[
        str,
        typer.Argument(help="Path to the repository workspace to ingest."),
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output machine-readable JSON results."),
    ] = False,
) -> None:
    """Ingest dependency manifests, lockfiles, and SBOMs from a repository workspace."""
    from pathlib import Path

    from acsa.ingestion.service import IngestionService

    service = IngestionService()
    result = service.ingest_repository(Path(repository_path))

    if json_output:
        console.print_json(result.model_dump_json(indent=2))
        return

    console.print(f"\n[bold blue]ACSA Artifact Ingestion Report[/bold blue] for: [cyan]{result.repository_path}[/cyan]\n")

    # Artifacts table
    art_table = Table(title="Discovered Artifacts")
    art_table.add_column("Relative Path", style="cyan")
    art_table.add_column("Format", style="magenta")
    art_table.add_column("Size (bytes)", justify="right")
    art_table.add_column("SHA-256", style="dim")

    for art in result.discovered_artifacts:
        art_table.add_row(
            art.relative_path,
            art.artifact_type.value,
            str(art.size_bytes),
            art.sha256[:16] + "..." if art.sha256 else "-",
        )
    if not result.discovered_artifacts:
        art_table.add_row("[dim]None found[/dim]", "-", "-", "-")
    console.print(art_table)

    # Ingestion metrics
    m = result.metrics
    console.print(
        f"\n[bold green][OK] Ingestion Summary:[/bold green] "
        f"[bold]{m.get('artifacts_parsed', 0)}[/bold] parsed, "
        f"[bold]{m.get('total_observations', 0)}[/bold] total observations, "
        f"[bold]{m.get('unique_components', 0)}[/bold] unique components, "
        f"[bold]{len(result.inventory.dependencies)}[/bold] dependency edges."
    )

    # Discrepancy highlights (Novelty 3 foundation)
    disc_count = m.get("components_with_version_discrepancy", 0)
    if disc_count > 0:
        disc_table = Table(title=f"Multi-Source Observations with Version Discrepancies ({disc_count})")
        disc_table.add_column("Component", style="yellow")
        disc_table.add_column("Observed Versions / Sources", style="white")

        for name in result.inventory.unique_component_names:
            if result.inventory.has_version_discrepancy(name):
                obs_list = result.inventory.get_observations_for_component(name)
                details = ", ".join(
                    f"{o.version or o.version_constraint} ({o.source_type.value})"
                    for o in obs_list
                )
                disc_table.add_row(name, details)
        console.print(disc_table)

    # Warnings / Errors
    if result.warnings:
        console.print(f"\n[yellow]Warnings ({len(result.warnings)}):[/yellow]")
        for w in result.warnings:
            console.print(f"  [yellow][!][/yellow] [{w.artifact_path}] {w.message}")

    if result.errors:
        console.print(f"\n[red]Errors ({len(result.errors)}):[/red]")
        for e in result.errors:
            console.print(f"  [red][ERROR][/red] [{e.artifact_path}] {e.message}")

    console.print("\n[dim]Phase 1 Ingestion complete. No external vulnerability queries executed.[/dim]")


@app.command(name="scan")
def scan(
    repository_path: Annotated[
        str,
        typer.Argument(help="Path to the repository workspace to scan."),
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output machine-readable JSON scan results."),
    ] = False,
    remediation: Annotated[
        bool,
        typer.Option("--remediation", help="Also generate and evaluate Minimum-Blast-Radius remediation candidates."),
    ] = False,
) -> None:
    """Scan repository artifacts, evaluate vulnerability applicability, compute reachability, analyze context, and fuse evidence into conclusive verdicts."""
    from pathlib import Path

    from acsa.context.models import AttackerControlStatus
    from acsa.context.service import ContextService
    from acsa.ingestion.service import IngestionService
    from acsa.reachability.models import ReachabilityState
    from acsa.reachability.service import ReachabilityService
    from acsa.verdict.service import EvidenceFusionService
    from acsa.verdict.vocabulary import Verdict
    from acsa.vulnerability.models import ApplicabilityStatus
    from acsa.vulnerability.service import VulnerabilityService

    target_path = Path(repository_path)

    # 1. Artifact Ingestion
    ingest_service = IngestionService()
    ingest_result = ingest_service.ingest_repository(target_path)

    # 2. OSV Intelligence
    vuln_service = VulnerabilityService()
    scan_result = vuln_service.scan_inventory(
        ingest_result.inventory, repository_path=str(repository_path)
    )

    # 3. Static Reachability
    reach_service = ReachabilityService()
    findings_reach, reach_ev, graph = reach_service.analyze_findings(
        target_path, scan_result.findings
    )

    # 4. Context & Attacker-Controlled Data Flow
    ctx_service = ContextService()
    findings_ctx, ctx_ev = ctx_service.analyze_findings(
        target_path, findings_reach, graph=graph
    )

    # Intermediate model with combined evidence
    intermediate_result = scan_result.model_copy(
        update={
            "findings": findings_ctx,
            "evidence": list(scan_result.evidence) + reach_ev + ctx_ev,
            "reachability_evaluated": True,
            "context_evaluated": True,
        }
    )

    # 5. Evidence Fusion & Verdict Determination
    fusion_service = EvidenceFusionService()
    final_result = fusion_service.enrich_scan_result(intermediate_result, graph=graph)

    if json_output:
        console.print_json(final_result.model_dump_json(indent=2))
        return

    console.print("\n" + "=" * 60)
    console.print("[bold blue]ACSA Security Analysis[/bold blue]")
    console.print("[bold blue]ACSA SECURITY ANALYSIS[/bold blue]")
    console.print("=" * 60)

    console.print("\n[bold cyan]Repository[/bold cyan]")
    console.print(f"  {final_result.repository_path}")

    # Inventory Truth Summary Table
    inv_table = Table(title="Inventory Truth Summary")
    inv_table.add_column("Metric", style="cyan")
    inv_table.add_column("Count", justify="right", style="bold white")
    inv_table.add_row("Artifacts Discovered", str(len(ingest_result.discovered_artifacts)))
    inv_table.add_row("Total Observations", str(len(final_result.inventory.observations)))
    inv_table.add_row("Unique Components", str(len(final_result.inventory.unique_component_names)))
    inv_table.add_row("Exact Versions Queried", str(final_result.exact_versions_queried))
    console.print(inv_table)

    # Vulnerability Intelligence Summary Table
    intel_table = Table(title="Vulnerability Intelligence Summary (OSV)")
    intel_table.add_column("Metric", style="magenta")
    unique_affected_versions = {
        (f.component.name, f.component.version)
        for f in final_result.findings
        if f.applicability_status == ApplicabilityStatus.AFFECTED
    }
    intel_table.add_row("OSV Queries Sent", str(final_result.queries_executed))
    intel_table.add_row("Advisories Evaluated", str(final_result.advisories_count))
    intel_table.add_row(
        "Affected Advisory Findings",
        str(final_result.affected_count),
        style="bold red" if final_result.affected_count else "green",
    )
    intel_table.add_row(
        "Affected Exact Versions",
        str(len(unique_affected_versions)),
        style="bold red" if unique_affected_versions else "green",
    )
    intel_table.add_row("Not Affected", str(final_result.not_affected_count))
    intel_table.add_row("Unknown / Ambiguous", str(final_result.unknown_count))
    console.print(intel_table)

    if not final_result.osv_available:
        console.print("\n[bold red][ERROR] OSV intelligence service was unavailable during scan.[/bold red]")
        for err in final_result.errors:
            console.print(f"  [red]- {err}[/red]")
        return

    # Reachability Summary Table
    reachable_count = sum(
        1 for f in final_result.findings if f.reachability and f.reachability.status == ReachabilityState.REACHABLE
    )
    not_reachable_count = sum(
        1 for f in final_result.findings if f.reachability and f.reachability.status == ReachabilityState.NOT_REACHABLE
    )
    reach_unknown_count = sum(
        1 for f in final_result.findings if f.reachability and f.reachability.status == ReachabilityState.UNKNOWN
    )
    reach_table = Table(title="Reachability Analysis Summary (AST & Call Graph)")
    reach_table.add_column("Reachability State", style="cyan")
    reach_table.add_column("Findings Count", justify="right", style="bold")
    reach_table.add_row("REACHABLE", str(reachable_count), style="bold red" if reachable_count else "dim")
    reach_table.add_row("NOT_REACHABLE", str(not_reachable_count), style="bold green" if not_reachable_count else "dim")
    reach_table.add_row("UNKNOWN (Preserved Uncertainty)", str(reach_unknown_count), style="bold yellow" if reach_unknown_count else "dim")
    console.print(reach_table)

    if not final_result.findings:
        console.print("\n[bold green][OK] No vulnerabilities reported for exact installed package versions.[/bold green]")
        return

    # Render each finding's concise story
    for f in final_result.findings:
        console.print("\n" + "-" * 60)

        # Vulnerability section
        console.print("[bold magenta]Vulnerability[/bold magenta]")
        console.print(f"  [bold yellow]{f.vulnerability.id}[/bold yellow] ({f.vulnerability.severity or 'SEVERITY N/A'})")
        console.print(f"  [cyan]{f.component.name}@{f.component.version or '-'}[/cyan]")
        if f.applicability_status == ApplicabilityStatus.AFFECTED:
            console.print("  [bold red]AFFECTED[/bold red]")
        elif f.applicability_status == ApplicabilityStatus.NOT_AFFECTED:
            console.print("  [bold green]NOT_AFFECTED[/bold green]")
        else:
            console.print("  [bold yellow]UNKNOWN[/bold yellow]")

        # Reachability section
        console.print("\n[bold magenta]Reachability[/bold magenta]")
        if f.reachability:
            if f.reachability.status == ReachabilityState.REACHABLE:
                console.print("  Status: [bold red]REACHABLE[/bold red]")
                if f.reachability.entry_point:
                    console.print(f"  Entry point: [cyan]{f.reachability.entry_point}[/cyan]")
                if f.reachability.target_symbol:
                    console.print(f"  Vulnerable symbol: [bold magenta]{f.reachability.target_symbol}[/bold magenta]")
                if f.reachability.evidence_path:
                    console.print("  Evidence path:")
                    for idx, step in enumerate(f.reachability.evidence_path):
                        if idx == 0:
                            console.print(f"    {step}")
                        else:
                            console.print(f"    [dim]->[/dim] {step}")
            elif f.reachability.status == ReachabilityState.NOT_REACHABLE:
                console.print("  Status: [bold green]NOT_REACHABLE[/bold green]")
            else:
                console.print("  Status: [bold yellow]UNKNOWN[/bold yellow]")
                if f.reachability.uncertainty_reason:
                    console.print(f"  Reason: [dim]{f.reachability.uncertainty_reason}[/dim]")
        else:
            console.print("  Status: [bold yellow]UNKNOWN[/bold yellow]")

        # Context section
        console.print("\n[bold magenta]Context[/bold magenta]")
        if f.context:
            if f.context.status == AttackerControlStatus.CONFIRMED:
                console.print("  ATTACKER CONTROL: [bold red]CONFIRMED[/bold red]")
            elif f.context.status == AttackerControlStatus.NOT_ESTABLISHED:
                console.print("  ATTACKER CONTROL: [bold green]NOT_ESTABLISHED[/bold green]")
                if f.context.uncertainty_reason:
                    console.print(f"  Reason: [dim]{f.context.uncertainty_reason}[/dim]")
            else:
                console.print("  ATTACKER CONTROL: [bold yellow]UNKNOWN[/bold yellow]")
                if f.context.uncertainty_reason:
                    console.print(f"  Reason: [dim]{f.context.uncertainty_reason}[/dim]")
                if f.context.missing_evidence:
                    console.print(f"  Missing evidence: [yellow]{f.context.missing_evidence}[/yellow]")
        else:
            console.print("  ATTACKER CONTROL: [bold yellow]UNKNOWN[/bold yellow]")

        # Evidence Chain section
        console.print("\n[bold magenta]Evidence[/bold magenta]")
        if f.context and f.context.data_flow_path:
            for idx, step in enumerate(f.context.data_flow_path):
                console.print(f"  {step}")
                if idx < len(f.context.data_flow_path) - 1:
                    console.print("    |")
                    console.print("    v")
        elif f.reachability and f.reachability.evidence_path:
            for idx, step in enumerate(f.reachability.evidence_path):
                console.print(f"  {step}")
                if idx < len(f.reachability.evidence_path) - 1:
                    console.print("    |")
                    console.print("    v")
        else:
            console.print(f"  Artifact: {f.source_artifact_path or 'manifest'}")
            console.print("    |")
            console.print("    v")
            console.print(f"  Component: {f.component.name}@{f.component.version or '-'}")
            console.print("    |")
            console.print("    v")
            console.print(f"  OSV: {f.vulnerability.id}")

        # Verdict section
        console.print("\n[bold magenta]VERDICT[/bold magenta]")
        if f.verdict == Verdict.PROVEN_EXPOSURE:
            console.print(f"  [bold red]{f.verdict.value}[/bold red]")
        elif f.verdict == Verdict.PROVEN_AFFECTED:
            console.print(f"  [bold magenta]{f.verdict.value}[/bold magenta]")
        elif f.verdict == Verdict.POTENTIALLY_AFFECTED:
            console.print(f"  [bold yellow]{f.verdict.value}[/bold yellow]")
        elif f.verdict == Verdict.PROVEN_NOT_AFFECTED:
            console.print(f"  [bold green]{f.verdict.value}[/bold green]")
        elif f.verdict == Verdict.CONTRADICTORY:
            console.print(f"  [bold red]{f.verdict.value}[/bold red]")
        else:
            console.print(f"  [bold yellow]{f.verdict.value}[/bold yellow]")

        if f.notes:
            console.print(f"  [dim]{f.notes}[/dim]")
        if f.verdict == Verdict.UNKNOWN:
            if f.uncertainty_reason:
                console.print(f"  Uncertainty reason: [dim]{f.uncertainty_reason}[/dim]")
            if f.missing_evidence:
                console.print(f"  Missing evidence: [yellow]{f.missing_evidence}[/yellow]")

    console.print("\n" + "=" * 60)

    # Final Verdict Summary Table
    verdict_table = Table(title="ACSA Verdict Summary")
    verdict_table.add_column("Verdict Classification", style="cyan")
    verdict_table.add_column("Count", justify="right", style="bold")
    verdict_table.add_row(
        "PROVEN_EXPOSURE",
        str(final_result.proven_exposure_count),
        style="bold red" if final_result.proven_exposure_count else "dim",
    )
    verdict_table.add_row(
        "PROVEN_AFFECTED",
        str(final_result.proven_affected_count),
        style="bold magenta" if final_result.proven_affected_count else "dim",
    )
    verdict_table.add_row(
        "POTENTIALLY_AFFECTED",
        str(final_result.potentially_affected_count),
        style="bold yellow" if final_result.potentially_affected_count else "dim",
    )
    verdict_table.add_row(
        "PROVEN_NOT_AFFECTED",
        str(final_result.proven_not_affected_count),
        style="bold green" if final_result.proven_not_affected_count else "dim",
    )
    verdict_table.add_row(
        "CONTRADICTORY",
        str(final_result.contradictory_count),
        style="bold red" if final_result.contradictory_count else "dim",
    )
    verdict_table.add_row(
        "UNKNOWN (UNKNOWN != SAFE)",
        str(final_result.unknown_count),
        style="bold yellow" if final_result.unknown_count else "dim",
    )
    console.print(verdict_table)

    if remediation:
        from acsa.remediation.service import RemediationService

        rem_service = RemediationService()
        rem_report = rem_service.remediate_repository(target_path, final_result)
        _render_remediation_section(rem_report)


def _render_remediation_section(remediation_report: Any) -> None:
    """Render structured remediation analysis results and simulated patches."""
    console.print("\n" + "=" * 60)
    console.print("[bold green]ACSA MINIMUM-BLAST-RADIUS REMEDIATION ANALYSIS[/bold green]")
    console.print("=" * 60)

    if not remediation_report.results:
        console.print("\n[dim]No findings requiring remediation candidates.[/dim]")
        return

    for res in remediation_report.results:
        console.print(f"\n[bold cyan]Finding:[/bold cyan] {res.finding_id}")
        console.print(f"  [bold]Current package/version:[/bold] {res.package_name}@{res.current_version}")
        console.print(f"  [bold]Advisories:[/bold] {', '.join(res.advisories)}")
        console.print(f"  [bold]Current verdict:[/bold] {res.verdict.value}")
        console.print(
            f"  [bold]Dependency relation:[/bold] {res.dependency_relation.value}"
            + (f" (parent: {res.parent_package})" if res.parent_package else "")
        )

        if res.selected_candidate:
            cand = res.selected_candidate
            console.print(f"  [bold green]Candidate strategy:[/bold green] {cand.strategy.value}")
            console.print(f"  [bold]Target version/range:[/bold] {cand.target_version or 'N/A'}")
            console.print(f"  [bold]Files affected:[/bold] {', '.join(cand.files_changed) or 'none'}")
            console.print(f"  [bold]Dependencies affected:[/bold] {', '.join(cand.dependencies_affected) or 'none'}")
            console.print(f"  [bold]API impact:[/bold] {cand.api_impact}")
            console.print(f"  [bold]Version impact:[/bold] {cand.version_impact}")
            console.print(f"  [bold]Exposure closure status:[/bold] {cand.closure_status.value}")
            console.print(f"  [bold]Evidence classification / Status:[/bold] {cand.confidence_level.value} ({cand.status.value})")
            console.print(f"  [bold]Lockfile action:[/bold] {cand.lockfile_action}")
            if cand.evidence_ids:
                console.print(f"  [bold]Evidence IDs:[/bold] {', '.join(cand.evidence_ids)}")

            console.print("\n  [bold magenta]Blast-radius explanation:[/bold magenta]")
            for line in res.blast_radius_explanation.split("\n"):
                console.print(f"    {line}")

            if cand.simulated_patch:
                console.print("\n  [bold yellow]Proposed Change (Simulated Unified Diff):[/bold yellow]")
                for line in cand.simulated_patch.split("\n"):
                    if line.startswith("+"):
                        console.print(f"    [green]{line}[/green]")
                    elif line.startswith("-"):
                        console.print(f"    [red]{line}[/red]")
                    elif line.startswith("@@"):
                        console.print(f"    [cyan]{line}[/cyan]")
                    else:
                        console.print(f"    [dim]{line}[/dim]")
        else:
            console.print("  [bold red]Candidate strategy:[/bold red] NO_SAFE_CANDIDATE")
            console.print(f"  [bold red]Rationale:[/bold red] {res.blast_radius_explanation}")

    # Summary table
    rem_table = Table(title="Remediation Candidates Summary")
    rem_table.add_column("Metric", style="cyan")
    rem_table.add_column("Count", justify="right", style="bold white")
    rem_table.add_row("Total Findings Evaluated", str(remediation_report.total_findings_evaluated))
    rem_table.add_row(
        "Actionable Candidates Generated",
        str(remediation_report.remediated_findings_count),
        style="bold green" if remediation_report.remediated_findings_count else "dim",
    )
    console.print(rem_table)


@app.command(name="remediate")
def remediate(
    repository_path: Annotated[
        str,
        typer.Argument(help="Path to the repository workspace to analyze and remediate."),
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output machine-readable JSON remediation report."),
    ] = False,
) -> None:
    """Analyze repository findings and generate Minimum-Blast-Radius remediation candidates with simulated patches."""
    from pathlib import Path

    from acsa.context.service import ContextService
    from acsa.ingestion.service import IngestionService
    from acsa.reachability.service import ReachabilityService
    from acsa.remediation.service import RemediationService
    from acsa.verdict.service import EvidenceFusionService
    from acsa.vulnerability.service import VulnerabilityService

    target_path = Path(repository_path)

    # 1. Ingestion
    ingest_service = IngestionService()
    ingest_result = ingest_service.ingest_repository(target_path)

    # 2. Vulnerability Intelligence
    vuln_service = VulnerabilityService()
    scan_result = vuln_service.scan_inventory(
        ingest_result.inventory, repository_path=str(repository_path)
    )

    # 3. Static Reachability
    reach_service = ReachabilityService()
    findings_reach, reach_ev, graph = reach_service.analyze_findings(
        target_path, scan_result.findings
    )

    # 4. Context & Attacker-Controlled Data Flow
    ctx_service = ContextService()
    findings_ctx, ctx_ev = ctx_service.analyze_findings(
        target_path, findings_reach, graph=graph
    )

    intermediate_result = scan_result.model_copy(
        update={
            "findings": findings_ctx,
            "evidence": list(scan_result.evidence) + reach_ev + ctx_ev,
            "reachability_evaluated": True,
            "context_evaluated": True,
        }
    )

    # 5. Evidence Fusion & Verdicts
    fusion_service = EvidenceFusionService()
    final_result = fusion_service.enrich_scan_result(intermediate_result, graph=graph)

    # 6. Minimum-Blast-Radius Remediation Analysis
    rem_service = RemediationService()
    rem_report = rem_service.remediate_repository(target_path, final_result)

    if json_output:
        console.print_json(rem_report.model_dump_json(indent=2))
        return

    _render_remediation_section(rem_report)


@app.command(name="verify-remediation")
def verify_remediation_command(
    repository_path: str = typer.Argument(
        ...,
        help="Path to repository workspace to verify remediation candidates against",
    ),
    candidate: str | None = typer.Option(
        None,
        "--candidate",
        "-c",
        help="Optional specific candidate ID to verify",
    ),
    mode: str = typer.Option(
        "simulated",
        "--mode",
        "-m",
        help="Verification mode: 'simulated' (Mode A) or 'materialized' (Mode B)",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Render output in machine-readable JSON format",
    ),
) -> None:
    """Verify remediation candidates in an isolated workspace and generate Proof-Carrying Remediation evidence."""
    from pathlib import Path

    from acsa.core.exceptions import PathTraversalError
    from acsa.core.path_security import validate_safe_path
    from acsa.proof.models import VerificationMode
    from acsa.proof.report import ProofReportGenerator
    from acsa.proof.service import RemediationProofService

    target_path = Path(repository_path)
    try:
        resolved_path = validate_safe_path(target_path, target_path)
    except PathTraversalError as err:
        console.print(f"[bold red]Path security violation:[/bold red] {err}")
        return
    except Exception as err:
        console.print(f"[bold red]Invalid repository path:[/bold red] {err}")
        return

    if not resolved_path.exists() or not resolved_path.is_dir():
        console.print(
            f"[bold red]Repository workspace directory not found:[/bold red] '{repository_path}'"
        )
        return

    verif_mode = (
        VerificationMode.MODE_B_MATERIALIZED
        if mode.lower() in ("materialized", "mode_b", "mode_b_materialized")
        else VerificationMode.MODE_A_SIMULATED
    )

    proof_report = RemediationProofService.verify_repository(
        repository_path=resolved_path,
        mode=verif_mode,
        candidate_id=candidate,
    )

    if json_output:
        console.print_json(proof_report.model_dump_json(indent=2))
        return

    console.print("\n" + "=" * 60)
    console.print("[bold green]ACSA PROOF-CARRYING REMEDIATION VERIFICATION[/bold green]")
    console.print("=" * 60)
    console.print(f"Repository: [cyan]{proof_report.repository_path}[/cyan]")
    console.print(f"Mode: [bold]{proof_report.verification_mode.value}[/bold]")
    console.print(f"Candidates Evaluated: [bold]{proof_report.total_candidates_verified}[/bold]")

    if not proof_report.results:
        console.print("\n[dim]No candidate remediations evaluated.[/dim]")
        return

    for proof in proof_report.results:
        console.print("\n" + ProofReportGenerator.format_text_report(proof))

    # Summary table
    table = Table(title="Remediation Proof Verdicts Summary")
    table.add_column("Verdict State", style="cyan")
    table.add_column("Count", justify="right", style="bold")
    table.add_row(
        "PROVEN_REMEDIATED",
        str(proof_report.proven_remediated_count),
        style="bold green" if proof_report.proven_remediated_count else "dim",
    )
    table.add_row(
        "REQUIRES_VERIFICATION",
        str(proof_report.requires_verification_count),
        style="bold yellow" if proof_report.requires_verification_count else "dim",
    )
    table.add_row(
        "PARTIALLY_VERIFIED",
        str(proof_report.partially_verified_count),
        style="bold yellow" if proof_report.partially_verified_count else "dim",
    )
    table.add_row(
        "REMEDIATION_FAILED",
        str(proof_report.failed_count),
        style="bold red" if proof_report.failed_count else "dim",
    )
    console.print("\n")
    console.print(table)


@app.command(name="probe-plan")
def probe_plan(
    repository_path: str = typer.Argument(
        ...,
        help="Path to repository workspace to plan dynamic probes for",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Render output in machine-readable JSON format",
    ),
) -> None:
    """Identify missing evidence for UNKNOWN findings and generate targeted dynamic probe specifications."""
    from pathlib import Path

    from acsa.core.exceptions import PathTraversalError
    from acsa.core.path_security import validate_safe_path
    from acsa.probe.report import ProbeReportGenerator
    from acsa.probe.service import ProbeService

    target_path = Path(repository_path)
    try:
        resolved_path = validate_safe_path(target_path, target_path)
    except PathTraversalError as err:
        console.print(f"[bold red]Security Error:[/bold red] {err}")
        raise typer.Exit(code=1) from err
    except Exception as err:
        console.print(f"[bold red]Path Error:[/bold red] {err}")
        raise typer.Exit(code=1) from err

    if not resolved_path.exists() or not resolved_path.is_dir():
        console.print(
            f"[bold red]Error:[/bold red] Repository path '{repository_path}' does not exist or is not a directory."
        )
        raise typer.Exit(code=1)

    with console.status(
        "[bold green]Analyzing repository and planning uncertainty-guided dynamic probes...[/bold green]"
    ):
        report, _ = ProbeService.plan_probes_for_repository(resolved_path)

    if json_output:
        console.print_json(report.model_dump_json(indent=2))
        return

    console.print("\n" + "=" * 60)
    console.print("[bold cyan]ACSA UNCERTAINTY-GUIDED DYNAMIC PROBE PLANNING[/bold cyan]")
    console.print("=" * 60)
    console.print(f"Repository: [cyan]{report.repository_path}[/cyan]")
    console.print(f"Unknown Findings: [bold]{report.total_unknown_findings}[/bold]")
    console.print(f"Probes Planned:   [bold]{report.total_probes_generated}[/bold]")

    if not report.probes:
        console.print("\n[dim]No UNKNOWN findings requiring dynamic probes detected.[/dim]")
        return

    for probe in report.probes:
        console.print("\n" + ProbeReportGenerator.render_probe(probe))

    # Summary table
    table = Table(title="Dynamic Probes Summary by Type")
    table.add_column("Probe Type", style="cyan")
    table.add_column("Count", justify="right", style="bold")
    for pt, count in sorted(report.probes_by_type.items()):
        table.add_row(pt, str(count))
    console.print("\n")
    console.print(table)


@app.command(name="plan")
def pipeline_plan() -> None:
    """Display the end-to-end evidence pipeline roadmap and novelty capabilities."""
    console.print("[bold blue]ACSA Technical Pipeline Flow:[/bold blue]")
    console.print(
        "Repository -> Inventory Truth -> Vulnerability Intelligence -> Applicability -> "
        "Reachability -> Context -> Evidence Fusion -> Verdict -> Remediation -> Verification -> Proof\n"
    )

    novelty_table = Table(title="Core Novelty Features")
    novelty_table.add_column("Feature", style="bold cyan")
    novelty_table.add_column("Description", style="white")

    novelty_table.add_row(
        "Proof-Carrying Remediation",
        "Eventual PRs will carry cryptographic before/after evidence showing exposure path closure.",
    )
    novelty_table.add_row(
        "Minimum-Blast-Radius Fix",
        "Calculates smallest verified change that severs all proven exposure paths.",
    )
    novelty_table.add_row(
        "Contradiction-Aware Inventory",
        "Reconciles manifest, lockfile, SBOM, source, and runtime evidence instead of blind trust.",
    )
    novelty_table.add_row(
        "Uncertainty-Guided Dynamic Probe (Supporting)",
        "Identifies runtime evidence needed when static analysis cannot establish a conclusive verdict.",
    )

    console.print(novelty_table)


if __name__ == "__main__":
    app()
