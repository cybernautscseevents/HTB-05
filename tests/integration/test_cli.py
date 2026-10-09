"""Integration tests for the ACSA Typer CLI startup, help, and commands."""

from typer.testing import CliRunner

from acsa.cli.main import app

runner = CliRunner()


def test_cli_help() -> None:
    """Verify CLI starts up and displays help cleanly."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "ACSA" in result.stdout
    assert "Artifact-Centric Security Analysis" in result.stdout
    assert "status" in result.stdout
    assert "plan" in result.stdout
    assert "version" in result.stdout


def test_cli_version_flag() -> None:
    """Verify CLI --version flag works."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.stdout


def test_cli_version_command() -> None:
    """Verify CLI version command works."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.stdout


def test_cli_status_command() -> None:
    """Verify CLI status command reports pipeline readiness."""
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "Phase 0" in result.stdout
    assert "Ready" in result.stdout
    assert "Planned" in result.stdout


def test_cli_plan_command() -> None:
    """Verify CLI plan command outlines pipeline and novelty features."""
    result = runner.invoke(app, ["plan"])
    assert result.exit_code == 0
    assert "Proof-Carrying Remediation" in result.stdout
    assert "Minimum-Blast-Radius Fix" in result.stdout
    assert "Contradiction-Aware Inventory" in result.stdout
    assert "Uncertainty-Guided Dynamic Probe" in result.stdout
