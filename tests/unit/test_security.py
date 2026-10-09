"""Unit tests for ACSA security boundaries, path traversal guards, and secret redaction."""

import logging
from pathlib import Path

import pytest

from acsa.core.exceptions import PathTraversalError
from acsa.core.logging import SecretMaskingFilter
from acsa.core.path_security import isolate_workspace, validate_safe_path


def test_validate_safe_path_success(tmp_path: Path) -> None:
    """Valid subpath within base directory passes without error."""
    sub_file = tmp_path / "sub" / "package.json"
    sub_file.parent.mkdir(parents=True, exist_ok=True)
    sub_file.write_text("{}", encoding="utf-8")

    resolved = validate_safe_path(tmp_path, sub_file)
    assert resolved.exists()
    assert resolved == sub_file.resolve()


def test_validate_safe_path_traversal_blocked(tmp_path: Path) -> None:
    """Path traversal attempt outside base directory raises PathTraversalError."""
    dangerous_path = tmp_path / ".." / "outside.txt"
    with pytest.raises(PathTraversalError):
        validate_safe_path(tmp_path, dangerous_path)


def test_validate_safe_path_null_byte_blocked(tmp_path: Path) -> None:
    """Null bytes in path parameters trigger PathTraversalError."""
    with pytest.raises(PathTraversalError):
        validate_safe_path(tmp_path, "package.json\x00.exe")


def test_isolate_workspace_lifecycle(tmp_path: Path) -> None:
    """Isolated temporary workspace is created and cleanly destroyed."""
    created_ws: Path | None = None
    with isolate_workspace(tmp_path, prefix="test_ws_") as ws:
        created_ws = ws
        assert ws.exists()
        assert ws.is_dir()
        # Verify workspace is inside base tmp_path
        validate_safe_path(tmp_path, ws)
        # Create a test file inside workspace
        (ws / "artifact.json").write_text("{}", encoding="utf-8")

    # Outside context manager, workspace must be deleted
    assert created_ws is not None
    assert not created_ws.exists()


def test_secret_masking_filter() -> None:
    """Ensure sensitive tokens and secrets are redacted from log messages."""
    mask_filter = SecretMaskingFilter()
    record = logging.LogRecord(
        name="acsa.test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Using token: ghp_1234567890abcdefghijklmnopqrstuvwxyz12 with Bearer eyJhbGciOiJIUzI1NiJ9",
        args=(),
        exc_info=None,
    )
    mask_filter.filter(record)

    assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz12" not in record.msg
    assert "***REDACTED***" in record.msg
    assert "Bearer ***REDACTED***" in record.msg
