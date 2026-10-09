"""Path security and workspace isolation primitives for ACSA."""

import os
import shutil
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from acsa.core.exceptions import PathTraversalError, WorkspaceSecurityError


def validate_safe_path(base_dir: Path | str, target_path: Path | str) -> Path:
    """Validate that target_path resides strictly within base_dir and has no traversal escapes.

    Raises:
        PathTraversalError: If target_path escapes base_dir or contains dangerous components.
    """
    base_resolved = Path(base_dir).resolve()
    target = Path(target_path)

    # Check for raw string indicators of traversal before resolution
    raw_str = str(target_path)
    if "\x00" in raw_str:
        raise PathTraversalError("Null byte detected in path")

    if target.resolve() == base_resolved:
        target_resolved = base_resolved
    elif target.is_absolute():
        target_resolved = target.resolve()
    else:
        target_resolved = (base_resolved / target).resolve()

    try:
        # Check if target_resolved is relative to base_resolved
        target_resolved.relative_to(base_resolved)
    except ValueError as err:
        raise PathTraversalError(
            f"Path traversal detected: '{target_path}' resolves outside base '{base_dir}'"
        ) from err

    return target_resolved


@contextmanager
def isolate_workspace(
    base_dir: Path | str, prefix: str = "acsa_ws_"
) -> Generator[Path, None, None]:
    """Create a temporary, isolated workspace directory within base_dir and ensure cleanup.

    Enforces workspace isolation so analysis runs cannot pollute each other or the host.
    """
    base_path = Path(base_dir).resolve()
    base_path.mkdir(parents=True, exist_ok=True)

    temp_dir = Path(tempfile.mkdtemp(prefix=prefix, dir=base_path)).resolve()
    try:
        # Validate that the temp directory is strictly inside base_path
        validate_safe_path(base_path, temp_dir)
        yield temp_dir
    finally:
        # Clean temporary workspace thoroughly
        if temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)


def enforce_file_size_limit(file_path: Path | str, max_bytes: int) -> int:
    """Check that file does not exceed maximum allowable scan size.

    Raises:
        WorkspaceSecurityError: If file exceeds max_bytes.
    """
    p = Path(file_path)
    if not p.is_file():
        return 0
    size = os.path.getsize(p)
    if size > max_bytes:
        raise WorkspaceSecurityError(
            f"File '{file_path}' ({size} bytes) exceeds maximum allowable scan size ({max_bytes} bytes)"
        )
    return size
