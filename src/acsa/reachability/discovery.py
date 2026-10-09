"""Safe, deterministic static source file discovery for JavaScript and TypeScript codebases."""

import logging
from pathlib import Path

from acsa.core.path_security import validate_safe_path

logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS: set[str] = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
}

DEFAULT_IGNORE_DIRS: set[str] = {
    ".git",
    "node_modules",
    ".acsa_cache",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "out",
    "coverage",
    "__pycache__",
    ".turbo",
    ".cache",
    ".idea",
    ".vscode",
}

MAX_FILE_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB
MAX_SCAN_DEPTH: int = 15
MAX_FILES_COUNT: int = 2000


class SourceDiscovery:
    """Discovers source code files within an authorized repository workspace boundary."""

    def __init__(
        self,
        supported_extensions: set[str] | None = None,
        ignore_dirs: set[str] | None = None,
        max_file_size: int = MAX_FILE_SIZE_BYTES,
        max_depth: int = MAX_SCAN_DEPTH,
        max_files: int = MAX_FILES_COUNT,
    ) -> None:
        self.supported_extensions = supported_extensions or SUPPORTED_EXTENSIONS
        self.ignore_dirs = ignore_dirs or DEFAULT_IGNORE_DIRS
        self.max_file_size = max_file_size
        self.max_depth = max_depth
        self.max_files = max_files

    def discover_source_files(self, repository_path: Path) -> list[str]:
        """Recursively scan repository directory for supported JS/TS source files.

        Returns a deterministic, sorted list of workspace-relative POSIX paths.
        Guarantees that files outside workspace or exceeding safety thresholds are excluded.
        """
        repo_root = validate_safe_path(repository_path, repository_path)
        if not repo_root.exists() or not repo_root.is_dir():
            return []

        discovered: list[str] = []

        def _scan(current_dir: Path, current_depth: int) -> None:
            if current_depth > self.max_depth:
                logger.debug("Reached max recursion depth %d at %s", self.max_depth, current_dir)
                return
            if len(discovered) >= self.max_files:
                logger.warning("Reached maximum file discovery limit (%d files)", self.max_files)
                return

            try:
                entries = sorted(current_dir.iterdir(), key=lambda p: p.name.lower())
            except (PermissionError, OSError) as err:
                logger.debug("Cannot read directory %s: %s", current_dir, err)
                return

            for entry in entries:
                if len(discovered) >= self.max_files:
                    break

                if entry.is_dir():
                    if entry.name in self.ignore_dirs or entry.name.startswith("."):
                        continue
                    _scan(entry, current_depth + 1)
                elif entry.is_file():
                    ext = entry.suffix.lower()
                    if ext in self.supported_extensions:
                        try:
                            # Verify path safety boundary
                            safe_file = validate_safe_path(repo_root, entry)
                            # Verify size constraint
                            size = safe_file.stat().st_size
                            if size > self.max_file_size:
                                logger.debug("Skipping %s: exceeds max size (%d bytes)", safe_file, size)
                                continue

                            rel_path = safe_file.relative_to(repo_root).as_posix()
                            discovered.append(rel_path)
                        except Exception as err:
                            logger.debug("Skipping unvalidated file %s: %s", entry, err)

        _scan(repo_root, 0)
        return sorted(discovered)

    @staticmethod
    def read_source_content(repository_path: Path, relative_file_path: str) -> str:
        """Safely read content of a discovered source file without executing it."""
        repo_root = validate_safe_path(repository_path, repository_path)
        target = validate_safe_path(repo_root, repo_root / relative_file_path)
        try:
            return target.read_text(encoding="utf-8", errors="replace")
        except OSError as err:
            logger.error("Failed to read source file %s: %s", target, err)
            return ""
