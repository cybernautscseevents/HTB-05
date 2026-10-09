"""Deterministic resolution of local relative imports in JavaScript/TypeScript codebases."""

from pathlib import Path


class LocalModuleResolver:
    """Resolves relative import paths (e.g. ./utils, ../services/auth) to canonical workspace-relative files."""

    def __init__(self, discovered_files: set[str] | None = None) -> None:
        # Pre-loaded set of workspace-relative POSIX paths
        self.discovered_files = discovered_files or set()

    def resolve(self, importing_file: str, specifier: str) -> str | None:
        """Resolve a relative module specifier imported from importing_file.

        Args:
            importing_file: Workspace-relative POSIX path of importing source file (e.g. 'src/routes/api.ts')
            specifier: Module specifier string (e.g. './helper', '../db/client')

        Returns:
            Resolved workspace-relative POSIX path (e.g. 'src/routes/helper.ts') or None if unresolvable.
        """
        # Only resolve local relative paths
        if not (specifier.startswith("./") or specifier.startswith("../") or specifier == "."):
            return None

        importing_dir = Path(importing_file).parent
        # Combine and normalize POSIX path
        try:
            # Reconstruct relative to workspace using pure Path normalization:
            parts = (importing_dir / specifier).parts
            # Normalize '..' and '.'
            norm_parts: list[str] = []
            for part in parts:
                if part == ".":
                    continue
                elif part == "..":
                    if norm_parts:
                        norm_parts.pop()
                else:
                    norm_parts.append(part)

            base_norm = "/".join(norm_parts)
        except Exception:
            return None

        # Try direct match
        if base_norm in self.discovered_files:
            return base_norm

        # Try candidate extensions
        for ext in (
            ".ts",
            ".tsx",
            ".js",
            ".jsx",
            ".mjs",
            ".cjs",
        ):
            candidate = f"{base_norm}{ext}"
            if candidate in self.discovered_files:
                return candidate

        # Try directory index files
        for ext in (
            ".ts",
            ".tsx",
            ".js",
            ".jsx",
            ".mjs",
            ".cjs",
        ):
            candidate = f"{base_norm}/index{ext}"
            if candidate in self.discovered_files:
                return candidate

        return None
