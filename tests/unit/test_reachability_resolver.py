"""Unit tests for local relative module resolution."""

from acsa.reachability.local_resolution import LocalModuleResolver


def test_resolver_resolves_relative_file_with_extensions() -> None:
    """LocalModuleResolver resolves extensionless relative paths to discovered files."""
    discovered = {
        "src/utils/helper.ts",
        "src/services/auth.js",
        "src/components/button.tsx",
    }
    resolver = LocalModuleResolver(discovered)

    # From src/routes/api.ts -> ../utils/helper -> src/utils/helper.ts
    resolved = resolver.resolve("src/routes/api.ts", "../utils/helper")
    assert resolved == "src/utils/helper.ts"

    # From src/index.ts -> ./services/auth -> src/services/auth.js
    resolved2 = resolver.resolve("src/index.ts", "./services/auth")
    assert resolved2 == "src/services/auth.js"


def test_resolver_resolves_directory_index_file() -> None:
    """LocalModuleResolver resolves directory specifiers to index files."""
    discovered = {
        "src/utils/index.js",
        "src/routes/index.ts",
    }
    resolver = LocalModuleResolver(discovered)

    resolved = resolver.resolve("src/app.js", "./utils")
    assert resolved == "src/utils/index.js"


def test_resolver_ignores_external_packages() -> None:
    """External package specifiers without relative prefix return None."""
    resolver = LocalModuleResolver({"src/app.js"})
    assert resolver.resolve("src/app.js", "lodash") is None
    assert resolver.resolve("src/app.js", "express") is None
    assert resolver.resolve("src/app.js", "@org/package") is None


def test_resolver_returns_none_for_missing_relative_file() -> None:
    """Missing relative target returns None without throwing exceptions."""
    resolver = LocalModuleResolver({"src/app.js"})
    assert resolver.resolve("src/app.js", "./nonexistent") is None
