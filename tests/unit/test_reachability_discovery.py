"""Unit tests for JavaScript/TypeScript source file discovery and boundary safety."""

from pathlib import Path

from acsa.reachability.discovery import SourceDiscovery


def test_discovery_finds_supported_extensions(tmp_path: Path) -> None:
    """Discovery identifies .js, .jsx, .ts, .tsx, .mjs, .cjs files."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "index.js").write_text("console.log('hi');", encoding="utf-8")
    (tmp_path / "src" / "component.jsx").write_text("export default null;", encoding="utf-8")
    (tmp_path / "src" / "service.ts").write_text("export class Service {}", encoding="utf-8")
    (tmp_path / "src" / "view.tsx").write_text("export const View = () => null;", encoding="utf-8")
    (tmp_path / "src" / "module.mjs").write_text("export default 42;", encoding="utf-8")
    (tmp_path / "src" / "common.cjs").write_text("module.exports = {};", encoding="utf-8")
    (tmp_path / "src" / "readme.md").write_text("# Readme", encoding="utf-8")
    (tmp_path / "src" / "styles.css").write_text("body {}", encoding="utf-8")

    discovery = SourceDiscovery()
    files = discovery.discover_source_files(tmp_path)

    assert "src/index.js" in files
    assert "src/component.jsx" in files
    assert "src/service.ts" in files
    assert "src/view.tsx" in files
    assert "src/module.mjs" in files
    assert "src/common.cjs" in files
    assert "src/readme.md" not in files
    assert "src/styles.css" not in files


def test_discovery_skips_node_modules_and_git(tmp_path: Path) -> None:
    """Discovery strictly ignores node_modules, .git, and cache directories."""
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "index.js").write_text("module.exports = 1;", encoding="utf-8")

    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    (tmp_path / ".git" / "hooks" / "pre-commit.js").write_text("// hook", encoding="utf-8")

    (tmp_path / ".acsa_cache").mkdir()
    (tmp_path / ".acsa_cache" / "cached.js").write_text("// cache", encoding="utf-8")

    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "bundle.js").write_text("// bundle", encoding="utf-8")

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.js").write_text("console.log('app');", encoding="utf-8")

    discovery = SourceDiscovery()
    files = discovery.discover_source_files(tmp_path)

    assert files == ["src/app.js"]


def test_discovery_respects_max_file_size(tmp_path: Path) -> None:
    """Files exceeding size threshold are skipped safely."""
    (tmp_path / "small.js").write_text("console.log('small');", encoding="utf-8")
    (tmp_path / "large.js").write_text("x" * 2000, encoding="utf-8")

    discovery = SourceDiscovery(max_file_size=1000)
    files = discovery.discover_source_files(tmp_path)

    assert "small.js" in files
    assert "large.js" not in files


def test_read_source_content_safely(tmp_path: Path) -> None:
    """Source content is read safely without evaluating code."""
    file_path = tmp_path / "sample.js"
    file_path.write_text("const msg = 'hello world';", encoding="utf-8")

    content = SourceDiscovery.read_source_content(tmp_path, "sample.js")
    assert content == "const msg = 'hello world';"

    # Nonexistent file returns empty string gracefully
    missing_content = SourceDiscovery.read_source_content(tmp_path, "missing.js")
    assert missing_content == ""
