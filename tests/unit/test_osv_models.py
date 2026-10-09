"""Unit tests for OSV request schemas, response parsing, and vulnerability normalization."""

from acsa.vulnerability.osv_models import (
    OSVBatchQuery,
    OSVPackage,
    OSVQuery,
    normalize_osv_advisory,
)


def test_osv_request_construction() -> None:
    """Verify construction of single and batch OSV query payloads."""
    pkg = OSVPackage(name="lodash", ecosystem="npm")
    query = OSVQuery(package=pkg, version="4.17.20")
    batch = OSVBatchQuery(queries=[query])

    assert query.package.name == "lodash"
    assert query.package.ecosystem == "npm"
    assert query.version == "4.17.20"
    assert len(batch.queries) == 1
    assert batch.queries[0].package.name == "lodash"


def test_npm_ecosystem_normalization() -> None:
    """Verify npm ecosystem defaulting and preservation."""
    pkg_default = OSVPackage(name="cookie")
    assert pkg_default.ecosystem == "npm"

    pkg_explicit = OSVPackage(name="express", ecosystem="npm")
    assert pkg_explicit.ecosystem == "npm"


def test_osv_advisory_normalization_full() -> None:
    """Verify normalization of a full OSV payload with aliases, severity, ranges, and fixes."""
    payload = {
        "id": "GHSA-35jh-r3h4-6jhm",
        "aliases": ["CVE-2021-23337"],
        "summary": "Command Injection in lodash",
        "details": "All versions of package lodash prior to 4.17.21 are vulnerable.",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "4.17.21"},
                        ],
                    }
                ],
                "ecosystem_specific": {
                    "affected_functions": ["template"],
                },
            }
        ],
        "database_specific": {
            "severity": "HIGH",
        },
    }

    vuln = normalize_osv_advisory(payload)

    assert vuln.id == "GHSA-35jh-r3h4-6jhm"
    assert "CVE-2021-23337" in vuln.aliases
    assert vuln.summary == "Command Injection in lodash"
    assert vuln.details is not None
    assert vuln.severity == "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
    assert "4.17.21" in vuln.fixed_versions
    assert ">=0 <4.17.21" in vuln.affected_ranges
    assert "template" in vuln.vulnerable_symbols
    assert vuln.database_specific.get("severity") == "HIGH"


def test_osv_advisory_normalization_minimal() -> None:
    """Verify safe fallback behavior for minimal or sparse OSV payloads."""
    payload = {
        "id": "CVE-2024-12345",
    }
    vuln = normalize_osv_advisory(payload)
    assert vuln.id == "CVE-2024-12345"
    assert "CVE-2024-12345" in vuln.summary
    assert vuln.aliases == []
    assert vuln.fixed_versions == []
    assert vuln.affected_ranges == []


def test_osv_advisory_rejects_generic_prose_words_including_the() -> None:
    """Regression test: ordinary prose words like 'the' must NEVER be accepted as vulnerable symbols."""
    payload = {
        "id": "GHSA-test-generic",
        "summary": "Denial of service via the function when user input is supplied",
        "details": "Vulnerable to regular expression denial of service via a function in the library.",
    }
    vuln = normalize_osv_advisory(payload)
    assert vuln.vulnerable_symbols == []
    assert "the" not in vuln.vulnerable_symbols
    assert "a" not in vuln.vulnerable_symbols
    assert "function" not in vuln.vulnerable_symbols


def test_semver_redos_advisory_extracts_no_generic_symbols() -> None:
    """Regression test: semver GHSA-c2qf-rxjj-qqgw prose ('via the function new Range') does not extract 'the'."""
    payload = {
        "id": "GHSA-c2qf-rxjj-qqgw",
        "summary": "semver vulnerable to Regular Expression Denial of Service",
        "details": (
            "Versions of the package semver before 7.5.2 on the 7.x branch, before 6.3.1 on the 6.x branch, "
            "and all other versions before 5.7.2 are vulnerable to Regular Expression Denial of Service (ReDoS) "
            "via the function new Range, when untrusted user data is provided as a range."
        ),
        "affected": [
            {
                "package": {"name": "semver", "ecosystem": "npm"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "5.7.2"}]}],
            }
        ],
    }
    vuln = normalize_osv_advisory(payload)
    assert vuln.vulnerable_symbols == []
    assert "the" not in vuln.vulnerable_symbols
    assert "new" not in vuln.vulnerable_symbols
    assert "Range" not in vuln.vulnerable_symbols


def test_osv_advisory_extracts_backticked_defensible_symbols() -> None:
    """Verify that explicitly quoted/backticked defensible code identifiers are extracted."""
    payload = {
        "id": "GHSA-test-quoted",
        "summary": "Prototype pollution via the `toNumber`, `trim` and `trimEnd` functions",
        "details": "Affected code is reachable via the `template` function in runtime execution.",
    }
    vuln = normalize_osv_advisory(payload)
    assert "toNumber" in vuln.vulnerable_symbols
    assert "trim" in vuln.vulnerable_symbols
    assert "trimEnd" in vuln.vulnerable_symbols
    assert "template" in vuln.vulnerable_symbols


def test_is_defensible_symbol_unit_validation() -> None:
    """Unit test: is_defensible_symbol accepts valid identifiers and rejects generic prose words."""
    from acsa.vulnerability.osv_models import is_defensible_symbol

    # Must reject generic English words / articles
    assert is_defensible_symbol("the") is False
    assert is_defensible_symbol("THE") is False
    assert is_defensible_symbol("a") is False
    assert is_defensible_symbol("an") is False
    assert is_defensible_symbol("via") is False

    # Must reject programming keywords & generic code nouns
    assert is_defensible_symbol("function") is False
    assert is_defensible_symbol("new") is False
    assert is_defensible_symbol("method") is False
    assert is_defensible_symbol("prototype") is False
    assert is_defensible_symbol("return") is False

    # Must reject non-identifiers or empty/whitespace
    assert is_defensible_symbol("") is False
    assert is_defensible_symbol("   ") is False
    assert is_defensible_symbol("123bad") is False
    assert is_defensible_symbol("new Range") is False  # contains space

    # Must accept defensible symbols
    assert is_defensible_symbol("template") is True
    assert is_defensible_symbol("toNumber") is True
    assert is_defensible_symbol("trim") is True
    assert is_defensible_symbol("trimEnd") is True
    assert is_defensible_symbol("lodash.template") is True


def test_prose_containing_via_the_function_variations_never_extracts_the() -> None:
    """Regression test: all variations of 'via the function' prose never extract 'the'."""
    variations = [
        "vulnerable to denial of service via the function when untrusted input is supplied",
        "vulnerable via the function new Range",
        "vulnerable via the 'the' function",
        "vulnerable via the `the` function",
        "vulnerable via the function 'the'",
        "vulnerable via the function `the`",
        "vulnerable via the `function` function",
        "vulnerable via the `new` function",
        "vulnerable via the `undefined` function",
        "ReDoS via the function without bounds checking",
    ]

    for prose in variations:
        payload = {
            "id": "GHSA-test-prose",
            "summary": prose,
            "details": prose,
        }
        vuln = normalize_osv_advisory(payload)
        assert "the" not in vuln.vulnerable_symbols, f"Extracted 'the' from prose: {prose}"
        assert "function" not in vuln.vulnerable_symbols, f"Extracted 'function' from prose: {prose}"
        assert "new" not in vuln.vulnerable_symbols, f"Extracted 'new' from prose: {prose}"
        assert vuln.vulnerable_symbols == [], f"Expected empty vulnerable_symbols but got {vuln.vulnerable_symbols} for: {prose}"


def test_ecosystem_specific_affected_functions_rejects_generic_words() -> None:
    """Regression test: ecosystem_specific.affected_functions containing generic words are discarded."""
    payload = {
        "id": "GHSA-test-ecosystem",
        "affected": [
            {
                "package": {"name": "semver", "ecosystem": "npm"},
                "ecosystem_specific": {
                    "affected_functions": ["the", "new", "function", "template"],
                },
            }
        ],
    }
    vuln = normalize_osv_advisory(payload)
    assert vuln.vulnerable_symbols == ["template"]
    assert "the" not in vuln.vulnerable_symbols
    assert "new" not in vuln.vulnerable_symbols
    assert "function" not in vuln.vulnerable_symbols


