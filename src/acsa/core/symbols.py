"""Defensible symbol validation and rejection of generic prose words."""

import re

# Comprehensive rejection list for generic English words, programming jargon, and advisory prose
REJECTED_GENERIC_WORDS: frozenset[str] = frozenset({
    # Common English stop words / articles / pronouns / prepositions / conjunctions
    "the", "a", "an", "this", "that", "these", "those", "it", "its", "their",
    "via", "in", "to", "of", "by", "for", "from", "with", "as", "at", "on", "into",
    "through", "when", "where", "which", "who", "whom", "whose", "why", "how",
    "and", "or", "but", "nor", "so", "yet", "both", "either", "neither",
    "all", "any", "some", "each", "every", "such", "no", "not", "only", "other",
    # Generic programming / code nouns
    "function", "functions", "method", "methods", "routine", "routines",
    "api", "apis", "call", "calls", "caller", "callee", "invocation", "invocations",
    "class", "classes", "module", "modules", "package", "packages",
    "library", "libraries", "component", "components", "object", "objects",
    "property", "properties", "symbol", "symbols", "variable", "variables",
    "identifier", "identifiers", "export", "exports", "import", "imports",
    "interface", "interfaces", "type", "types", "file", "files", "path", "paths",
    # Language keywords
    "new", "var", "let", "const", "return", "returns", "throw", "throws",
    "if", "else", "switch", "case", "default", "while", "do", "break",
    "continue", "try", "catch", "finally", "typeof", "instanceof", "void", "delete",
    "prototype", "constructor", "super", "null", "undefined", "true", "false",
    # Advisory / security jargon
    "vulnerable", "vulnerability", "vulnerabilities", "affected", "unaffected",
    "untrusted", "trusted", "user", "users", "input", "inputs", "data",
    "parameter", "parameters", "argument", "arguments", "param", "params",
    "value", "values", "payload", "payloads", "string", "strings", "number", "numbers",
    "array", "arrays", "boolean", "booleans", "regex", "regexp", "regular",
    "expression", "expressions", "denial", "service", "redos", "dos", "rce", "xss",
    "code", "execution", "injection", "pollution", "prototype_pollution",
    "bypass", "handling", "processing", "flaw", "issue", "bug", "advisory", "advisories",
    "version", "versions", "branch", "branches", "release", "releases",
    "fixed", "introduced", "patch", "patches", "update", "updates", "upgrade",
    "following", "provided", "given", "used", "using", "allows", "causing", "causes",
    "lead", "leads", "leading", "result", "results", "resulting", "found", "discovered",
})

VALID_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$")


def is_defensible_symbol(symbol: str) -> bool:
    """Validate that an extracted symbol is a defensible code identifier rather than generic prose.

    Rejects:
    - Empty strings or strings with invalid characters/spaces
    - Identifiers outside length 2..80
    - Stop words and generic English words ('the', 'a', 'via')
    - Generic programming nouns ('function', 'api', 'method')
    - Language keywords ('new', 'return', 'null')
    - Security jargon ('vulnerability', 'redos', 'service')
    """
    if not symbol or not isinstance(symbol, str):
        return False
    s = symbol.strip()
    if len(s) < 2 or len(s) > 80:
        return False
    if not VALID_IDENTIFIER_PATTERN.match(s):
        return False
    parts = s.split(".")
    for part in parts:
        if part.lower() in REJECTED_GENERIC_WORDS:
            return False
    return True
