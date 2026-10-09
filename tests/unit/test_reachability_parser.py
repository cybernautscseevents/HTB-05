"""Unit tests for JavaScript/TypeScript static parsing of imports, calls, entry points, and line numbers."""

from acsa.reachability.parser import JavaScriptSourceParser, strip_comments_preserving_line_count


def test_strip_comments_preserves_line_numbers() -> None:
    """Comment stripping preserves exact line numbers and character offsets."""
    code = (
        "// line 1 comment\n"
        "const a = 1;\n"
        "/* line 3\n"
        "   line 4 block comment */\n"
        "const b = 2;\n"
    )
    stripped = strip_comments_preserving_line_count(code)
    lines = stripped.splitlines()
    assert len(lines) == 5
    assert "const a = 1;" in lines[1]
    assert "const b = 2;" in lines[4]


def test_parse_esm_imports() -> None:
    """Parser accurately extracts ESM imports with symbols, aliases, and line numbers."""
    parser = JavaScriptSourceParser()
    source = (
        "import lodash from 'lodash';\n"
        "import { template, escape as esc } from 'lodash';\n"
        "import * as utils from './utils';\n"
        "import 'polyfill';\n"
    )
    parsed = parser.parse_source("src/app.ts", source)

    assert len(parsed.imports) == 5

    # import lodash from 'lodash'
    imp0 = parsed.imports[0]
    assert imp0.module_name == "lodash"
    assert imp0.symbol_name == "default"
    assert imp0.alias == "lodash"
    assert imp0.location.line_number == 1
    assert not imp0.is_local

    # import { template } from 'lodash'
    imp1 = parsed.imports[1]
    assert imp1.module_name == "lodash"
    assert imp1.symbol_name == "template"
    assert imp1.alias == "template"
    assert imp1.location.line_number == 2

    # import { escape as esc } from 'lodash'
    imp2 = parsed.imports[2]
    assert imp2.module_name == "lodash"
    assert imp2.symbol_name == "escape"
    assert imp2.alias == "esc"

    # import * as utils from './utils'
    imp3 = parsed.imports[3]
    assert imp3.module_name == "./utils"
    assert imp3.symbol_name == "*"
    assert imp3.alias == "utils"
    assert imp3.is_namespace
    assert imp3.is_local


def test_parse_cjs_requires() -> None:
    """Parser accurately extracts CommonJS require statements."""
    parser = JavaScriptSourceParser()
    source = (
        "const lodash = require('lodash');\n"
        "const { template, merge: customMerge } = require('lodash');\n"
        "const localHelper = require('./helper');\n"
    )
    parsed = parser.parse_source("src/server.js", source)

    assert len(parsed.imports) == 4

    # const lodash = require('lodash')
    imp0 = parsed.imports[0]
    assert imp0.module_name == "lodash"
    assert imp0.symbol_name == "default"
    assert imp0.alias == "lodash"
    assert imp0.location.line_number == 1

    # const { template } = require('lodash')
    imp1 = parsed.imports[1]
    assert imp1.symbol_name == "template"
    assert imp1.alias == "template"

    # const { merge: customMerge } = require('lodash')
    imp2 = parsed.imports[2]
    assert imp2.symbol_name == "merge"
    assert imp2.alias == "customMerge"

    # const localHelper = require('./helper')
    imp3 = parsed.imports[3]
    assert imp3.module_name == "./helper"
    assert imp3.is_local


def test_parse_dynamic_imports_and_computed_access() -> None:
    """Parser detects dynamic require, dynamic import, and computed property access."""
    parser = JavaScriptSourceParser()
    source = (
        "const modName = 'lodash';\n"
        "const dyn = require(modName);\n"
        "const result = dyn[action](data);\n"
    )
    parsed = parser.parse_source("src/dynamic.js", source)

    assert parsed.has_dynamic_constructs
    assert any(imp.is_dynamic for imp in parsed.imports)
    assert any(cs.is_dynamic for cs in parsed.call_sites)


def test_parse_entry_points_and_calls() -> None:
    """Parser identifies Express route entry points and member call sites with exact line numbers."""
    parser = JavaScriptSourceParser()
    source = (
        "const express = require('express');\n"
        "const lodash = require('lodash');\n"
        "const app = express();\n"
        "\n"
        "app.get('/api/render', (req, res) => {\n"
        "    const fn = lodash.template(req.query.tmpl);\n"
        "    res.send(fn());\n"
        "});\n"
    )
    parsed = parser.parse_source("src/routes.js", source)

    # Route entry point
    routes = [ep for ep in parsed.entry_points if ep.entry_type == "route"]
    assert len(routes) == 1
    assert routes[0].name == "GET /api/render (app)"
    assert routes[0].location.line_number == 5

    # Calls
    template_calls = [cs for cs in parsed.call_sites if cs.symbol_name == "template"]
    assert len(template_calls) == 1
    assert template_calls[0].callee_object == "lodash"
    assert template_calls[0].location.line_number == 6
