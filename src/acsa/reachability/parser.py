"""Static lexical and structural parser for JavaScript and TypeScript source files."""

import re
from pathlib import Path

from acsa.reachability.models import (
    CallSite,
    EntryPoint,
    FunctionDefinition,
    ImportStatement,
    ParsedSourceFile,
    SourceLocation,
)

# Reserved JS/TS control keywords that precede parentheses but are not function calls
RESERVED_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "function",
    "return",
    "typeof",
    "instanceof",
    "delete",
    "void",
    "throw",
    "yield",
    "await",
    "new",
    "case",
    "default",
    "do",
    "finally",
    "else",
    "class",
    "extends",
    "super",
    "constructor",
}

TOP_LEVEL_ENTRY_BASENAMES = {
    "server.js",
    "server.ts",
    "app.js",
    "app.ts",
    "main.js",
    "main.ts",
    "index.js",
    "index.ts",
    "cli.js",
    "cli.ts",
    "bin.js",
    "bin.ts",
}


def strip_comments_preserving_line_count(source_code: str) -> str:
    """Strip single-line and multi-line comments while preserving exact character offsets and line numbers.

    Replaces commented non-whitespace characters with spaces so line and column tracking remain exact.
    """
    chars = list(source_code)
    n = len(chars)
    i = 0

    state = "NORMAL"

    while i < n:
        c = chars[i]
        nxt = chars[i + 1] if i + 1 < n else ""

        if state == "NORMAL":
            if c == "'" and (i == 0 or chars[i - 1] != "\\"):
                state = "SINGLE_QUOTE"
            elif c == '"' and (i == 0 or chars[i - 1] != "\\"):
                state = "DOUBLE_QUOTE"
            elif c == "`" and (i == 0 or chars[i - 1] != "\\"):
                state = "BACKTICK"
            elif c == "/" and nxt == "/":
                state = "LINE_COMMENT"
                chars[i] = " "
                chars[i + 1] = " "
                i += 1
            elif c == "/" and nxt == "*":
                state = "BLOCK_COMMENT"
                chars[i] = " "
                chars[i + 1] = " "
                i += 1
        elif state == "SINGLE_QUOTE":
            if c == "'" and (i == 0 or chars[i - 1] != "\\"):
                state = "NORMAL"
        elif state == "DOUBLE_QUOTE":
            if c == '"' and (i == 0 or chars[i - 1] != "\\"):
                state = "NORMAL"
        elif state == "BACKTICK":
            if c == "`" and (i == 0 or chars[i - 1] != "\\"):
                state = "NORMAL"
        elif state == "LINE_COMMENT":
            if c == "\n":
                state = "NORMAL"
            else:
                chars[i] = " "
        elif state == "BLOCK_COMMENT":
            if c == "*" and nxt == "/":
                state = "NORMAL"
                chars[i] = " "
                chars[i + 1] = " "
                i += 1
            elif c != "\n":
                chars[i] = " "

        i += 1

    return "".join(chars)


class JavaScriptSourceParser:
    """Extracts imports, requires, calls, functions, exports, and entry points from JS/TS code."""

    def __init__(self) -> None:
        pass

    def parse_source(self, file_path: str, source_code: str) -> ParsedSourceFile:
        """Parse source code content into structured static observations."""
        cleaned_source = strip_comments_preserving_line_count(source_code)

        imports = self._extract_imports(file_path, cleaned_source)
        exports = self._extract_exports(cleaned_source)
        functions = self._extract_functions(file_path, cleaned_source, exports)
        call_sites = self._extract_calls(file_path, cleaned_source, functions)
        entry_points = self._extract_entry_points(file_path, cleaned_source, functions, exports)

        # Detect dynamic evaluation or reflection
        dynamic_reasons: list[str] = []
        has_dynamic = False

        for imp in imports:
            if imp.is_dynamic:
                has_dynamic = True
                dynamic_reasons.append(
                    f"Dynamic import/require at {imp.location}"
                )

        for cs in call_sites:
            if cs.is_dynamic:
                has_dynamic = True
                dynamic_reasons.append(
                    f"Dynamic/computed call invocation '{cs.raw_expression}' at {cs.location}"
                )

        # Check for eval() or new Function()
        for m in re.finditer(r"\b(?:eval|Function)\s*\(", cleaned_source):
            line_no = self._offset_to_line(cleaned_source, m.start())
            has_dynamic = True
            dynamic_reasons.append(f"Reflection construct eval/Function at {file_path}:{line_no}")

        return ParsedSourceFile(
            file_path=file_path,
            imports=imports,
            exports=exports,
            entry_points=entry_points,
            call_sites=call_sites,
            functions=functions,
            has_dynamic_constructs=has_dynamic,
            dynamic_construct_reasons=dynamic_reasons,
        )

    def _offset_to_line(self, text: str, offset: int) -> int:
        """Calculate 1-indexed line number from character offset."""
        return text[:offset].count("\n") + 1

    def _is_local_module(self, module_name: str) -> bool:
        """Determine whether module specifier is a relative/local path."""
        return (
            module_name.startswith("./")
            or module_name.startswith("../")
            or module_name == "."
            or module_name.startswith("/")
        )

    def _extract_imports(self, file_path: str, text: str) -> list[ImportStatement]:
        """Extract ESM import statements and CommonJS require() calls."""
        results: list[ImportStatement] = []

        # 1. ESM: import * as pkg from "mod"
        for m in re.finditer(
            r"""\bimport\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+['"]([^'"]+)['"]""",
            text,
        ):
            alias = m.group(1)
            mod_name = m.group(2)
            line = self._offset_to_line(text, m.start())
            results.append(
                ImportStatement(
                    module_name=mod_name,
                    symbol_name="*",
                    alias=alias,
                    is_local=self._is_local_module(mod_name),
                    is_namespace=True,
                    is_dynamic=False,
                    location=SourceLocation(file_path=file_path, line_number=line),
                )
            )

        # 2. ESM: import defPkg, { named } from "mod" OR import defPkg from "mod"
        for m in re.finditer(
            r"""\bimport\s+([A-Za-z_$][\w$]*)(?:\s*,\s*\{\s*([^}]+)\s*\})?\s+from\s+['"]([^'"]+)['"]""",
            text,
        ):
            def_alias = m.group(1)
            named_block = m.group(2)
            mod_name = m.group(3)
            line = self._offset_to_line(text, m.start())

            results.append(
                ImportStatement(
                    module_name=mod_name,
                    symbol_name="default",
                    alias=def_alias,
                    is_local=self._is_local_module(mod_name),
                    is_namespace=False,
                    is_dynamic=False,
                    location=SourceLocation(file_path=file_path, line_number=line),
                )
            )

            if named_block:
                self._parse_named_imports(
                    file_path, line, mod_name, named_block, results
                )

        # 3. ESM: import { named1, named2 as alias } from "mod"
        for m in re.finditer(
            r"""\bimport\s*\{\s*([^}]+)\s*\}\s*from\s+['"]([^'"]+)['"]""",
            text,
        ):
            named_block = m.group(1)
            mod_name = m.group(2)
            line = self._offset_to_line(text, m.start())
            self._parse_named_imports(file_path, line, mod_name, named_block, results)

        # 4. ESM: import "mod" (side effect)
        for m in re.finditer(
            r"""\bimport\s+['"]([^'"]+)['"]\s*;?""",
            text,
        ):
            mod_name = m.group(1)
            line = self._offset_to_line(text, m.start())
            results.append(
                ImportStatement(
                    module_name=mod_name,
                    symbol_name="*",
                    alias="",
                    is_local=self._is_local_module(mod_name),
                    is_namespace=False,
                    is_dynamic=False,
                    location=SourceLocation(file_path=file_path, line_number=line),
                )
            )

        # 5. CommonJS: const pkg = require("mod")
        for m in re.finditer(
            r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)""",
            text,
        ):
            alias = m.group(1)
            mod_name = m.group(2)
            line = self._offset_to_line(text, m.start())
            results.append(
                ImportStatement(
                    module_name=mod_name,
                    symbol_name="default",
                    alias=alias,
                    is_local=self._is_local_module(mod_name),
                    is_namespace=False,
                    is_dynamic=False,
                    location=SourceLocation(file_path=file_path, line_number=line),
                )
            )

        # 6. CommonJS: const { f1, f2: alias } = require("mod")
        for m in re.finditer(
            r"""\b(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)""",
            text,
        ):
            named_block = m.group(1)
            mod_name = m.group(2)
            line = self._offset_to_line(text, m.start())
            self._parse_cjs_destructured_imports(file_path, line, mod_name, named_block, results)

        # 7. Dynamic require(): require(expr) where expr is not a static string literal
        for m in re.finditer(r"""\brequire\(\s*([^)'"]+)\s*\)""", text):
            raw_arg = m.group(1).strip()
            if raw_arg:
                line = self._offset_to_line(text, m.start())
                results.append(
                    ImportStatement(
                        module_name=raw_arg,
                        symbol_name="*",
                        alias="",
                        is_local=False,
                        is_namespace=False,
                        is_dynamic=True,
                        location=SourceLocation(file_path=file_path, line_number=line),
                    )
                )

        # 8. Dynamic import(): import(expr) where expr is not a static string literal
        for m in re.finditer(r"""\bimport\(\s*([^)'"]+)\s*\)""", text):
            raw_arg = m.group(1).strip()
            if raw_arg:
                line = self._offset_to_line(text, m.start())
                results.append(
                    ImportStatement(
                        module_name=raw_arg,
                        symbol_name="*",
                        alias="",
                        is_local=False,
                        is_namespace=False,
                        is_dynamic=True,
                        location=SourceLocation(file_path=file_path, line_number=line),
                    )
                )

        return sorted(results, key=lambda imp: (imp.location.line_number or 0))

    def _parse_named_imports(
        self,
        file_path: str,
        line: int,
        mod_name: str,
        named_block: str,
        results: list[ImportStatement],
    ) -> None:
        """Parse comma-separated named imports { a, b as c }."""
        parts = named_block.split(",")
        for part in parts:
            item = part.strip()
            if not item:
                continue
            # Remove possible TS 'type' prefix
            if item.startswith("type "):
                item = item[5:].strip()

            if " as " in item:
                sym, alias = item.split(" as ", 1)
                sym = sym.strip()
                alias = alias.strip()
            else:
                sym = item
                alias = item

            results.append(
                ImportStatement(
                    module_name=mod_name,
                    symbol_name=sym,
                    alias=alias,
                    is_local=self._is_local_module(mod_name),
                    is_namespace=False,
                    is_dynamic=False,
                    location=SourceLocation(file_path=file_path, line_number=line),
                )
            )

    def _parse_cjs_destructured_imports(
        self,
        file_path: str,
        line: int,
        mod_name: str,
        named_block: str,
        results: list[ImportStatement],
    ) -> None:
        """Parse CommonJS destructured requires { a, b: c }."""
        parts = named_block.split(",")
        for part in parts:
            item = part.strip()
            if not item:
                continue

            if ":" in item:
                sym, alias = item.split(":", 1)
                sym = sym.strip()
                alias = alias.strip()
            else:
                sym = item
                alias = item

            results.append(
                ImportStatement(
                    module_name=mod_name,
                    symbol_name=sym,
                    alias=alias,
                    is_local=self._is_local_module(mod_name),
                    is_namespace=False,
                    is_dynamic=False,
                    location=SourceLocation(file_path=file_path, line_number=line),
                )
            )

    def _extract_exports(self, text: str) -> list[str]:
        """Extract exported identifiers and functions."""
        exports: set[str] = set()

        # export function foo
        for m in re.finditer(
            r"""\bexport\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)""", text
        ):
            exports.add(m.group(1))

        # export const foo = ...
        for m in re.finditer(
            r"""\bexport\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)""", text
        ):
            exports.add(m.group(1))

        # export default function foo
        for m in re.finditer(
            r"""\bexport\s+default\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)?""",
            text,
        ):
            if m.group(1):
                exports.add(m.group(1))
            else:
                exports.add("default")

        # module.exports.foo = ... or exports.foo = ...
        for m in re.finditer(
            r"""\b(?:module\.)?exports\.([A-Za-z_$][\w$]*)\s*=""", text
        ):
            exports.add(m.group(1))

        # module.exports = { foo, bar }
        for m in re.finditer(r"""\bmodule\.exports\s*=\s*\{\s*([^}]+)\s*\}""", text):
            for item in m.group(1).split(","):
                cand = item.split(":")[0].strip()
                if re.match(r"^[A-Za-z_$][\w$]*$", cand):
                    exports.add(cand)

        return sorted(exports)

    def _extract_functions(
        self, file_path: str, text: str, exports: list[str]
    ) -> list[FunctionDefinition]:
        """Extract function declarations, expressions, and methods with line numbers."""
        funcs: list[FunctionDefinition] = []
        export_set = set(exports)

        # 1. function foo(...) or async function foo(...)
        for m in re.finditer(
            r"""\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(""", text
        ):
            name = m.group(1)
            line = self._offset_to_line(text, m.start())
            funcs.append(
                FunctionDefinition(
                    name=name,
                    location=SourceLocation(file_path=file_path, line_number=line),
                    is_exported=(name in export_set),
                )
            )

        # 2. const foo = (...) => ... or const foo = function(...)
        for m in re.finditer(
            r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>""",
            text,
        ):
            name = m.group(1)
            line = self._offset_to_line(text, m.start())
            funcs.append(
                FunctionDefinition(
                    name=name,
                    location=SourceLocation(file_path=file_path, line_number=line),
                    is_exported=(name in export_set),
                )
            )

        for m in re.finditer(
            r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function""",
            text,
        ):
            name = m.group(1)
            line = self._offset_to_line(text, m.start())
            funcs.append(
                FunctionDefinition(
                    name=name,
                    location=SourceLocation(file_path=file_path, line_number=line),
                    is_exported=(name in export_set),
                )
            )

        return sorted(funcs, key=lambda f: (f.location.line_number or 0))

    def _extract_calls(
        self,
        file_path: str,
        text: str,
        functions: list[FunctionDefinition],
    ) -> list[CallSite]:
        """Extract function invocations, member calls, and dynamic calls."""
        calls: list[CallSite] = []

        # Find enclosing function for a given line number
        def _get_enclosing_func(line_num: int) -> str | None:
            closest_func: str | None = None
            closest_line = 0
            for f in functions:
                if f.location.line_number and f.location.line_number <= line_num:
                    if f.location.line_number > closest_line:
                        closest_line = f.location.line_number
                        closest_func = f.name
            return closest_func

        # 1. Member calls: obj.method(...)
        for m in re.finditer(
            r"""\b([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*\(""", text
        ):
            callee_obj = m.group(1)
            sym_name = m.group(2)
            line = self._offset_to_line(text, m.start())

            calls.append(
                CallSite(
                    symbol_name=sym_name,
                    callee_object=callee_obj,
                    is_dynamic=False,
                    location=SourceLocation(file_path=file_path, line_number=line),
                    raw_expression=f"{callee_obj}.{sym_name}()",
                    enclosing_function=_get_enclosing_func(line),
                )
            )

        # 2. Direct calls: func(...)
        for m in re.finditer(
            r"""(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(""", text
        ):
            sym_name = m.group(1)
            if sym_name in RESERVED_KEYWORDS:
                continue

            line = self._offset_to_line(text, m.start())
            calls.append(
                CallSite(
                    symbol_name=sym_name,
                    callee_object=None,
                    is_dynamic=False,
                    location=SourceLocation(file_path=file_path, line_number=line),
                    raw_expression=f"{sym_name}()",
                    enclosing_function=_get_enclosing_func(line),
                )
            )

        # 3. Dynamic / computed member calls: obj[prop](...)
        for m in re.finditer(
            r"""\b([A-Za-z_$][\w$]*)\s*\[\s*([^\]]+)\s*\]\s*\(""", text
        ):
            callee_obj = m.group(1)
            expr = m.group(2).strip()
            line = self._offset_to_line(text, m.start())

            calls.append(
                CallSite(
                    symbol_name=expr,
                    callee_object=callee_obj,
                    is_dynamic=True,
                    location=SourceLocation(file_path=file_path, line_number=line),
                    raw_expression=f"{callee_obj}[{expr}]()",
                    enclosing_function=_get_enclosing_func(line),
                )
            )

        # 4. Dynamic computed property access without immediate parens: obj[prop]
        for m in re.finditer(
            r"""\b([A-Za-z_$][\w$]*)\s*\[\s*([^'"`\d\]][^\]]*)\s*\]""", text
        ):
            callee_obj = m.group(1)
            expr = m.group(2).strip()
            line = self._offset_to_line(text, m.start())

            # Skip if this is followed by '(' as already captured
            sub_after = text[m.end():m.end() + 5]
            if "(" not in sub_after:
                calls.append(
                    CallSite(
                        symbol_name=expr,
                        callee_object=callee_obj,
                        is_dynamic=True,
                        location=SourceLocation(file_path=file_path, line_number=line),
                        raw_expression=f"{callee_obj}[{expr}]",
                        enclosing_function=_get_enclosing_func(line),
                    )
                )

        return sorted(calls, key=lambda cs: (cs.location.line_number or 0))

    def _extract_entry_points(
        self,
        file_path: str,
        text: str,
        functions: list[FunctionDefinition],
        exports: list[str],
    ) -> list[EntryPoint]:
        """Extract application entry points: HTTP routes, handlers, exported functions, and main CLI entries."""
        entry_points: list[EntryPoint] = []

        # 1. Express / Router / Fastify / Koa route handlers
        # Patterns: app.get("/path", ...), router.post("/path", ...), fastify.get(...)
        for m in re.finditer(
            r"""\b(app|router|server|fastify)\.(get|post|put|delete|patch|options|head|all|use)\s*\(\s*(['"][^'"]+['"])?""",
            text,
        ):
            obj = m.group(1)
            method = m.group(2).upper()
            route_literal = m.group(3)
            route_path = route_literal.strip("'\"") if route_literal else "/"
            line = self._offset_to_line(text, m.start())

            entry_type = "middleware" if method == "USE" else "route"
            name = f"{method} {route_path} ({obj})"
            entry_points.append(
                EntryPoint(
                    name=name,
                    entry_type=entry_type,
                    location=SourceLocation(file_path=file_path, line_number=line),
                    handler_symbol=None,
                )
            )

        # 2. http.createServer((req, res) => ...)
        for m in re.finditer(r"""\bhttp\.createServer\s*\(""", text):
            line = self._offset_to_line(text, m.start())
            entry_points.append(
                EntryPoint(
                    name="HTTP Server Handler",
                    entry_type="http_handler",
                    location=SourceLocation(file_path=file_path, line_number=line),
                    handler_symbol=None,
                )
            )

        # 3. Exported functions as entry points (serverless handlers, public library API)
        for func in functions:
            if func.is_exported:
                entry_points.append(
                    EntryPoint(
                        name=f"export {func.name}",
                        entry_type="exported_function",
                        location=func.location,
                        handler_symbol=func.name,
                    )
                )

        # 4. Top-level application / CLI files
        base_name = Path(file_path).name.lower()
        if base_name in TOP_LEVEL_ENTRY_BASENAMES or text.startswith("#!"):
            entry_points.append(
                EntryPoint(
                    name=f"Main Script Entry ({Path(file_path).name})",
                    entry_type="cli_entry",
                    location=SourceLocation(file_path=file_path, line_number=1),
                    handler_symbol=None,
                )
            )

        return sorted(entry_points, key=lambda ep: (ep.location.line_number or 0))
