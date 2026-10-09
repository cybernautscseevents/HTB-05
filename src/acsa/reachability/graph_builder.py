"""Constructs EvidenceGraph connecting entry points, functions, local modules, packages, and call sites."""

import logging

from acsa.evidence.graph import EvidenceGraph
from acsa.evidence.models import EvidenceEdge, EvidenceNode
from acsa.reachability.local_resolution import LocalModuleResolver
from acsa.reachability.models import ParsedSourceFile

logger = logging.getLogger(__name__)


class ReachabilityGraphBuilder:
    """Builds a unified EvidenceGraph from parsed source files and local import resolution."""

    def __init__(self, local_resolver: LocalModuleResolver) -> None:
        self.local_resolver = local_resolver

    def build_graph(
        self,
        parsed_files: dict[str, ParsedSourceFile],
        target_vulnerabilities: dict[str, list[str]] | None = None,
    ) -> EvidenceGraph:
        """Construct the EvidenceGraph.

        Args:
            parsed_files: Mapping of relative file path to its ParsedSourceFile.
            target_vulnerabilities: Optional mapping of package name to list of vulnerable symbol names.

        Returns:
            Fully connected EvidenceGraph instance.
        """
        graph = EvidenceGraph()
        targets = target_vulnerabilities or {}

        # 1. Register Package & Vulnerable Symbol nodes
        for pkg_name, symbols in targets.items():
            pkg_node_id = f"pkg:{pkg_name}"
            graph.add_node(
                EvidenceNode(
                    id=pkg_node_id,
                    node_type="component",
                    label=pkg_name,
                    properties={"package": pkg_name},
                )
            )
            for sym in symbols:
                sym_node_id = f"sym:{pkg_name}:{sym}"
                graph.add_node(
                    EvidenceNode(
                        id=sym_node_id,
                        node_type="vulnerable_symbol",
                        label=sym,
                        properties={"package": pkg_name, "symbol": sym},
                    )
                )
                graph.add_edge(
                    EvidenceEdge(
                        source=sym_node_id,
                        target=pkg_node_id,
                        relationship="belongs_to",
                        weight=1.0,
                    )
                )

        # 2. Register Source Files, Functions, and Entry Points
        for file_path, parsed in parsed_files.items():
            file_node_id = f"file:{file_path}"
            graph.add_node(
                EvidenceNode(
                    id=file_node_id,
                    node_type="source_file",
                    label=file_path,
                    properties={"file_path": file_path},
                )
            )

            # Register Functions
            for func in parsed.functions:
                func_node_id = f"func:{file_path}:{func.name}"
                graph.add_node(
                    EvidenceNode(
                        id=func_node_id,
                        node_type="app_function",
                        label=func.name,
                        properties={
                            "file_path": file_path,
                            "line_number": func.location.line_number,
                            "is_exported": func.is_exported,
                        },
                    )
                )
                graph.add_edge(
                    EvidenceEdge(
                        source=file_node_id,
                        target=func_node_id,
                        relationship="declares",
                        weight=1.0,
                    )
                )

            # Register Entry Points
            for ep in parsed.entry_points:
                ep_node_id = f"entry:{file_path}:{ep.location.line_number or 1}:{ep.name}"
                graph.add_node(
                    EvidenceNode(
                        id=ep_node_id,
                        node_type="entry_point",
                        label=ep.name,
                        properties={
                            "file_path": file_path,
                            "line_number": ep.location.line_number,
                            "entry_type": ep.entry_type,
                            "handler_symbol": ep.handler_symbol,
                        },
                    )
                )
                # Link entry point to file
                graph.add_edge(
                    EvidenceEdge(
                        source=ep_node_id,
                        target=file_node_id,
                        relationship="routes_to",
                        weight=1.0,
                    )
                )
                # If entry point names a specific handler function, link directly
                if ep.handler_symbol:
                    target_func_id = f"func:{file_path}:{ep.handler_symbol}"
                    graph.add_edge(
                        EvidenceEdge(
                            source=ep_node_id,
                            target=target_func_id,
                            relationship="triggers",
                            weight=1.0,
                        )
                    )

        # 3. Connect Imports (Local modules and External Packages)
        for file_path, parsed in parsed_files.items():
            file_node_id = f"file:{file_path}"

            for imp in parsed.imports:
                if imp.is_local:
                    resolved_local = self.local_resolver.resolve(file_path, imp.module_name)
                    if resolved_local and resolved_local in parsed_files:
                        target_file_id = f"file:{resolved_local}"
                        graph.add_edge(
                            EvidenceEdge(
                                source=file_node_id,
                                target=target_file_id,
                                relationship="imports_local",
                                weight=1.0,
                                properties={"specifier": imp.module_name, "alias": imp.alias},
                            )
                        )
                else:
                    pkg_node_id = f"pkg:{imp.module_name}"
                    if pkg_node_id in graph.nodes:
                        graph.add_edge(
                            EvidenceEdge(
                                source=file_node_id,
                                target=pkg_node_id,
                                relationship="imports_package",
                                weight=1.0,
                                properties={"alias": imp.alias, "symbol": imp.symbol_name},
                            )
                        )

        # 4. Connect Function Calls, Local Invocations, and Vulnerable Symbols
        for file_path, parsed in parsed_files.items():
            file_node_id = f"file:{file_path}"

            # Map package alias/imports in this file
            package_bindings: dict[str, str] = {}  # alias -> package_name
            named_import_bindings: dict[str, tuple[str, str]] = {}  # local_alias -> (package_name, imported_symbol)
            local_import_bindings: dict[str, tuple[str, str]] = {}  # local_alias -> (resolved_file, exported_name)

            for imp in parsed.imports:
                if imp.is_local:
                    resolved = self.local_resolver.resolve(file_path, imp.module_name)
                    if resolved:
                        local_import_bindings[imp.alias] = (resolved, imp.symbol_name)
                else:
                    if imp.symbol_name in ("default", "*"):
                        package_bindings[imp.alias] = imp.module_name
                    else:
                        named_import_bindings[imp.alias] = (imp.module_name, imp.symbol_name)

            for cs in parsed.call_sites:
                call_node_id = f"call:{file_path}:{cs.location.line_number}:{cs.symbol_name}"
                graph.add_node(
                    EvidenceNode(
                        id=call_node_id,
                        node_type="dependency_call",
                        label=cs.raw_expression or cs.symbol_name,
                        properties={
                            "file_path": file_path,
                            "line_number": cs.location.line_number,
                            "symbol": cs.symbol_name,
                            "callee_object": cs.callee_object,
                            "is_dynamic": cs.is_dynamic,
                        },
                    )
                )

                # Connect calling origin (enclosing function or file) to call site
                source_caller = f"func:{file_path}:{cs.enclosing_function}" if cs.enclosing_function else file_node_id
                graph.add_edge(
                    EvidenceEdge(
                        source=source_caller,
                        target=call_node_id,
                        relationship="calls",
                        weight=1.0,
                    )
                )

                # Route A: Member call on imported package object, e.g. lodash.template(...)
                if cs.callee_object and cs.callee_object in package_bindings:
                    pkg_name = package_bindings[cs.callee_object]
                    sym_node_id = f"sym:{pkg_name}:{cs.symbol_name}"
                    if sym_node_id in graph.nodes:
                        graph.add_edge(
                            EvidenceEdge(
                                source=call_node_id,
                                target=sym_node_id,
                                relationship="invokes",
                                weight=1.0,
                            )
                        )

                # Route B: Direct call of named imported symbol, e.g. template(...)
                elif not cs.callee_object and cs.symbol_name in named_import_bindings:
                    pkg_name, orig_sym = named_import_bindings[cs.symbol_name]
                    sym_node_id = f"sym:{pkg_name}:{orig_sym}"
                    if sym_node_id in graph.nodes:
                        graph.add_edge(
                            EvidenceEdge(
                                source=call_node_id,
                                target=sym_node_id,
                                relationship="invokes",
                                weight=1.0,
                            )
                        )

                # Route C: Local helper call, e.g. helper(...) or utils.helper(...)
                callee_key = cs.symbol_name if not cs.callee_object else cs.callee_object
                if callee_key in local_import_bindings:
                    target_file, target_sym = local_import_bindings[callee_key]
                    func_sym = cs.symbol_name if cs.callee_object else target_sym
                    target_func_node_id = f"func:{target_file}:{func_sym}"
                    graph.add_edge(
                        EvidenceEdge(
                            source=call_node_id,
                            target=target_func_node_id,
                            relationship="dispatches_to",
                            weight=1.0,
                        )
                    )

        return graph
