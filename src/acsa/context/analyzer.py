"""Context analysis engine evaluating attacker-controlled data flow to vulnerable sinks."""

import logging
import re
from typing import TYPE_CHECKING, Any

from acsa.context.models import (
    AttackerControlStatus,
    ContextAnalysis,
    DataFlowStep,
    InputSource,
    InputSourceType,
)
from acsa.evidence.graph import EvidenceGraph
from acsa.evidence.models import Evidence, EvidenceSource
from acsa.reachability.models import (
    ParsedSourceFile,
    ReachabilityState,
    SourceLocation,
)
from acsa.vulnerability.models import ApplicabilityStatus

if TYPE_CHECKING:
    from acsa.vulnerability.models import Finding

logger = logging.getLogger(__name__)

# Primary regex for attacker-controlled request inputs in Express, Fastify, Koa, and Node HTTP
REQUEST_SOURCE_PATTERN = re.compile(
    r"""\b(?:req|request|ctx\.request|ctx)\.(body|query|params|headers|cookies)(?:\.([A-Za-z0-9_$]+)|\[['"]([^'"]+)['"]\])?""",
    re.IGNORECASE,
)

# Destructuring patterns from request objects, e.g. const { tpl, input } = req.body;
DESTRUCTURE_PATTERN = re.compile(
    r"""\b(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*(?:req|request|ctx\.request|ctx)\.(body|query|params|headers|cookies)\b""",
    re.IGNORECASE,
)

# Variable assignments: const input = req.body.template; or let x = req.query.tpl;
VAR_ASSIGN_PATTERN = re.compile(
    r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+?);?$"""
)

# Dynamic property access patterns on request or objects
DYNAMIC_REQ_ACCESS_PATTERN = re.compile(
    r"""\b(?:req|request|ctx\.request|ctx)(?:\.(?:body|query|params|headers|cookies))?\s*\[\s*([^'"`\d\]][^\]]*)\s*\]"""
)


class ContextAnalyzer:
    """Evaluates whether an application exposes a meaningful attacker-controlled path to vulnerable functionality."""

    def evaluate_context(
        self,
        finding: Finding,
        parsed_files: dict[str, ParsedSourceFile],
        source_contents: dict[str, str],
        graph: EvidenceGraph,
    ) -> tuple[ContextAnalysis, list[Evidence]]:
        """Evaluate context and attacker-controlled data flow for a single finding."""
        # 1. Applicability prerequisite check
        if finding.applicability_status != ApplicabilityStatus.AFFECTED:
            return (
                ContextAnalysis(
                    status=AttackerControlStatus.NOT_ESTABLISHED,
                    uncertainty_reason="Component version is not affected by this advisory",
                    confidence=1.0,
                ),
                [],
            )

        # 2. Reachability prerequisite check
        reach = finding.reachability
        if not reach:
            return (
                ContextAnalysis(
                    status=AttackerControlStatus.UNKNOWN,
                    uncertainty_reason="Reachability analysis has not been performed",
                    missing_evidence="Static reachability evaluation is required",
                    confidence=0.5,
                ),
                [],
            )

        if reach.status == ReachabilityState.NOT_REACHABLE:
            return (
                ContextAnalysis(
                    status=AttackerControlStatus.NOT_ESTABLISHED,
                    uncertainty_reason="Vulnerable symbol is proven not reachable in application source code",
                    confidence=1.0,
                ),
                [],
            )

        if reach.status == ReachabilityState.UNKNOWN:
            return (
                ContextAnalysis(
                    status=AttackerControlStatus.UNKNOWN,
                    uncertainty_reason=reach.uncertainty_reason or "Reachability status is unknown",
                    missing_evidence="Resolution of reachability or dynamic symbol access is required",
                    confidence=reach.confidence,
                ),
                [],
            )

        # 3. Check for dynamic constructs in the reachability path
        for ep_step in reach.evidence_path:
            if ep_step.startswith("file:"):
                f_path = ep_step.split(":", 1)[1]
                if f_path in parsed_files and parsed_files[f_path].has_dynamic_constructs:
                    for d_reason in parsed_files[f_path].dynamic_construct_reasons:
                        if "dynamic" in d_reason.lower() or "eval" in d_reason.lower():
                            return (
                                ContextAnalysis(
                                    status=AttackerControlStatus.UNKNOWN,
                                    uncertainty_reason=d_reason,
                                    missing_evidence="Runtime observation of dynamic property flow is required",
                                    confidence=0.4,
                                ),
                                [],
                            )

        # 4. Locate sink call site and file
        call_site_str = reach.call_site
        if not call_site_str:
            return (
                ContextAnalysis(
                    status=AttackerControlStatus.UNKNOWN,
                    uncertainty_reason="Call site location unavailable in reachability analysis",
                    missing_evidence="Precise call site coordinates required",
                    confidence=0.5,
                ),
                [],
            )

        sink_file, sink_line_str = self._parse_location(call_site_str)
        sink_line = int(sink_line_str) if sink_line_str else 1
        target_symbol = reach.target_symbol or (
            finding.vulnerability.vulnerable_symbols[0]
            if finding.vulnerability.vulnerable_symbols
            else "unknown"
        )

        sink_location = SourceLocation(file_path=sink_file, line_number=sink_line)
        sink_name = f"{finding.component.name}.{target_symbol}()"

        # Check for dynamic request access in the sink file or caller files
        sink_file_text = source_contents.get(sink_file, "")
        if DYNAMIC_REQ_ACCESS_PATTERN.search(sink_file_text):
            return (
                ContextAnalysis(
                    status=AttackerControlStatus.UNKNOWN,
                    sink=sink_name,
                    sink_location=sink_location,
                    uncertainty_reason="Dynamic property access on request object prevents static determination",
                    missing_evidence="Runtime observation of computed property access is required",
                    confidence=0.4,
                ),
                [],
            )

        # 5. Extract arguments passed to the vulnerable call site
        sink_args = self._extract_call_arguments_at_line(
            sink_file_text, sink_line, target_symbol
        )

        # Extract entry point name from reachability
        entry_name = self._format_entry_name(reach.entry_point)

        # Route A: Direct Flow at Sink Call Site
        # e.g. lodash.template(req.body.template) or lodash.template(req.query.tpl)
        # or lodash.template(body.template) where const { body } = req;
        for arg in sink_args:
            match = REQUEST_SOURCE_PATTERN.search(arg)
            source_expr: str | None = None
            source_type_val: InputSourceType | None = None

            if match:
                src_type_str = match.group(1).lower()
                source_expr = match.group(0)
                source_type_val = self._map_source_type(src_type_str)
            else:
                # Check for aliased container property: body.template
                prop_m = re.match(
                    r"""\b([A-Za-z_$][\w$]*)\.(?:([A-Za-z0-9_$]+)|\[['"]([^'"]+)['"]\])""",
                    arg.strip(),
                )
                if prop_m:
                    c_var = prop_m.group(1)
                    p_name = prop_m.group(2) or prop_m.group(3)
                    lines = sink_file_text.splitlines()
                    c_src = self._find_container_alias(lines, sink_line - 1, c_var, sink_file)
                    if c_src:
                        src_pref, c_type_str, _c_loc = c_src
                        source_expr = f"{src_pref}.{c_type_str}.{p_name}"
                        source_type_val = self._map_source_type(c_type_str)

            if source_expr and source_type_val:
                input_source = InputSource(
                    source_type=source_type_val,
                    expression=source_expr,
                    location=sink_location,
                    entry_point=entry_name,
                )
                steps = [
                    DataFlowStep(
                        step_type="http_entry",
                        expression=entry_name,
                        location=self._parse_entry_location(reach.entry_point),
                        description=f"HTTP entry point: {entry_name}",
                    ),
                    DataFlowStep(
                        step_type="input_source",
                        expression=source_expr,
                        location=sink_location,
                        description=f"Attacker-controlled input source: {source_expr}",
                    ),
                    DataFlowStep(
                        step_type="sink_call",
                        expression=sink_name,
                        location=sink_location,
                        description=f"Vulnerable function invocation: {sink_name}",
                    ),
                ]
                flow_path = [entry_name, source_expr, sink_name, finding.vulnerability.id]
                evidence = self._build_context_evidence(
                    finding, input_source, sink_name, flow_path
                )
                return (
                    ContextAnalysis(
                        status=AttackerControlStatus.CONFIRMED,
                        source=input_source,
                        entry_point=entry_name,
                        sink=sink_name,
                        sink_location=sink_location,
                        data_flow_path=flow_path,
                        data_flow_steps=steps,
                        confidence=0.95,
                        evidence_ids=[evidence.id],
                    ),
                    [evidence],
                )

        # Route B: Local Variable Assignment Flow
        # e.g. const input = req.body.template; lodash.template(input);
        # or const { template } = req.body; lodash.template(template);
        for arg in sink_args:
            var_name = arg.strip()
            if re.match(r"^[A-Za-z_$][\w$]*$", var_name):
                # Search preceding statements in the same file/scope
                src_info = self._trace_local_variable_source(
                    sink_file_text, sink_line, var_name, sink_file
                )
                if src_info:
                    input_source, assign_step_str, assign_loc = src_info
                    input_source = input_source.model_copy(update={"entry_point": entry_name})
                    steps = [
                        DataFlowStep(
                            step_type="http_entry",
                            expression=entry_name,
                            location=self._parse_entry_location(reach.entry_point),
                            description=f"HTTP entry point: {entry_name}",
                        ),
                        DataFlowStep(
                            step_type="input_source",
                            expression=input_source.expression,
                            location=input_source.location,
                            description=f"Attacker-controlled input source: {input_source.expression}",
                        ),
                        DataFlowStep(
                            step_type="variable_assignment",
                            expression=assign_step_str,
                            location=assign_loc,
                            description=f"Local assignment: {assign_step_str}",
                        ),
                        DataFlowStep(
                            step_type="sink_call",
                            expression=sink_name,
                            location=sink_location,
                            description=f"Vulnerable function invocation: {sink_name}",
                        ),
                    ]
                    flow_path = [
                        entry_name,
                        input_source.expression,
                        sink_name,
                        finding.vulnerability.id,
                    ]
                    evidence = self._build_context_evidence(
                        finding, input_source, sink_name, flow_path
                    )
                    return (
                        ContextAnalysis(
                            status=AttackerControlStatus.CONFIRMED,
                            source=input_source,
                            entry_point=entry_name,
                            sink=sink_name,
                            sink_location=sink_location,
                            data_flow_path=flow_path,
                            data_flow_steps=steps,
                            confidence=0.95,
                            evidence_ids=[evidence.id],
                        ),
                        [evidence],
                    )

        # Route C: Simple Function Parameter Propagation (1-Hop / Multi-Hop)
        # e.g. function renderUserTemplate(input) { lodash.template(input); }
        # called from router.post("/render", (req, res) => { renderUserTemplate(req.body.template); });
        prop_res = self._trace_parameter_propagation(
            finding=finding,
            sink_file=sink_file,
            sink_line=sink_line,
            sink_args=sink_args,
            sink_name=sink_name,
            sink_location=sink_location,
            reach=reach,
            entry_name=entry_name,
            source_contents=source_contents,
            parsed_files=parsed_files,
        )
        if prop_res:
            analysis, ev_list = prop_res
            return analysis, ev_list

        # Route D: No External Input Source Established
        # Vulnerable function is reachable, but called with static arguments or constants
        return (
            ContextAnalysis(
                status=AttackerControlStatus.NOT_ESTABLISHED,
                entry_point=entry_name,
                sink=sink_name,
                sink_location=sink_location,
                uncertainty_reason="Vulnerable function reachable from internal helper, but no external input source was established",
                confidence=0.9,
            ),
            [],
        )

    def _trace_parameter_propagation(
        self,
        finding: "Finding",
        sink_file: str,
        sink_line: int,
        sink_args: list[str],
        sink_name: str,
        sink_location: SourceLocation,
        reach: Any,
        entry_name: str,
        source_contents: dict[str, str],
        parsed_files: dict[str, ParsedSourceFile],
    ) -> tuple[ContextAnalysis, list[Evidence]] | None:
        """Trace function parameter propagation across caller-callee boundaries."""
        if not sink_args:
            return None

        primary_arg = sink_args[0].strip()
        if not re.match(r"^[A-Za-z_$][\w$]*$", primary_arg):
            return None

        # 1. Determine enclosing function and parameter index in sink file
        parsed_sink = parsed_files.get(sink_file)
        if not parsed_sink:
            return None

        enclosing_func_name: str | None = None
        for func in parsed_sink.functions:
            if (
                func.location.line_number
                and func.location.line_number <= sink_line
            ):
                enclosing_func_name = func.name

        if not enclosing_func_name:
            return None

        # Extract function parameter names
        sink_text = source_contents.get(sink_file, "")
        func_params = self._extract_function_param_names(
            sink_text, enclosing_func_name
        )
        if primary_arg not in func_params:
            return None
        param_index = func_params.index(primary_arg)

        # 2. Inspect evidence path to find callers of enclosing_func_name
        for step in reach.evidence_path:
            if step.startswith("call:") and enclosing_func_name in step:
                parts = step.split(":")
                caller_file = parts[1]
                caller_line = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 1

                caller_text = source_contents.get(caller_file, "")
                caller_args = self._extract_call_arguments_at_line(
                    caller_text, caller_line, enclosing_func_name
                )
                if len(caller_args) > param_index:
                    passed_arg = caller_args[param_index].strip()

                    # Check if passed_arg is a direct request source
                    req_match = REQUEST_SOURCE_PATTERN.search(passed_arg)
                    if req_match:
                        src_type_str = req_match.group(1).lower()
                        source_expr = req_match.group(0)
                        source_type = self._map_source_type(src_type_str)
                        caller_loc = SourceLocation(
                            file_path=caller_file, line_number=caller_line
                        )
                        input_source = InputSource(
                            source_type=source_type,
                            expression=source_expr,
                            location=caller_loc,
                            entry_point=entry_name,
                        )
                        steps = [
                            DataFlowStep(
                                step_type="http_entry",
                                expression=entry_name,
                                location=self._parse_entry_location(reach.entry_point),
                                description=f"HTTP entry point: {entry_name}",
                            ),
                            DataFlowStep(
                                step_type="input_source",
                                expression=source_expr,
                                location=caller_loc,
                                description=f"Attacker-controlled input source: {source_expr}",
                            ),
                            DataFlowStep(
                                step_type="parameter_passing",
                                expression=f"{enclosing_func_name}({passed_arg})",
                                location=caller_loc,
                                description=f"Inter-procedural call passing input: {enclosing_func_name}({passed_arg})",
                            ),
                            DataFlowStep(
                                step_type="sink_call",
                                expression=sink_name,
                                location=sink_location,
                                description=f"Vulnerable function invocation: {sink_name}",
                            ),
                        ]
                        flow_path = [
                            entry_name,
                            source_expr,
                            f"{enclosing_func_name}({primary_arg})",
                            sink_name,
                            finding.vulnerability.id,
                        ]
                        evidence = self._build_context_evidence(
                            finding, input_source, sink_name, flow_path
                        )
                        return (
                            ContextAnalysis(
                                status=AttackerControlStatus.CONFIRMED,
                                source=input_source,
                                entry_point=entry_name,
                                sink=sink_name,
                                sink_location=sink_location,
                                data_flow_path=flow_path,
                                data_flow_steps=steps,
                                confidence=0.95,
                                evidence_ids=[evidence.id],
                            ),
                            [evidence],
                        )

                    # Check if passed_arg is a local variable in caller
                    local_src = self._trace_local_variable_source(
                        caller_text, caller_line, passed_arg, caller_file
                    )
                    if local_src:
                        input_source, _assign_str, _ = local_src
                        input_source = input_source.model_copy(update={"entry_point": entry_name})
                        caller_loc = SourceLocation(
                            file_path=caller_file, line_number=caller_line
                        )
                        steps = [
                            DataFlowStep(
                                step_type="http_entry",
                                expression=entry_name,
                                location=self._parse_entry_location(reach.entry_point),
                                description=f"HTTP entry point: {entry_name}",
                            ),
                            DataFlowStep(
                                step_type="input_source",
                                expression=input_source.expression,
                                location=input_source.location,
                                description=f"Attacker-controlled input source: {input_source.expression}",
                            ),
                            DataFlowStep(
                                step_type="parameter_passing",
                                expression=f"{enclosing_func_name}({passed_arg})",
                                location=caller_loc,
                                description=f"Inter-procedural parameter propagation: {enclosing_func_name}({passed_arg})",
                            ),
                            DataFlowStep(
                                step_type="sink_call",
                                expression=sink_name,
                                location=sink_location,
                                description=f"Vulnerable function invocation: {sink_name}",
                            ),
                        ]
                        flow_path = [
                            entry_name,
                            input_source.expression,
                            f"{enclosing_func_name}({primary_arg})",
                            sink_name,
                            finding.vulnerability.id,
                        ]
                        evidence = self._build_context_evidence(
                            finding, input_source, sink_name, flow_path
                        )
                        return (
                            ContextAnalysis(
                                status=AttackerControlStatus.CONFIRMED,
                                source=input_source,
                                entry_point=entry_name,
                                sink=sink_name,
                                sink_location=sink_location,
                                data_flow_path=flow_path,
                                data_flow_steps=steps,
                                confidence=0.95,
                                evidence_ids=[evidence.id],
                            ),
                            [evidence],
                        )

        return None

    def _trace_local_variable_source(
        self,
        file_text: str,
        current_line: int,
        var_name: str,
        file_path: str,
    ) -> tuple[InputSource, str, SourceLocation] | None:
        """Trace a local variable backwards to see if it was assigned from an attacker source."""
        lines = file_text.splitlines()
        # Look backwards from current_line - 1 up to start of file (or scope)
        search_range = range(max(0, current_line - 1), 0, -1)

        for line_idx in search_range:
            line_str = lines[line_idx - 1].strip()

            # 1. Direct assignment: const var_name = req.body.template;
            for m in VAR_ASSIGN_PATTERN.finditer(line_str):
                assigned_var = m.group(1)
                assigned_rhs = m.group(2)
                if assigned_var == var_name:
                    # 1a. Direct request source: const var_name = req.body.template;
                    req_match = REQUEST_SOURCE_PATTERN.search(assigned_rhs)
                    if req_match:
                        src_type_str = req_match.group(1).lower()
                        source_expr = req_match.group(0)
                        source_type = self._map_source_type(src_type_str)
                        loc = SourceLocation(file_path=file_path, line_number=line_idx)
                        input_source = InputSource(
                            source_type=source_type,
                            expression=source_expr,
                            location=loc,
                        )
                        return input_source, f"const {var_name} = {source_expr}", loc

                    # 1b. Aliased container property: const template = body.template;
                    # where body was destructured: const { body } = req; or const body = req.body;
                    prop_match = re.match(
                        r"""\b([A-Za-z_$][\w$]*)\.(?:([A-Za-z0-9_$]+)|\[['"]([^'"]+)['"]\])""",
                        assigned_rhs.strip(),
                    )
                    if prop_match:
                        container_var = prop_match.group(1)
                        prop_name = prop_match.group(2) or prop_match.group(3)
                        container_src = self._find_container_alias(
                            lines, line_idx - 1, container_var, file_path
                        )
                        if container_src:
                            src_prefix, c_type_str, _c_loc = container_src
                            source_expr = f"{src_prefix}.{c_type_str}.{prop_name}"
                            source_type = self._map_source_type(c_type_str)
                            loc = SourceLocation(file_path=file_path, line_number=line_idx)
                            input_source = InputSource(
                                source_type=source_type,
                                expression=source_expr,
                                location=loc,
                            )
                            return (
                                input_source,
                                f"const {var_name} = {container_var}.{prop_name} (from {src_prefix}.{c_type_str})",
                                loc,
                            )

            # 2. Destructuring: const { var_name } = req.body;
            for dm in DESTRUCTURE_PATTERN.finditer(line_str):
                destruct_vars = [v.strip().split(":")[0].strip() for v in dm.group(1).split(",")]
                if var_name in destruct_vars:
                    src_type_str = dm.group(2).lower()
                    source_expr = f"req.{src_type_str}.{var_name}"
                    source_type = self._map_source_type(src_type_str)
                    loc = SourceLocation(file_path=file_path, line_number=line_idx)
                    input_source = InputSource(
                        source_type=source_type,
                        expression=source_expr,
                        location=loc,
                    )
                    return input_source, f"const {{ {var_name} }} = req.{src_type_str}", loc

            # 3. Sub-destructuring from an aliased container: const { template } = body;
            sub_dm = re.search(
                r"""\b(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*([A-Za-z_$][\w$]*)\b""",
                line_str,
            )
            if sub_dm:
                destruct_vars = [v.strip().split(":")[0].strip() for v in sub_dm.group(1).split(",")]
                container_var = sub_dm.group(2)
                if var_name in destruct_vars:
                    container_src = self._find_container_alias(
                        lines, line_idx - 1, container_var, file_path
                    )
                    if container_src:
                        src_prefix, c_type_str, _c_loc = container_src
                        source_expr = f"{src_prefix}.{c_type_str}.{var_name}"
                        source_type = self._map_source_type(c_type_str)
                        loc = SourceLocation(file_path=file_path, line_number=line_idx)
                        input_source = InputSource(
                            source_type=source_type,
                            expression=source_expr,
                            location=loc,
                        )
                        return (
                            input_source,
                            f"const {{ {var_name} }} = {container_var} (from {src_prefix}.{c_type_str})",
                            loc,
                        )

        return None

    def _find_container_alias(
        self, lines: list[str], max_line: int, container_var: str, file_path: str
    ) -> tuple[str, str, SourceLocation] | None:
        """Find if container_var (e.g. body, query) was aliased from req/request in preceding lines."""
        for idx in range(max(0, max_line), 0, -1):
            line = lines[idx - 1].strip()

            # Pattern A: const { body } = req; or const { body, query } = request;
            req_destruct = re.search(
                r"""\b(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*(req|request|ctx\.request|ctx)\b""",
                line,
                re.IGNORECASE,
            )
            if req_destruct:
                items = [v.strip().split(":")[0].strip() for v in req_destruct.group(1).split(",")]
                if container_var in items:
                    req_obj = req_destruct.group(2)
                    c_type = container_var.lower()
                    if c_type in ("body", "query", "params", "headers", "cookies"):
                        return req_obj, c_type, SourceLocation(file_path=file_path, line_number=idx)

            # Pattern B: const body = req.body; or let query = request.query;
            assign_m = re.search(
                r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(req|request|ctx\.request|ctx)\.(body|query|params|headers|cookies)\b""",
                line,
                re.IGNORECASE,
            )
            if assign_m and assign_m.group(1) == container_var:
                req_obj = assign_m.group(2)
                c_type = assign_m.group(3).lower()
                return req_obj, c_type, SourceLocation(file_path=file_path, line_number=idx)

        return None

    def _extract_call_arguments_at_line(
        self, file_text: str, line_number: int, symbol_name: str
    ) -> list[str]:
        """Extract arguments passed to a function or method invocation at a specific line."""
        lines = file_text.splitlines()
        if not (1 <= line_number <= len(lines)):
            return []

        # Inspect target line and up to 3 following lines in case of multiline call
        window = " ".join(lines[line_number - 1 : min(len(lines), line_number + 3)])

        # Match symbol_name(...)
        pattern = re.compile(
            rf"""(?:[A-Za-z_$][\w$]*\.)?{re.escape(symbol_name)}\s*\(([^)]*)\)"""
        )
        match = pattern.search(window)
        if match:
            raw_args = match.group(1).strip()
            if not raw_args:
                return []
            # Split comma separated arguments (respecting simple parens/quotes)
            return [arg.strip() for arg in raw_args.split(",") if arg.strip()]

        return []

    def _extract_function_param_names(
        self, file_text: str, func_name: str
    ) -> list[str]:
        """Extract the parameter list of a declared function."""
        # function foo(a, b) or const foo = (a, b) =>
        pattern = re.compile(
            rf"""(?:function\s+{re.escape(func_name)}|\b{re.escape(func_name)}\s*=\s*(?:async\s*)?)\s*\(([^)]*)\)"""
        )
        match = pattern.search(file_text)
        if match:
            raw_params = match.group(1).strip()
            if not raw_params:
                return []
            params = []
            for p in raw_params.split(","):
                cand = p.strip().split("=")[0].strip()  # Remove default values
                if re.match(r"^[A-Za-z_$][\w$]*$", cand):
                    params.append(cand)
            return params
        return []

    def _map_source_type(self, raw: str) -> InputSourceType:
        """Map raw request member to InputSourceType enum."""
        mapping = {
            "body": InputSourceType.BODY,
            "query": InputSourceType.QUERY,
            "params": InputSourceType.PARAMS,
            "headers": InputSourceType.HEADERS,
            "cookies": InputSourceType.COOKIES,
        }
        return mapping.get(raw.lower(), InputSourceType.CUSTOM)

    def _parse_location(self, loc_str: str) -> tuple[str, str | None]:
        """Parse 'path/to/file.js:12' into (file_path, line_str)."""
        if ":" in loc_str:
            parts = loc_str.split(":")
            return parts[0], parts[1]
        return loc_str, None

    def _parse_entry_location(self, entry_str: str | None) -> SourceLocation | None:
        """Extract SourceLocation from entry point string if available."""
        if not entry_str:
            return None
        parts = entry_str.split(":")
        if len(parts) >= 2 and parts[1].isdigit():
            return SourceLocation(file_path=parts[0], line_number=int(parts[1]))
        return None

    def _format_entry_name(self, entry_str: str | None) -> str:
        """Format entry point string into clean display name."""
        if not entry_str:
            return "Application Entry"
        m = re.search(r"\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+/[^\s)]*", entry_str)
        if m:
            return m.group(0)
        parts = entry_str.split(":")
        if len(parts) >= 3:
            return parts[2]
        return entry_str

    def _build_context_evidence(
        self,
        finding: "Finding",
        input_source: InputSource,
        sink_name: str,
        flow_path: list[str],
    ) -> Evidence:
        """Construct a verifiable Evidence object recording attacker control proof."""
        return Evidence(
            source=EvidenceSource.CALL_GRAPH,
            description=(
                f"Verified attacker-controlled path established from {input_source.expression} "
                f"to vulnerable sink {sink_name} ({finding.vulnerability.id})"
            ),
            confidence=0.95,
            location=str(input_source.location),
            data={
                "advisory_id": finding.vulnerability.id,
                "package": finding.component.name,
                "input_source": input_source.expression,
                "input_type": input_source.source_type.value,
                "sink": sink_name,
                "entry_point": input_source.entry_point,
                "flow_path": flow_path,
            },
        )
