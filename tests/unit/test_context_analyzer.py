"""Unit tests for ContextAnalyzer evaluating attacker-controlled data flow."""

from acsa.context.analyzer import ContextAnalyzer
from acsa.context.models import AttackerControlStatus
from acsa.evidence.graph import EvidenceGraph
from acsa.inventory.models import Component
from acsa.reachability.models import (
    CallSite,
    EntryPoint,
    ParsedSourceFile,
    ReachabilityAnalysis,
    ReachabilityState,
    SourceLocation,
)
from acsa.vulnerability.models import ApplicabilityStatus, Finding, Vulnerability


def test_context_direct_flow() -> None:
    """Direct invocation: lodash.template(req.query.tpl) produces CONFIRMED."""
    vuln = Vulnerability(
        id="GHSA-29mw-wpgm-hmr9",
        summary="Prototype Pollution in lodash",
        vulnerable_symbols=["template"],
        affected_ranges=["< 4.17.21"],
    )
    comp = Component(name="lodash", version="4.17.19")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        applicability_status=ApplicabilityStatus.AFFECTED,
        reachability=ReachabilityAnalysis(
            status=ReachabilityState.REACHABLE,
            target_symbol="template",
            entry_point="src/server.js:6:GET /render (app)",
            call_site="src/server.js:7",
            evidence_path=[
                "entry:src/server.js:6:GET /render (app)",
                "call:src/server.js:7:template",
                "sym:lodash:template",
            ],
        ),
    )

    source_code = """
const express = require("express");
const lodash = require("lodash");
const app = express();

app.get("/render", (req, res) => {
  const compiled = lodash.template(req.query.tpl);
  res.send(compiled());
});
"""
    parsed_files = {
        "src/server.js": ParsedSourceFile(
            file_path="src/server.js",
            entry_points=[
                EntryPoint(
                    name="GET /render (app)",
                    entry_type="route",
                    location=SourceLocation(file_path="src/server.js", line_number=6),
                )
            ],
            call_sites=[
                CallSite(
                    symbol_name="template",
                    callee_object="lodash",
                    location=SourceLocation(file_path="src/server.js", line_number=7),
                )
            ],
        )
    }

    analyzer = ContextAnalyzer()
    analysis, evidence = analyzer.evaluate_context(
        finding=finding,
        parsed_files=parsed_files,
        source_contents={"src/server.js": source_code},
        graph=EvidenceGraph(),
    )

    assert analysis.status == AttackerControlStatus.CONFIRMED
    assert analysis.source is not None
    assert analysis.source.expression == "req.query.tpl"
    assert analysis.entry_point == "GET /render"
    assert "lodash.template" in (analysis.sink or "")
    assert len(evidence) == 1
    assert "req.query.tpl" in evidence[0].description


def test_context_local_variable_flow() -> None:
    """Local variable propagation: const input = req.body.template; lodash.template(input) produces CONFIRMED."""
    vuln = Vulnerability(
        id="GHSA-29mw-wpgm-hmr9",
        summary="Prototype Pollution in lodash",
        vulnerable_symbols=["template"],
    )
    comp = Component(name="lodash", version="4.17.19")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        applicability_status=ApplicabilityStatus.AFFECTED,
        reachability=ReachabilityAnalysis(
            status=ReachabilityState.REACHABLE,
            target_symbol="template",
            entry_point="src/server.js:6:POST /render (app)",
            call_site="src/server.js:8",
            evidence_path=[
                "entry:src/server.js:6:POST /render (app)",
                "call:src/server.js:8:template",
                "sym:lodash:template",
            ],
        ),
    )

    source_code = """
const express = require("express");
const lodash = require("lodash");
const app = express();

app.post("/render", (req, res) => {
  const input = req.body.template;
  const compiled = lodash.template(input);
  res.send(compiled());
});
"""
    parsed_files = {
        "src/server.js": ParsedSourceFile(
            file_path="src/server.js",
            call_sites=[
                CallSite(
                    symbol_name="template",
                    callee_object="lodash",
                    location=SourceLocation(file_path="src/server.js", line_number=8),
                )
            ],
        )
    }

    analyzer = ContextAnalyzer()
    analysis, _evidence = analyzer.evaluate_context(
        finding=finding,
        parsed_files=parsed_files,
        source_contents={"src/server.js": source_code},
        graph=EvidenceGraph(),
    )

    assert analysis.status == AttackerControlStatus.CONFIRMED
    assert analysis.source is not None
    assert analysis.source.expression == "req.body.template"
    assert len(analysis.data_flow_steps) >= 3


def test_context_dynamic_computed_flow_produces_unknown() -> None:
    """Dynamic property access on request produces UNKNOWN with preserved uncertainty and missing evidence."""
    vuln = Vulnerability(
        id="GHSA-29mw-wpgm-hmr9",
        summary="Prototype Pollution in lodash",
        vulnerable_symbols=["template"],
    )
    comp = Component(name="lodash", version="4.17.19")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        applicability_status=ApplicabilityStatus.AFFECTED,
        reachability=ReachabilityAnalysis(
            status=ReachabilityState.REACHABLE,
            target_symbol="template",
            entry_point="src/server.js:6:POST /dynamic (app)",
            call_site="src/server.js:9",
            evidence_path=[
                "entry:src/server.js:6:POST /dynamic (app)",
                "call:src/server.js:9:template",
                "sym:lodash:template",
            ],
        ),
    )

    source_code = """
const express = require("express");
const lodash = require("lodash");
const app = express();

app.post("/dynamic", (req, res) => {
  const key = req.headers["x-dynamic-key"];
  const dynamicInput = req.body[key];
  const compiled = lodash.template(dynamicInput);
  res.send(compiled());
});
"""
    parsed_files = {
        "src/server.js": ParsedSourceFile(
            file_path="src/server.js",
            call_sites=[
                CallSite(
                    symbol_name="template",
                    callee_object="lodash",
                    location=SourceLocation(file_path="src/server.js", line_number=9),
                )
            ],
        )
    }

    analyzer = ContextAnalyzer()
    analysis, _evidence = analyzer.evaluate_context(
        finding=finding,
        parsed_files=parsed_files,
        source_contents={"src/server.js": source_code},
        graph=EvidenceGraph(),
    )

    assert analysis.status == AttackerControlStatus.UNKNOWN
    assert analysis.uncertainty_reason is not None
    assert "Dynamic property access" in analysis.uncertainty_reason
    assert analysis.missing_evidence is not None
    assert "Runtime observation" in analysis.missing_evidence


def test_context_static_call_produces_not_established() -> None:
    """Invocation with constant static arguments produces NOT_ESTABLISHED."""
    vuln = Vulnerability(
        id="GHSA-29mw-wpgm-hmr9",
        summary="Prototype Pollution in lodash",
        vulnerable_symbols=["template"],
    )
    comp = Component(name="lodash", version="4.17.19")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        applicability_status=ApplicabilityStatus.AFFECTED,
        reachability=ReachabilityAnalysis(
            status=ReachabilityState.REACHABLE,
            target_symbol="template",
            entry_point="src/server.js:6:GET /welcome (app)",
            call_site="src/server.js:7",
            evidence_path=[
                "entry:src/server.js:6:GET /welcome (app)",
                "call:src/server.js:7:template",
                "sym:lodash:template",
            ],
        ),
    )

    source_code = """
const express = require("express");
const lodash = require("lodash");
const app = express();

app.get("/welcome", (req, res) => {
  const compiled = lodash.template("<h1>Static HTML</h1>");
  res.send(compiled());
});
"""
    parsed_files = {
        "src/server.js": ParsedSourceFile(
            file_path="src/server.js",
            call_sites=[
                CallSite(
                    symbol_name="template",
                    callee_object="lodash",
                    location=SourceLocation(file_path="src/server.js", line_number=7),
                )
            ],
        )
    }

    analyzer = ContextAnalyzer()
    analysis, _evidence = analyzer.evaluate_context(
        finding=finding,
        parsed_files=parsed_files,
        source_contents={"src/server.js": source_code},
        graph=EvidenceGraph(),
    )

    assert analysis.status == AttackerControlStatus.NOT_ESTABLISHED
    assert analysis.uncertainty_reason is not None
    assert "no external input source was established" in analysis.uncertainty_reason


def test_context_container_alias_destructuring() -> None:
    """Aliased destructuring: const { body } = req; const template = body.template; lodash.template(template)."""
    vuln = Vulnerability(
        id="GHSA-29mw-wpgm-hmr9",
        summary="Prototype Pollution in lodash",
        vulnerable_symbols=["template"],
    )
    comp = Component(name="lodash", version="4.17.19")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        applicability_status=ApplicabilityStatus.AFFECTED,
        reachability=ReachabilityAnalysis(
            status=ReachabilityState.REACHABLE,
            target_symbol="template",
            entry_point="src/server.js:6:POST /render (app)",
            call_site="src/server.js:9",
            evidence_path=[
                "entry:src/server.js:6:POST /render (app)",
                "call:src/server.js:9:template",
                "sym:lodash:template",
            ],
        ),
    )

    source_code = """
const express = require("express");
const lodash = require("lodash");
const app = express();

app.post("/render", (req, res) => {
  const { body } = req;
  const template = body.template;
  const compiled = lodash.template(template);
  res.send(compiled());
});
"""
    parsed_files = {
        "src/server.js": ParsedSourceFile(
            file_path="src/server.js",
            call_sites=[
                CallSite(
                    symbol_name="template",
                    callee_object="lodash",
                    location=SourceLocation(file_path="src/server.js", line_number=9),
                )
            ],
        )
    }

    analyzer = ContextAnalyzer()
    analysis, evidence = analyzer.evaluate_context(
        finding=finding,
        parsed_files=parsed_files,
        source_contents={"src/server.js": source_code},
        graph=EvidenceGraph(),
    )

    assert analysis.status == AttackerControlStatus.CONFIRMED
    assert analysis.source is not None
    assert "req.body.template" in analysis.source.expression
    assert analysis.entry_point == "POST /render"
    assert len(evidence) == 1


def test_context_fastify_request_input() -> None:
    """Fastify request input: fastify.post + request.body.template produces CONFIRMED."""
    vuln = Vulnerability(
        id="GHSA-29mw-wpgm-hmr9",
        summary="Prototype Pollution in lodash",
        vulnerable_symbols=["template"],
    )
    comp = Component(name="lodash", version="4.17.19")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        applicability_status=ApplicabilityStatus.AFFECTED,
        reachability=ReachabilityAnalysis(
            status=ReachabilityState.REACHABLE,
            target_symbol="template",
            entry_point="src/server.js:4:POST /render (fastify)",
            call_site="src/server.js:5",
            evidence_path=[
                "entry:src/server.js:4:POST /render (fastify)",
                "call:src/server.js:5:template",
                "sym:lodash:template",
            ],
        ),
    )

    source_code = """const fastify = require("fastify")();
const lodash = require("lodash");

fastify.post("/render", async (request, reply) => {
  const compiled = lodash.template(request.body.template);
  return compiled();
});"""
    parsed_files = {
        "src/server.js": ParsedSourceFile(
            file_path="src/server.js",
            call_sites=[
                CallSite(
                    symbol_name="template",
                    callee_object="lodash",
                    location=SourceLocation(file_path="src/server.js", line_number=5),
                )
            ],
        )
    }

    analyzer = ContextAnalyzer()
    analysis, evidence = analyzer.evaluate_context(
        finding=finding,
        parsed_files=parsed_files,
        source_contents={"src/server.js": source_code},
        graph=EvidenceGraph(),
    )

    assert analysis.status == AttackerControlStatus.CONFIRMED
    assert analysis.source is not None
    assert analysis.source.expression == "request.body.template"
    assert analysis.entry_point == "POST /render"
    assert len(evidence) == 1


def test_context_helper_parameter_propagation_with_local_var() -> None:
    """Helper propagation: req.body.template -> local variable -> helper(input) -> lodash.template."""
    from acsa.reachability.models import FunctionDefinition

    vuln = Vulnerability(
        id="GHSA-29mw-wpgm-hmr9",
        summary="Prototype Pollution in lodash",
        vulnerable_symbols=["template"],
    )
    comp = Component(name="lodash", version="4.17.19")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        applicability_status=ApplicabilityStatus.AFFECTED,
        reachability=ReachabilityAnalysis(
            status=ReachabilityState.REACHABLE,
            target_symbol="template",
            entry_point="src/server.js:9:POST /render (app)",
            call_site="src/server.js:6",
            evidence_path=[
                "entry:src/server.js:9:POST /render (app)",
                "call:src/server.js:11:renderHelper",
                "call:src/server.js:6:template",
                "sym:lodash:template",
            ],
        ),
    )

    source_code = """const express = require("express");
const lodash = require("lodash");
const app = express();

function renderHelper(input) {
  return lodash.template(input);
}

app.post("/render", (req, res) => {
  const template = req.body.template;
  const compiled = renderHelper(template);
  res.send(compiled());
});"""
    parsed_files = {
        "src/server.js": ParsedSourceFile(
            file_path="src/server.js",
            functions=[
                FunctionDefinition(
                    name="renderHelper",
                    location=SourceLocation(file_path="src/server.js", line_number=5),
                )
            ],
            call_sites=[
                CallSite(
                    symbol_name="template",
                    callee_object="lodash",
                    location=SourceLocation(file_path="src/server.js", line_number=6),
                ),
                CallSite(
                    symbol_name="renderHelper",
                    callee_object=None,
                    location=SourceLocation(file_path="src/server.js", line_number=11),
                ),
            ],
        )
    }

    analyzer = ContextAnalyzer()
    analysis, evidence = analyzer.evaluate_context(
        finding=finding,
        parsed_files=parsed_files,
        source_contents={"src/server.js": source_code},
        graph=EvidenceGraph(),
    )

    assert analysis.status == AttackerControlStatus.CONFIRMED
    assert analysis.source is not None
    assert analysis.source.expression == "req.body.template"
    assert "renderHelper" in analysis.data_flow_path[2]
    assert len(evidence) == 1

