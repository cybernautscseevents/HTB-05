"""Standard templates and specification factories for dynamic probes."""

from acsa.probe.models import ProbeType, SafetyConstraint
from acsa.verdict.vocabulary import Verdict


class ProbeTemplateFactory:
    """Constructs structured, defensible probe specifications based on analysis gaps."""

    @classmethod
    def default_safety_constraints(cls) -> list[str]:
        """Return mandatory safety boundaries applied to all probe specifications."""
        return [
            SafetyConstraint.NO_UNTRUSTED_SCRIPTS.value,
            SafetyConstraint.NON_DESTRUCTIVE_PAYLOAD.value,
            SafetyConstraint.ISOLATED_SANDBOX.value,
            SafetyConstraint.READ_ONLY_ACCESS.value,
            SafetyConstraint.EXPLICIT_EXECUTION_ONLY.value,
        ]

    @classmethod
    def http_input_to_sink(
        cls,
        component: str,
        symbol: str | None,
        entry_point: str | None,
        input_source: str | None,
        uncertainty_reason: str,
    ) -> dict[str, str | Verdict]:
        """Generate specification fields for HTTP_INPUT_TO_SINK probe."""
        sym_desc = symbol or f"{component} internal sink"
        entry_desc = entry_point or "application HTTP endpoint"
        input_desc = input_source or "attacker-controlled HTTP request data"

        return {
            "probe_type": ProbeType.HTTP_INPUT_TO_SINK,
            "required_observation": (
                f"Runtime trace or taint propagation showing value originating from {input_desc} "
                f"reaches {sym_desc} during request processing on {entry_desc}."
            ),
            "missing_evidence": (
                f"Empirical observation confirming runtime data flow from {input_desc} to {sym_desc}."
            ),
            "success_condition": (
                f"Execution of {sym_desc} observed with input argument derived from {input_desc} "
                f"via {entry_desc}."
            ),
            "failure_condition": (
                f"Execution of {entry_desc} completes without invoking {sym_desc}, or arguments to "
                f"{sym_desc} are statically bound constants uninfluenced by {input_desc}."
            ),
            "expected_verdict_if_confirmed": Verdict.PROVEN_EXPOSURE,
            "expected_verdict_if_not_confirmed": Verdict.PROVEN_AFFECTED,
        }

    @classmethod
    def module_resolution(
        cls,
        component: str,
        entry_point: str | None,
        uncertainty_reason: str,
    ) -> dict[str, str | Verdict]:
        """Generate specification fields for MODULE_RESOLUTION probe."""
        return {
            "probe_type": ProbeType.MODULE_RESOLUTION,
            "required_observation": (
                f"Runtime module loader trace confirming '{component}' is resolved and loaded by "
                f"the application during startup or execution."
            ),
            "missing_evidence": (
                f"Runtime module resolution event verifying '{component}' is imported or required."
            ),
            "success_condition": (
                f"Module resolver successfully loads package '{component}' into the runtime module cache."
            ),
            "failure_condition": (
                f"Module resolver never attempts or fails to resolve '{component}' during standard execution."
            ),
            "expected_verdict_if_confirmed": Verdict.POTENTIALLY_AFFECTED,
            "expected_verdict_if_not_confirmed": Verdict.PROVEN_NOT_AFFECTED,
        }

    @classmethod
    def symbol_invocation(
        cls,
        component: str,
        symbol: str | None,
        entry_point: str | None,
        uncertainty_reason: str,
    ) -> dict[str, str | Verdict]:
        """Generate specification fields for SYMBOL_INVOCATION probe."""
        sym_desc = symbol or f"{component} vulnerable symbol"
        entry_desc = entry_point or "application workflow"

        return {
            "probe_type": ProbeType.SYMBOL_INVOCATION,
            "required_observation": (
                f"Runtime function entry hook or call-stack trace confirming execution of {sym_desc} "
                f"during {entry_desc}."
            ),
            "missing_evidence": (
                f"Runtime execution log or stack frame demonstrating invocation of {sym_desc}."
            ),
            "success_condition": (
                f"Function entry probe triggers on {sym_desc} during execution of {entry_desc}."
            ),
            "failure_condition": (
                f"Application operation completes without invoking {sym_desc}."
            ),
            "expected_verdict_if_confirmed": Verdict.PROVEN_AFFECTED,
            "expected_verdict_if_not_confirmed": Verdict.PROVEN_NOT_AFFECTED,
        }

    @classmethod
    def route_execution(
        cls,
        component: str,
        entry_point: str | None,
        uncertainty_reason: str,
    ) -> dict[str, str | Verdict]:
        """Generate specification fields for ROUTE_EXECUTION probe."""
        route_desc = entry_point or f"{component} dynamic route"

        return {
            "probe_type": ProbeType.ROUTE_EXECUTION,
            "required_observation": (
                f"HTTP request to {route_desc} triggers execution of the registered router callback "
                f"or middleware in '{component}'."
            ),
            "missing_evidence": (
                f"Runtime HTTP dispatch log confirming {route_desc} activates {component} middleware."
            ),
            "success_condition": (
                f"Incoming HTTP request matches route and dispatches to handler in '{component}'."
            ),
            "failure_condition": (
                f"Incoming HTTP request does not invoke {component} handler (e.g. 404, unmounted route, "
                f"or handler unreached)."
            ),
            "expected_verdict_if_confirmed": Verdict.PROVEN_AFFECTED,
            "expected_verdict_if_not_confirmed": Verdict.PROVEN_NOT_AFFECTED,
        }

    @classmethod
    def dependency_version_confirmation(
        cls,
        component: str,
        manifest_constraint: str | None,
        uncertainty_reason: str,
    ) -> dict[str, str | Verdict]:
        """Generate specification fields for DEPENDENCY_VERSION_CONFIRMATION probe."""
        constraint_desc = manifest_constraint or "unlocked range"

        return {
            "probe_type": ProbeType.DEPENDENCY_VERSION_CONFIRMATION,
            "required_observation": (
                f"Inspection of installed package metadata (`node_modules/{component}/package.json`) "
                f"or `npm ls --json` confirming exact resolved version for constraint '{constraint_desc}'."
            ),
            "missing_evidence": (
                f"Lockfile or node_modules metadata recording exact installed version of '{component}'."
            ),
            "success_condition": (
                f"Package metadata reveals exact version of '{component}' installed on disk."
            ),
            "failure_condition": (
                f"Package '{component}' is not present in node_modules or metadata is inaccessible."
            ),
            "expected_verdict_if_confirmed": Verdict.PROVEN_AFFECTED,
            "expected_verdict_if_not_confirmed": Verdict.NOT_VERIFIED,
        }
