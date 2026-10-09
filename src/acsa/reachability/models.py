"""Domain models for static reachability analysis, import/call graph, and exposure paths."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ReachabilityState(StrEnum):
    """Classification of application reachability to vulnerable dependencies."""

    REACHABLE = "REACHABLE"
    """Verified static evidence establishes an executable path from an application entry point to the vulnerable symbol."""

    NOT_REACHABLE = "NOT_REACHABLE"
    """Verified static analysis confirms the vulnerable package/symbol is never referenced or called in application paths."""

    UNKNOWN = "UNKNOWN"
    """Analysis cannot determine reachability due to dynamic imports, reflection, or missing advisory symbols (UNKNOWN != SAFE)."""


class SourceLocation(BaseModel):
    """Source file and line location."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    file_path: str = Field(description="Workspace-relative path to source file")
    line_number: int | None = Field(default=None, description="1-indexed line number")

    def __str__(self) -> str:
        if self.line_number is not None:
            return f"{self.file_path}:{self.line_number}"
        return self.file_path


class ImportStatement(BaseModel):
    """Parsed import or require statement."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    module_name: str = Field(description="Package or local module path being imported")
    symbol_name: str = Field(description="Imported symbol name (e.g. default, template, *)")
    alias: str = Field(description="Local variable or binding name in this file")
    is_local: bool = Field(default=False, description="Whether import refers to a local file")
    is_namespace: bool = Field(default=False, description="Whether this is a namespace import (import * as x)")
    is_dynamic: bool = Field(default=False, description="Whether this is dynamic require or import")
    location: SourceLocation = Field(description="Source location where import occurs")


class CallSite(BaseModel):
    """Invocation or reference to a symbol or method."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    symbol_name: str = Field(description="Function, method, or property name invoked")
    callee_object: str | None = Field(default=None, description="Object or module prefix if member call (e.g. 'pkg')")
    is_dynamic: bool = Field(default=False, description="Whether call uses dynamic invocation or computed access")
    location: SourceLocation = Field(description="Source location where call occurs")
    raw_expression: str | None = Field(default=None, description="Original expression text")
    enclosing_function: str | None = Field(default=None, description="Name of enclosing function if inside one")


class EntryPoint(BaseModel):
    """Application entry point where execution begins (route, HTTP handler, CLI, export)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(description="Descriptive name of entry point (e.g. GET /api/user)")
    entry_type: str = Field(description="Category: route, http_handler, exported_function, cli_entry")
    location: SourceLocation = Field(description="Source location of entry point definition")
    handler_symbol: str | None = Field(default=None, description="Associated handler function name if known")


class FunctionDefinition(BaseModel):
    """Function or method definition within a source file."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(description="Function identifier")
    location: SourceLocation = Field(description="Location where function is declared")
    is_exported: bool = Field(default=False, description="Whether function is exported from module")
    calls: list[CallSite] = Field(default_factory=list, description="Call sites invoked inside this function")


class ParsedSourceFile(BaseModel):
    """Consolidated static analysis extracted from a single source file."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    file_path: str = Field(description="Workspace-relative path to source file")
    imports: list[ImportStatement] = Field(default_factory=list, description="Parsed imports and requires")
    exports: list[str] = Field(default_factory=list, description="Exported identifiers")
    entry_points: list[EntryPoint] = Field(default_factory=list, description="Identified entry points")
    call_sites: list[CallSite] = Field(default_factory=list, description="All call sites in file")
    functions: list[FunctionDefinition] = Field(default_factory=list, description="Function declarations")
    has_dynamic_constructs: bool = Field(default=False, description="Whether dynamic eval/require/access occurs")
    dynamic_construct_reasons: list[str] = Field(default_factory=list, description="Details of dynamic constructs")


class ReachabilityAnalysis(BaseModel):
    """Outcome of static reachability evaluation for a specific finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: ReachabilityState = Field(
        default=ReachabilityState.UNKNOWN,
        description="Reachability classification (REACHABLE, NOT_REACHABLE, UNKNOWN)",
    )
    target_symbol: str | None = Field(
        default=None,
        description="Vulnerable symbol evaluated",
    )
    entry_point: str | None = Field(
        default=None,
        description="Application entry point where execution commences (e.g. src/routes/user.ts:12)",
    )
    call_site: str | None = Field(
        default=None,
        description="Call site location where vulnerable functionality is invoked",
    )
    evidence_path: list[str] = Field(
        default_factory=list,
        description="Step-by-step traversal path: [entry -> helper -> package -> symbol]",
    )
    uncertainty_reason: str | None = Field(
        default=None,
        description="Reason for UNKNOWN classification (e.g. dynamic require, missing symbols)",
    )
    missing_evidence: str | None = Field(
        default=None,
        description="Missing evidence needed to resolve reachability, preparing dynamic probe",
    )
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence score for reachability conclusion",
    )
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="IDs of verifiable Evidence nodes supporting this result",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional analysis properties",
    )
