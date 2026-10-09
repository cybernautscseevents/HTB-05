"""ACSA Phase 3 Reachability Analysis module."""

from acsa.reachability.discovery import SourceDiscovery
from acsa.reachability.engine import ReachabilityEngine
from acsa.reachability.graph_builder import ReachabilityGraphBuilder
from acsa.reachability.local_resolution import LocalModuleResolver
from acsa.reachability.models import (
    CallSite,
    EntryPoint,
    FunctionDefinition,
    ImportStatement,
    ParsedSourceFile,
    ReachabilityAnalysis,
    ReachabilityState,
    SourceLocation,
)
from acsa.reachability.parser import JavaScriptSourceParser
from acsa.reachability.service import ReachabilityService

__all__ = [
    "CallSite",
    "EntryPoint",
    "FunctionDefinition",
    "ImportStatement",
    "JavaScriptSourceParser",
    "LocalModuleResolver",
    "ParsedSourceFile",
    "ReachabilityAnalysis",
    "ReachabilityEngine",
    "ReachabilityGraphBuilder",
    "ReachabilityService",
    "ReachabilityState",
    "SourceDiscovery",
    "SourceLocation",
]
