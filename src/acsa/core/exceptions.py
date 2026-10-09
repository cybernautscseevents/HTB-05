"""ACSA exception hierarchy."""


class ACSAError(Exception):
    """Base exception for all ACSA domain and runtime errors."""


class ConfigurationError(ACSAError):
    """Raised when environment or runtime configuration is invalid."""


class PathTraversalError(ACSAError):
    """Raised when a path traverses outside of the authorized boundary."""


class WorkspaceSecurityError(ACSAError):
    """Raised when workspace sandbox security rules or scan limits are violated."""


class ModelValidationError(ACSAError):
    """Raised when domain model validation fails."""
