# ACSA Security Architecture & Security Boundaries

As a security analysis system, ACSA ingests third-party repositories, manifests, lockfiles, and code that may be untrusted, malicious, or compromised. Robust security boundaries are non-negotiable.

---

## 1. Credential & Secret Hygiene
- **Never Expose GitHub Tokens to Frontend**: GitHub App installation tokens and personal access tokens (PATs) are strictly restricted to backend worker processes and ephemeral memory. No API endpoint may ever echo, return, or serialize VCS tokens.
- **Never Commit Secrets**: Environment variables and `.env` files containing credentials are excluded by `.gitignore`.
- **Never Log Secrets**: The ACSA logging framework incorporates an active `SecretMaskingFilter` that intercepts and redacts GitHub tokens (`ghp_`, `github_pat_`), Bearer authorization headers, and credential key-value patterns before output is flushed to streams or files.

---

## 2. Filesystem & Path Traversal Guards
- **Validate Repository Paths**: All file and repository paths supplied via CLI or API must undergo canonical resolution and validation via `validate_safe_path()`.
- **Prevent Path Traversal**: Targets attempting to escape the authorized root workspace via `../`, absolute root jumps, symlink escapes, or embedded null bytes (`\x00`) are immediately halted with `PathTraversalError`.
- **Isolate Analysis Workspaces**: Every analysis session operates in a uniquely partitioned workspace using `isolate_workspace()`.
- **Clean Temporary Workspaces**: Temporary analysis workspaces are automatically purged upon session completion or error via deterministic context manager cleanup routines.

---

## 3. Resource Quotas & Denial-of-Service Defense
- **Enforce Scan Limits**: Strict per-file maximum size limits (default: 50MB) are enforced before attempting AST parsing or JSON manifest decoding to prevent memory exhaustion.
- **Enforce Timeouts**: Every scanning and analysis task enforces an upper execution time boundary (default: 300 seconds) via `Settings.scan_timeout_seconds`.
- **Sandbox CPU / Memory Caps**: Worker subprocesses run with bounded resource allocations.

---

## 4. Execution Sandbox & Code Isolation
- **Never Blindly Execute Arbitrary Repository Code**: ACSA static analysis inspects source ASTs and dependency graphs declaratively. Target repository code is never loaded into the main analyzer process.
- **Never Blindly Run npm Lifecycle Scripts**: Automatic execution of `preinstall`, `install`, `postinstall`, or `prepare` scripts from untrusted `package.json` manifests is strictly blocked. When package resolution is required, `--ignore-scripts` and isolated manifest interpreters are mandated.
