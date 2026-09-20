# Implementation status — v0.1.0

## Delivered

- Installable Python CLI with `doctor`, one-shot `chat`, and bounded `run`.
- Standard-library Gemini REST adapter, configurable model, clear common API errors.
- Preserves model content/opaque thought signatures and function IDs in tool round trips.
- Workspace file listing/read/write; schema validation and traversal/hidden-path/symlink rejection.
- Interactive approval for each write and optional Python script, noninteractive default denial.
- Script inspection, changed-script check, minimal child environment, timeout/output limits, cancellation cleanup.
- API-key redaction in file contents and final responses; no conversation or prompt logs persisted.
- Step/token/runtime thresholds, offline tests and installation instructions. Desktop CI configuration is prepared in the downloadable ZIP but not published because workflow-file permissions are missing.

## Not yet verified

- Installation and behavior on an actual Android/Termux device.
- Gemini API account/model availability and live tool calls with real credentials.
- Native SDK compatibility. REST was selected for a minimal dependency footprint; no SDK failure is claimed.

## Pending roadmap work

- File search, richer per-tool policies and deterministic task-specific verifiers.
- Persistent task state, SQLite memory, context summarization, crash recovery.
- Retry/backoff policy, hard cost accounting and service-side quota documentation.
- Web research, API integrations, Android/voice features, scheduling and parallel workers.
- Full security evaluation and representative benchmark suite.

No milestone is marked fully complete until its device/live acceptance checks pass.

## Security boundaries

Workspace restrictions apply to built-in file tools only. They are not robust against a malicious local process racing filesystem changes. Use a private workspace owned by one user and avoid concurrent modification. Approved Python is arbitrary code with the Termux user's access, not an isolation boundary; it can escape workspace restrictions and create detached children. Process-group cleanup is best effort, not containment. Use a genuinely isolated remote worker for untrusted execution.

The program does not expose generic shell execution, an HTTP server, an auto-approval option, or self-modification of permissions. Built-in reads can upload workspace content to Gemini. Avoid secrets in the workspace.
