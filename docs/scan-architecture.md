# Leakline scan architecture

## Purpose and scope

This document defines the scan contract for Leakline before scanner implementation
begins. It is intentionally designed for the current Tauri v2, Rust, and React
application—not as a separate service or a new platform.

Today, `src-tauri/src/lib.rs` contains the application setup, an `app_info`
command, and a `scan_directory` command. The latter recursively returns paths
whose extension or name matches an allowlist. It does not inspect contents or
produce findings. The React application currently calls only `app_info`.

The implementation should evolve that prototype into this local flow:

```text
validated target
  -> file discovery and coverage accounting
  -> native rules and external scanner adapters
  -> normalized findings and scan issues
  -> in-memory scan result
  -> Tauri events/commands
  -> React scan UI
```

The first implementation is a single-process desktop scanner. It must not add a
database, network service, background daemon, or general-purpose plugin
framework. A small scanner trait and a registry in Rust are sufficient to add
future scanners without rewriting the orchestration layer.

## Architectural shape

Keep `main.rs` as the thin binary entry point. As the current `lib.rs` grows,
split it into small modules under `src-tauri/src/`:

```text
lib.rs                 Tauri builder, managed ScanManager, command registration
scan/
  mod.rs               scan orchestration and public scan types
  model.rs             findings, issues, progress, result DTOs
  target.rs            target validation and path-safe display helpers
  discovery.rs         WalkDir traversal, selection, exclusions, coverage data
  limits.rs            explicit default resource limits
  native.rs            native scanner and custom-rule registry
  external/
    mod.rs             shared safe-process adapter support
    gitleaks.rs        Gitleaks adapter and JSON normalization
    semgrep.rs         Semgrep adapter and JSON normalization
  manager.rs           in-memory jobs, cancellation, result lifetime
```

This is an organizational target, not a requirement to create every file before
there is code for it. The existing allowlist should move from `lib.rs` to
`discovery.rs`; its behavior should be covered by tests before it is changed.

`ScanManager` is Tauri managed state. It owns active scan handles and completed
results in memory for the lifetime of the app, keyed by a monotonic `u64` scan
ID. It is not persistent storage. The UI fetches and dismisses completed
results; app exit discards them.

## 1. Scan targets and validation

### Initial supported target

Version one accepts one existing, local **directory** per scan. The UI will
eventually select it with a native directory picker, but the Rust command remains
the authority: frontend input is untrusted and must be validated again.

The target validator must:

1. Accept a path supplied to the command and reject an empty path.
2. Resolve it to an absolute, canonical path.
3. Require that it exists, is a directory, and is readable enough to start
   traversal.
4. Reject a target that is itself a symbolic link in the initial release. This
   makes the root scanned unambiguous under the default no-symlink policy.
5. Reject a duplicate active scan of the same canonical root, unless a later UI
   deliberately offers a queue.
6. Return a structured, safe validation error rather than falling back to a
   relative path or a partial scan.

Single-file targets, multiple targets, archives, remote shares, and git-history
scans are out of scope for the first scanner contract. They can be added as
explicit target kinds later without changing the finding model.

Native code retains paths as `PathBuf`. IPC paths are UTF-8 display strings.
Paths that cannot be safely represented for the React UI must produce an explicit
coverage issue with a lossless escaped display form; they must never disappear
through `to_string_lossy()` without a record.

## 2. File discovery and exclusions

`walkdir`, already present in `Cargo.toml`, remains the discovery mechanism.
Discovery produces `DiscoveredFile` records internally:

```text
absolute path | path relative to target | byte size | selection reason
```

The existing extension/name allowlist remains the initial candidate-selection
policy. Normalize extension and filename comparisons to ASCII lowercase so that
the existing `Procfile`/`Gemfile`/`Pipfile` case mismatch is removed during
implementation. Filename families such as `.env.*` stay supported.

The discovered file list is the authoritative input for native rules. It gives
the UI and result a truthful coverage record: selected, excluded, skipped for a
limit, unreadable, or unsupported/binary. Discovery must record every traversal
error and every category of skipped file; it must not use the current
`filter_map(|e| e.ok())` behavior.

### Default exclusions

By default, prune version-control metadata directories (`.git`, `.hg`, `.svn`)
before descent. Do not broadly prune dotfiles: `.env`, `.npmrc`, and similar
files are intentional candidates. Other high-volume directories are not silently
excluded. If product testing later establishes defaults for `node_modules`,
`target`, or build output, they must be named in the result's coverage summary,
visible in the UI, and overridable by the user.

The request includes two explicit lists:

- `exclude_paths`: target-relative directory/file patterns supplied by the user.
- `include_paths`: a future explicit opt-in for paths otherwise excluded by a
  configured policy.

Both are interpreted relative to the canonical target, cannot escape it, and are
reported in scan metadata. Initial implementation may ship only built-in VCS
pruning and no editable UI; the data model should reserve these fields now.

External scanners are passed the same canonical target and equivalent exclusion
configuration where their CLIs support it. Leakline must not copy selected files
to a staging directory merely to feed an external process, because doing so
creates another on-disk secret copy. If an external tool cannot honor a requested
exclusion, its adapter reports that capability limitation and does not claim
equivalent coverage.

## 3. File-size and resource limits

Limits prevent a local scan from exhausting memory, CPU, or UI responsiveness.
They are policy, not silent filtering. Each hit is included in `CoverageSummary`
and produces an issue or aggregated skipped-file record that the UI can inspect.

Proposed initial defaults, pending approval:

| Limit | Proposed default | Behavior |
| --- | ---: | --- |
| Native-rule file size | 10 MiB | Do not read the file for native text rules; record `file_too_large`. |
| Candidate file count | 100,000 | Stop discovery; finish as a partial scan with `candidate_limit_reached`. |
| Total bytes read by native rules | 1 GiB | Stop native content reads; return partial coverage. |
| Per external scanner runtime | 10 minutes | Request termination and return a scanner failure/timeout issue. |
| Captured external stdout/stderr | 10 MiB per stream | Stop/terminate the process and report an output-limit failure. |

Discovery streams files to native scanners rather than retaining file contents.
Metadata may be retained only as needed for result coverage. Native rules read a
bounded file once, process it, and release the buffer. File reads are limited to
the configured maximum even if filesystem metadata is inaccurate.

A limit ending only one scanner results in a partial scan, not a successful clean
scan. The completion status and UI must make that distinction obvious.

## 4. Symlink and permission handling

The initial policy is **do not follow symlinks**. A symlinked directory is not
descended into; a symlinked file is not read. Both are counted with their
relative path and reason. This avoids cycles, unexpected traversal outside the
target, and ambiguous ownership. A future opt-in must include loop detection,
canonical containment checks, and clearly show the effective target.

Permission, metadata, read, and decoding failures are recorded as `ScanIssue`
or aggregated coverage entries with a path and operation. Discovery continues
where safe, so one unreadable path does not discard the rest of the target.
The scan completes as `completed_with_issues` or `partial`, never as a clean
success if coverage failures occurred.

## 5. Normalized finding data model

All scanners normalize their output into the same model. A finding is evidence
that a rule or scanner detected something; it is not an operational error.

```rust
// Rust-oriented shape; field names serialize as camelCase for React.
struct Finding {
    finding_id: String,          // unique within one scan; no secret value
    scanner_id: String,          // "native", "gitleaks", "semgrep", ...
    rule_id: String,             // stable identifier within that scanner
    title: String,
    description: String,
    severity: Severity,
    location: FindingLocation,
    tags: Vec<String>,
    remediation: Option<String>,
    fingerprint: String,         // deterministic from scanner/rule/path/location, never raw secret
}

struct FindingLocation {
    relative_path: String,
    start_line: Option<u64>,
    start_column: Option<u64>,
    end_line: Option<u64>,
    end_column: Option<u64>,
}
```

`finding_id` can be a scan-local sequence. `fingerprint` supports deduplication
within a scan and comparison in a future non-secret history feature. It must not
include the matched secret or a reversible snippet. Findings deliberately omit
the matched text, full line, raw external JSON, and absolute path. A future
explicit “reveal locally” feature needs a separate security review and is not
part of this contract.

The complete result is:

```rust
struct ScanResult {
    scan_id: u64,
    target: ScanTargetSummary,   // display path, not secret content
    status: ScanStatus,
    started_at: String,          // RFC 3339 UTC
    finished_at: Option<String>,
    summary: ScanSummary,
    coverage: CoverageSummary,
    scanner_runs: Vec<ScannerRunSummary>,
    findings: Vec<Finding>,
    issues: Vec<ScanIssue>,
}
```

`ScanStatus` is one of `running`, `completed`, `completed_with_issues`,
`partial`, `failed`, or `cancelled`. `partial` means a resource/coverage limit
or scanner limitation intentionally left part of the target unscanned. `failed`
means no useful scan result could be produced. A scanner failure is never
converted to a finding.

## 6. Severity levels

Leakline retains the current five severity names, serialized consistently as
`minimal`, `low`, `medium`, `high`, and `critical`:

| Severity | Meaning |
| --- | --- |
| Critical | Likely active, high-impact compromise material, such as a production private key or unrestricted cloud credential. |
| High | Strong sensitive credential or configuration with material misuse potential. |
| Medium | Security-relevant weakness or potentially sensitive value requiring review. |
| Low | Limited-impact exposure, weak configuration, or contextual indicator. |
| Minimal | Informational hardening signal with little direct exploitability. |

Every native rule owns a default severity. External adapters preserve a tool's
severity where it maps unambiguously; otherwise they use a documented adapter
mapping. The adapter includes the original severity in a non-secret tag such as
`gitleaks:high` for debugging. The UI must not treat scanner confidence as
severity.

## 7. Native/custom rule architecture

Native rules cover environment-specific AD/SCCM/SAP checks and lightweight local
secret/configuration patterns that do not require an external binary.

Use a small, internal registry:

```text
NativeScanner
  owns Vec<Rule>
  -> evaluates each applicable bounded file
  -> emits normalized Finding values or typed rule errors
```

Rules declare a stable ID, title, applicable file predicate, default severity,
tags, remediation, and evaluation function. The scanner, not individual rules,
owns bounded reading, line/column calculation, cancellation checks, and error
conversion. Rules receive a bounded, in-memory text view and return match
locations—not raw secret values to the result model.

Start with compiled Rust rules and reviewable unit-test fixtures. Do not start
with downloadable rules, arbitrary user code, or a generic plugin runtime.
Later, an optional local declarative rule file can compile into the same `Rule`
definition after validation; it must remain local and use the same limits and
redaction rules.

## 8. Gitleaks integration

Gitleaks is an optional external scanner adapter, not a prerequisite for native
scans. At scan start the adapter resolves a user-configured executable path or a
PATH-discovered executable, records its version/capability, and reports a clear
`scanner_unavailable` issue if it cannot run.

The adapter must:

- Invoke the binary with `std::process::Command`; never construct a shell command
  string or interpolate paths into shell syntax.
- Set the canonical target as the working directory/source argument and use the
  working-tree/file-scan mode by default—not repository history—unless a future
  target type explicitly asks for history.
- Request machine-readable JSON via pipes and parse it in memory.
- Disable update checks, telemetry, network-backed rules, and any behavior that
  could transmit target contents, using the supported version-specific local
  configuration.
- Apply compatible exclusions where Gitleaks supports them and report mismatch
  as a coverage limitation.
- Bound runtime and output, terminate on cancellation, redact process diagnostics,
  and normalize records to `Finding` values without preserving matched secrets.

No raw JSON report is written beside the target or retained in app storage.

## 9. Semgrep integration

Semgrep follows the same adapter contract. It is optional and must run only with
a bundled or explicitly selected **local** rules configuration. Leakline must not
use remote registries, `auto` configuration, cloud upload, or telemetry in its
default local-first mode.

The adapter invokes Semgrep without a shell, requests JSON through stdout, and
maps each result's rule ID, message, severity, range, and local path into the
normalized model. It validates that reported paths remain inside the canonical
target before accepting them. Unsupported language, parse, or configuration
problems are scanner issues, not clean results or native findings.

Because Semgrep generally discovers files internally, the adapter must pass its
equivalent exclusions and report scanner-specific coverage separately. It must
not claim that native discovery's file count is Semgrep's coverage count.

## 10. Scanner error handling

Use a structured `ScanIssue` model rather than strings or silent omission:

```rust
struct ScanIssue {
    issue_id: String,
    stage: IssueStage,           // target, discovery, native, gitleaks, semgrep, result
    code: String,                // e.g. permission_denied, process_timeout
    severity: IssueSeverity,     // warning or error; independent of finding severity
    message: String,             // safe user-facing message
    relative_path: Option<String>,
    scanner_id: Option<String>,
}
```

Examples include inaccessible paths, invalid user exclusions, unreadable files,
non-UTF-8 text when a rule requires text, missing executables, invalid scanner
JSON, nonzero process exit, timeout, cancellation, and result-normalization
failures. Diagnostic stderr is redacted and bounded; it is not copied verbatim
into scan results or logs.

The orchestrator isolates scanner failures: a failed Semgrep invocation does not
discard native or Gitleaks findings. It determines the final status from what
completed and the recorded coverage. A result with zero findings is only “clean”
when the requested scanners finished and coverage has no errors or partial-limit
state.

## 11. Progress reporting

Progress is advisory and phase based because recursive discovery does not know
the total file count before traversal. Emit only non-secret progress:

```text
queued -> validating_target -> discovering -> scanning_native
       -> scanning_gitleaks / scanning_semgrep -> normalizing -> completed
```

`ScanProgress` includes scan ID, phase, elapsed milliseconds, discovered count,
selected count, processed count, finding count, issue count, and an optional
scanner ID. It contains neither file content nor raw matched values. The UI
should show an indeterminate phase indicator until a meaningful total is known,
then show counts rather than a misleading percentage.

Throttle events (for example, at most four per second plus phase changes) so a
large scan cannot overload the Tauri event queue or React rendering.

## 12. Scan cancellation

Each active scan receives an `Arc<AtomicBool>` cancellation flag owned by
`ScanManager`; no new dependency is required. Discovery, native bounded reads,
normalization loops, and external-process supervision check it frequently.

Cancellation is cooperative:

1. React requests cancellation for a scan ID.
2. The manager sets the flag and acknowledges the request.
3. The orchestrator stops scheduling new work, terminates active child processes,
   and closes their pipes.
4. It emits a final `cancelled` completion event with work completed so far and
   any safe partial findings only if the product chooses to retain them.

The default UI should discard cancelled partial findings unless the user
explicitly requests to view them. Cancellation does not erase a secret from an
external process's own memory, but Leakline must release in-memory buffers and
avoid writing reports.

## 13. Rust-to-React/Tauri IPC contracts

Tauri commands are a narrow application API. React does not receive filesystem
handles, process output, or raw scanner payloads.

```text
start_scan(ScanRequest) -> ScanStarted | CommandError
cancel_scan { scanId } -> CancelAcknowledged | CommandError
get_scan_result { scanId } -> ScanResult | CommandError
dismiss_scan_result { scanId } -> () | CommandError
```

`ScanRequest` initially contains `targetPath`, requested scanner IDs, and optional
target-relative exclusions. The backend applies a safe default scanner set and
rejects unknown scanner IDs or invalid options. `ScanStarted` returns the scan ID
and canonical display target immediately; it does not wait for the scan.

The backend emits these window events:

```text
scan-progress    ScanProgress
scan-complete    { scanId, status, summary }
```

React subscribes once, filters by scan ID, and calls `get_scan_result` after
completion. This avoids pushing a potentially large findings list repeatedly.
Results are held in memory only until dismissed or app exit. Commands return
structured command errors for invalid requests and manager state; scan-time
problems appear in `ScanResult.issues`.

All Rust DTOs use `Serialize` (and `Deserialize` for request types), explicit
camelCase serde names, and versioned/forward-compatible enum values. The current
`FindingVuln`, `ScanResult`, and `Severity` prototypes should be replaced rather
than exposed unchanged because they do not distinguish scanner source, location
shape, status, or failures.

## 14. Privacy and secret handling

Leakline is local-first by contract:

- Target paths, contents, rules, results, and reports remain on the local
  machine. No cloud API, telemetry, remote rule fetch, or content upload is
  enabled by default.
- File contents are read only for the active scan and released after each bounded
  operation. The application does not create temporary copies of target files.
- Findings never contain matched secrets, complete lines, raw scanner output, or
  absolute paths. A path relative to the selected target and position are enough
  for remediation.
- Results are in memory only in the initial release. Export, history, or “reveal
  match” features require explicit user action and a separate design review.
- External scanner processes use only local binaries and local rule/config files.
  Their executable path and effective configuration are disclosed to the user.
- Process environments are minimized where the tool permits; stdin is closed and
  stdout/stderr are bounded pipes. No shell is used.

This policy should be reflected in the product UI and README before external
scanners are advertised as implemented.

## 15. Logging requirements

The existing debug-only `tauri-plugin-log` setup can remain, but scan logging
must be structured and redaction-first. Log scan lifecycle events, scanner ID and
version, counts, durations, limit hits, and error codes. Do **not** log file
contents, matched text, raw Gitleaks/Semgrep JSON, unbounded stderr, access
tokens, environment variables, or absolute target paths by default.

Where a path is useful for local troubleshooting, use a target-relative path and
only at a deliberate debug level. Redaction is performed before any logging call,
not by caller convention. Logs are diagnostics, not a scan-results store.

## 16. Testing strategy

Testing begins with the current behavior before feature expansion:

1. **Rust unit tests:** allowlist/filename behavior (including case handling),
   exclusion matching, target validation, symlink policy, size limits, line and
   column mapping, severity mappings, redaction, and final status computation.
2. **Rust integration tests:** temporary directory fixtures covering readable and
   unreadable paths, binary/oversized files, cancellation, partial limits, and
   known native-rule positives/negatives. Assert coverage issues rather than just
   findings.
3. **Adapter tests:** inject a process runner and use controlled fixture
   executables/JSON. Cover unavailable tool, nonzero exit, malformed output,
   timeout, cancellation, path escape, severity normalization, and verify no raw
   match enters a `Finding` or log event.
4. **IPC contract tests:** serialize request/result/event DTOs and maintain JSON
   fixtures so React and Rust changes are deliberate.
5. **React tests:** mock Tauri commands/events for validation error, progress,
   completed-with-issues, partial, failed, and cancelled UI states. Assert that
   the UI never renders secret-bearing fields.
6. **Manual local verification:** run known harmless fixtures with local tool
   binaries; verify no network access or report files are created. CI should not
   require Gitleaks or Semgrep to test native behavior.

## Decisions requiring approval

The following defaults are proposed so implementation can proceed, but should be
confirmed before coding:

1. The initial target is exactly one local directory; symbolic-link targets and
   all symlinks beneath it are skipped and visibly reported.
2. Gitleaks scans the working tree/files by default, not git history.
3. Semgrep accepts only bundled or user-selected local rules; remote registries
   and automatic configuration are disabled.
4. Findings never display or persist the matched secret or raw source line.
5. The initial limits are 10 MiB/file, 100,000 candidates, 1 GiB native bytes,
   and 10 minutes/external scanner.
6. The default exclusion set initially prunes only VCS metadata; any broader
   performance exclusions must be transparent and user-overridable.
7. Scan results remain in memory until dismissed or app exit; there is no scan
   history or export in the first implementation.

These choices prioritize trustworthy coverage and local privacy over maximum
throughput and convenience. They can be revised centrally in `limits`, target,
and adapter policy modules without changing React's finding/result contract.
