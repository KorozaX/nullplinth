# Threat model

NULLPLINTH reads attacker-controlled data and displays it to a human. The threat model follows
from that single fact.

## Assets

1. The integrity of the analyst's machine and other local files.
2. The confidentiality of imported security evidence.
3. The analyst's trust in the findings the tool reports.

## Adversaries and inputs

| Input | Risk |
|-------|------|
| Malicious log lines (JSON, CSV, Zeek TSV) | Injection into SQL, HTML/script injection in the UI, parser crashes |
| Malicious packet captures | Parser memory errors, huge allocations, pathologically nested protocols |
| Oversized files | Memory exhaustion, UI lock-up |
| The user's own workflow | Mistaken conclusions from unlabelled synthetic data |

## Controls

**Data is never code.** Imported strings are stored as text and rendered as React text nodes.
There is no `innerHTML`, no `dangerouslySetInnerHTML`, and no eval anywhere in the frontend.
A restrictive Content Security Policy blocks inline and remote scripts.

**SQL is always parameterized.** Filter values are bound parameters. Column names come from a
fixed whitelist; the operator set is a fixed match. An unrecognised field, operator, IP, port
or CIDR value is rejected with a validation message instead of being silently ignored.

**Local only.** No network client exists in the application. No telemetry, analytics, update
ping, cloud storage, remote model or external threat-intelligence call. The CSP forbids remote
origins, so even injected markup could not exfiltrate data through the webview.

**Least privilege.** The Tauri capability file grants only core defaults and the file dialog
plugin. The installer is per-user; the application never requests administrator rights.

**Safe file handling.** Imported files are opened read-only and never modified. Exports write
only to a path the user picks in the native save dialog. No file from imported data is ever
executed.

**Robust parsing.** Each record is parsed independently: one malformed record increments the
skipped counter and is reported, it does not abort the import. Packet parsing keeps raw bytes
when a layer cannot be decoded and marks the packet as unsupported rather than failing.

**Honest detection.** Detection is deterministic and threshold based. Every alert links to the
events that produced it. Alerts state "potential" activity; they never claim a compromise.

## Out of scope for V1

- Malware execution, sandboxing and YARA scanning.
- TLS decryption and full TCP stream reassembly.
- Multi-user access control: the local database is protected by operating-system file
  permissions, not by an application password.
- Live capture, which would require kernel drivers and elevation.

## Residual risks

- A determined attacker who already has code execution on the machine can read the local
  database. NULLPLINTH does not add disk encryption.
- Very large datasets can still exhaust memory if the machine is tiny; imports are streamed,
  but a single pathological record can be large.
- Detection thresholds are heuristic. A quiet environment can produce false positives and a
  noisy one can hide a real attack below the threshold.
