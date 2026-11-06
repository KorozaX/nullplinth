# NULLPLINTH architecture

## Layers

```
React (src/)  --invoke-->  Tauri commands (src-tauri/src/commands/)
                                   |
                                   v
                       Rust service modules (ingest, pcap, query,
                       detection, investigation, export, demo)
                                   |
                                   v
                       SQLite (src-tauri/src/db/) + FTS5
```

Command handlers are thin: they borrow the database handle, move the work onto the
Tauri blocking thread pool, and translate `AppError` into a rejected promise.

## Module boundaries

| Module | Responsibility | Owner |
|--------|----------------|-------|
| `src-tauri/src/types.rs` | Shared DTOs (camelCase on the wire) | Lead |
| `src-tauri/src/db/` | Schema, migrations, dataset/event storage | Lead |
| `src-tauri/src/query/` | Filter validation, parameterized search, aggregates | Lead |
| `src-tauri/src/commands/` | Tauri command surface | Lead |
| `src-tauri/src/ingest/` | Format detection, parsers, normalization, CSV wizard | data-engine |
| `src-tauri/src/pcap/` | Capture parsing, protocol decoding, conversations | network |
| `src-tauri/src/detection/` | Rule engine, alerts, evidence | Lead |
| `src-tauri/src/investigation/` | Incident records and notes | Lead |
| `src-tauri/src/export/` | CSV/JSON/report writers | Lead |
| `src-tauri/src/demo/` | Deterministic demonstration dataset | Lead |
| `src/` (except types/ and services/) | Application shell, design system, screens | frontend |
| `src/types/`, `src/services/` | Frontend contract and IPC layer | Lead |

## Event model

Every log format is normalized into `NormalizedEvent`: timestamp (epoch ms), source type,
category, event type, severity, source/destination IP and port, transport, application
protocol, action, username, hostname, process name, message, plus `attrs` (unmapped fields)
and `raw` (the untouched original record). Nothing is dropped: fields without a standard
equivalent stay in `attrs` and the original record stays in `raw`.

## Storage

One SQLite file in the per-user application data directory, WAL mode, per-operation
connections. Tables: datasets, events, packet_captures, packets, flows, alerts,
alert_evidence, investigations, investigation_notes, investigation_alerts, saved_filters,
settings. `events_fts` is an FTS5 external-content table kept in sync by triggers.

## Security posture

- Imported content is data, never code: it is stored as text and rendered as text.
- All SQL is parameterized; field names come from a whitelist.
- The CSP forbids remote script/style/frame origins.
- Tauri capabilities are limited to the core defaults and the dialog plugin.
- No network calls are made by the application at any point.
