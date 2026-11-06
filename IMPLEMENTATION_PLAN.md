# NULLPLINTH implementation plan

## Architecture in one paragraph

A Tauri 2 desktop application. The React/TypeScript frontend renders screens and calls thin
Tauri commands. Every command delegates to a Rust service module: ingestion parses and
normalizes records, storage writes them to a local SQLite database, the query module turns
guided filters into parameterized SQL, the pcap module decodes captured packets, and the
detection module derives alerts with explicit evidence links. No business logic lives in
command handlers.

## Phases

| Phase | Scope | Status |
|-------|-------|--------|
| 0 | Environment inspection, toolchain verification | done |
| 1 | Scaffolding, contracts, SQLite schema, design system | in progress |
| 2 | Ingestion, normalization, storage, query engine, demo data | in progress |
| 3 | Overview, Event Explorer, guided filters, mode switching | in progress |
| 4 | PCAP/PCAPNG import, packet inspection, conversations | in progress |
| 5 | Detection rules, alerts, investigations, exports | in progress |
| 6 | Tests, 100k-event performance run, malformed-input hardening | pending |
| 7 | Release build and NSIS installer verification | pending |

## Dependencies between workstreams

1. The shared contracts in `src-tauri/src/types.rs` and `src/types/contracts.ts` are
   authoritative and change only through the Lead.
2. Ingestion depends on `types::NormalizedEvent` and `db::insert_events`.
3. Packet analysis depends on the packet tables in `src-tauri/src/db/schema.sql`.
4. The frontend depends only on `src/services/api.ts`.
5. Detection depends on stored events only; it never reads raw files.

## Acceptance criteria

The V1 release criteria are listed in the master specification (section 23) and are
tracked in `PROGRESS.md`. A phase is only "done" when its tests pass on this machine.

## Outstanding technical decisions

- Whether to keep the GNU Rust toolchain used for the reference build; the MSVC toolchain is
  the officially supported one for Tauri and should be preferred when available.
- TLS metadata extraction stays at record/handshake level only (no decryption).
- Full TCP stream reassembly is out of scope for V1.
