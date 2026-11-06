# NULLPLINTH progress

Updated at meaningful milestones. Every line reflects code that exists on disk.

## Status: foundation in place, feature work in progress

### Done

- Repository created and initialised (git, GitHub remote).
- Toolchain verified on the development machine: Node 22, Rust 1.99, npm 10, Tauri 2.
- Project scaffold: Vite + React + TypeScript frontend, Tauri 2 shell, Rust backend crate.
- Shared contracts: `src-tauri/src/types.rs` and `src/types/contracts.ts`.
- SQLite schema with FTS5, indexes, migrations versioning (`src/db/schema.sql`).
- Parameterized query engine and overview aggregates (`src/query/mod.rs`).
- Command layer skeleton with async, off-thread execution.

### In progress

- Ingestion: JSON/NDJSON/Suricata/Zeek/CSV parsers (data-engine teammate).
- PCAP/PCAPNG decoding and packet views (network teammate).
- React application: shell, design system, all screens (frontend teammate).
- Detection rules, investigations, exports, demo dataset (Lead).

### Pending

- Backend and frontend test suites.
- 100,000-event performance measurement.
- End-to-end workflow verification.
- Release build and NSIS installer.

## Known issues

- None recorded yet beyond the unimplemented stubs (see `grep -r "not implemented yet"`).

## Build status

| Check | Command | Result |
|-------|---------|--------|
| Backend compiles | `cargo check` | in progress |
| Frontend typechecks | `npx tsc --noEmit` | passing |
