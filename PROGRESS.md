# NULLPLINTH progress

Updated at meaningful milestones. Every line reflects code that exists on disk and has
been executed on the development machine.

## Status: V1 feature complete, packaging in progress

### Toolchain on the development machine

| Component | Version | Note |
|-----------|---------|------|
| Node.js / npm | 22.18.0 / 10.9.3 | |
| Rust | 1.99.1 (stable-x86_64-pc-windows-gnu) | GNU toolchain: no MSVC workload installed, see docs/KNOWN_LIMITATIONS.md |
| Tauri | 2.12 | NSIS bundler |
| WebView2 runtime | 142.0.3595.53 | present on the machine |

### Completed

- Repository, git history, GitHub remote; branch `main`.
- Shared contracts: `src-tauri/src/types.rs` and `src/types/contracts.ts`.
- SQLite schema v1 with FTS5, indexes and schema versioning.
- Parameterized query engine, CIDR matching, overview aggregates.
- Ingestion: JSON/NDJSON, Suricata EVE, Zeek TSV, CSV wizard backend (18 tests).
- Network analysis: PCAP/PCAPNG, Ethernet/VLAN/IPv4/IPv6/TCP/UDP/ICMP/ARP/DNS/HTTP/TLS
  decoding, hex/ASCII view, bidirectional conversations (12 tests).
- Detection: four deterministic rules with evidence links and dedupe (covered by tests).
- Investigations with notes and attached alerts; CSV/JSON exports; report export.
- Demo dataset generated deterministically.
- Frontend: design system, shell, all seven sections, beginner/analyst modes, CSV wizard
  (18 vitest tests, tsc + build clean).
- Test manifest workaround so Rust test binaries load on the GNU toolchain.

### Test results (executed)

| Suite | Command | Result |
|-------|---------|--------|
| Backend integration | `cargo test --test backend_tests` | 9 passed, 0 failed |
| End-to-end acceptance | `cargo test --test e2e_tests` | 2 passed, 0 failed |
| Ingestion | `cargo test --test ingest_tests` | 18 passed, 0 failed |
| Network analysis | `cargo test --test pcap_tests` | 12 passed, 0 failed |
| Performance | `cargo test --test perf_tests -- --nocapture` | 1 passed (measurements below) |
| Frontend | `npm test` | 18 passed, 0 failed (6 files) |
| Frontend types | `npx tsc --noEmit` | clean |
| Frontend bundle | `npm run build` | clean, 243 kB JS / 25 kB CSS |

### Performance measurements (100,000 synthetic events, this machine)

| Metric | Measured |
|--------|----------|
| Import 100k events (batched, FTS triggers on) | 19.3 s |
| Indexed source-IP equality filter | 1 ms |
| Time-range + protocol filter (25,265 matches) | 227 ms |
| FTS5 full-text query (16,667 matches) | 176 ms |
| Deep pagination (page 500, 100 rows) | 19 ms |
| Database size for 100k events | 38.7 MB |

### Pending

- Release build and NSIS installer verification (running).
- Final documentation pass and GitHub push.

## Build status

| Check | Command | Result |
|-------|---------|--------|
| Backend compiles | `cargo check --all-targets` | clean |
| Frontend typechecks | `npx tsc --noEmit` | clean |
| Release build | `npm run tauri build` | running |

## Known issues

See `docs/KNOWN_LIMITATIONS.md`.
