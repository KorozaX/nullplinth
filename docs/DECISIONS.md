# Architectural decisions

## ADR-001 - Tauri 2 instead of Electron
Smaller binaries, a Rust backend that can parse multi-hundred-megabyte logs off the UI
thread, and no Node runtime shipped to users. Cost: a native toolchain is required to build.

## ADR-002 - One normalized event schema, raw preserved
Every parser maps into `NormalizedEvent`. Fields without a standard equivalent go into
`attrs`; the original record is kept verbatim in `raw`. This keeps cross-format search
honest and still allows full technical inspection.

## ADR-003 - Parameterized SQL only
The guided filter builder compiles to a whitelisted set of column names and bound
parameters. No string interpolation of user values, ever. CIDR matching uses a registered
SQLite scalar function (`ip_in_cidr`) so filtering stays in SQL and pagination stays exact.

## ADR-004 - FTS5 external content table
`events_fts` mirrors `events.message` and `events.raw` through triggers. Search stays fast,
storage overhead stays low, and deleting a dataset cleans the index automatically.

## ADR-005 - Detection is deterministic and evidence-linked
Rules are threshold queries over stored events. Each alert row links to the exact event ids
that produced it through `alert_evidence`, so no alert can exist without supporting data.
Re-running detection uses a dedupe key, so alerts are not duplicated.

## ADR-006 - Beginner and Analyst modes share one engine
Mode switching only changes presentation density; there is no second code path and no second
data source.

## ADR-007 - GNU toolchain for the reference build
The machine had no MSVC C++ workload installed and no elevation was available. Rust's
`x86_64-pc-windows-gnu` toolchain plus the bundled MinGW runtime produces a working Tauri
binary and NSIS installer. The MSVC toolchain remains the recommended build path when
available; this is documented in `docs/KNOWN_LIMITATIONS.md`.
