# NULLPLINTH progress

Updated at meaningful milestones. Every line reflects code that exists on disk and has
been executed on the development machine.

## Status: complete visual redesign shipped as 0.3.0

### Toolchain on the development machine

| Component | Version | Note |
|-----------|---------|------|
| Node.js / npm | 22.18.0 / 10.9.3 | |
| Rust | 1.99.1 (stable-x86_64-pc-windows-gnu) | GNU toolchain, no MSVC workload on this machine |
| Tauri | 2.12 | NSIS bundler |
| WebView2 runtime | 142.0.3595.53 | present |

### Complete visual redesign (0.3.0)

| Area | Change | Verified by |
|------|--------|-------------|
| Design system | New token file: black surfaces, off-white type, coral/lime/orange signal palette, teal/cyan/blue/violet analytical colours, spacing/row/radius/motion/layer scales | renders identically at 1024-1920 with zero DOM overflow |
| Typography | Urbanist variable font bundled locally (OFL 1.1) with a system monospace stack for technical values | font asset emitted into the bundle |
| Shell | 60px icon rail, top bar with workspace summary, global search, fullscreen and mode switch; F11 / Alt+1..7 / Alt+M | shell tests |
| Overview | Metric strip, event volume, severity mix, protocol donut, top sources/destinations, event severity, top hosts/ports, recent alerts and a **relationship graph from real events and alerts** | rendered review at four resolutions |
| Event Explorer | Search hero, filter chips, collapsible builder, dense table, inspector drawer with raw record | existing suite + rendered review |
| Network Analyzer | Capture strip, conversations, packet table with protocol/frame/encrypted chips, protocol hierarchy and hex view | rendered review |
| Alerts / Investigations / Data Sources / Settings | Redesigned on shared primitives with severity icon+label+colour, KPI strips, timelines, drop zone, storage and startup controls | 102 frontend tests + rendered review |
| Interaction | Hover/selected states, tooltips, skeleton loading, reduced-motion support | component tests |

### Quality overhaul (0.2.0)

| Area | Change | Verified by |
|------|--------|-------------|
| Imports - CSV | Preview with header-based mapping suggestions, estimated rows, validation, then import | 33 ingest tests + the supplied windows_event.csv (500 rows) |
| Imports - logs | Content-based registry: Suricata EVE, Zeek TSV, JSON/NDJSON, Linux auth, syslog, Apache/Nginx access, firewall key=value, generic text fallback | 33 ingest tests + the supplied firewall.log (500 events, 0 skipped) |
| Imports - capture preview | pcap/pcapng magic sniffed before any UTF-8 read; unknown binary reports itself instead of erroring | 5 new tests + both supplied captures preview as pcap/high |
| Network analysis | IEEE 802.11 (link type 105) and radiotap (127) decoding, LLC/SNAP into IP, encrypted frames labelled honestly | 16 pcap tests + the supplied 65 MB wireless capture |
| Search | Text filters are case-insensitive; pagination is 1-based so page 1 shows the first page | backend regression test + real app screenshot |
| UI | Semantic colour system, responsive containment, short chart labels, unambiguous column headers | 52 frontend tests + headless-Chrome overflow probe + real desktop screenshots |
| Workspace | Resume or Start Fresh on launch, confirmation, optional backup, settings preserved | 5 workspace tests + real-database copy clear |

### Bugs found by user testing and fixed

1. `.log` files were misdetected as CSV and failed to import.
2. CSV import required a mapping the UI never produced.
3. PCAP import was blocked because the preview tried to read binary as UTF-8 text.
4. Link type 105 captures imported packets that decoded as "Unsupported link type".
5. **Search returned nothing on page 1** because the UI sent 1-based pages while the backend
   offset by `page * page_size`. A 50-row search such as "User equals root" showed an empty
   table. Fixed in both event and packet search, with a regression test.
6. Text equality was case-sensitive ("root" did not match "Root").
7. Dashboard counts were misreported: the demo import notification printed the dataset id as a
   count, and the overview now reflects real aggregates.

### Test results (executed)

| Suite | Command | Result |
|-------|---------|--------|
| Backend integration | `cargo test --test backend_tests` | 10 passed, 0 failed |
| End-to-end acceptance | `cargo test --test e2e_tests` | 2 passed, 0 failed |
| Ingestion | `cargo test --test ingest_tests` | 33 passed, 0 failed |
| Network analysis | `cargo test --test pcap_tests` | 16 passed, 1 ignored |
| Workspace/migration | `cargo test --test workspace_tests` | 5 passed, 2 ignored |
| Real sample files | `cargo test --test example_files -- --include-ignored` | 5 passed, 1 ignored |
| Performance | `cargo test --test perf_tests -- --nocapture` | 1 passed |
| Frontend | `npm test` | 52 passed, 0 failed (14 files) |
| Frontend types/build | `npx tsc --noEmit`, `npm run build` | clean |

### Real sample files (supplied by the user)

| File | Result |
|------|--------|
| `firewall.log` (500 lines) | format `firewall`, confidence high, 500 imported, 0 skipped, endpoints and actions extracted |
| `windows_event.csv` (500 rows) | timestamp suggested from `TimeGenerated`, 500 imported, unmapped columns preserved |
| `2026-02-28-traffic-analysis-exercise.pcap` (6.5 MB, Ethernet) | 15,512 packets, TCP/UDP/ICMP/DNS/HTTP/TLS labels, conversations grouped |
| `evidence-defcon2010.pcap` (65 MB, IEEE 802.11) | 426,642 packets in ~40 s: 18,713 management / 204,926 control / 203,003 data, 200,867 encrypted frames labelled, no fabricated endpoints |

### Performance (100,000 synthetic events, this machine)

| Metric | Measured |
|--------|----------|
| Import 100k events | 19.3 s |
| Indexed source-IP filter | 1 ms |
| Time-range + protocol filter | 227 ms |
| FTS5 full-text query | 176 ms |
| Deep pagination | 19 ms |
| Database size | 38.7 MB |

### Workspace operations on the real 362 MB database

| Operation | Result |
|-----------|--------|
| Schema v1 -> v2 migration | in place, 221 events / 2 captures / 442,154 packets preserved |
| Start Fresh clear | 345 MB workspace cleared in 325 ms, FTS index and relationships consistent |

### Release and distribution (verified)

| Item | Value |
|------|-------|
| Application binary | `src-tauri/target/release/nullplinth.exe`, version 0.3.0 |
| Installer | `src-tauri/target/release/bundle/nsis/NULLPLINTH_0.3.0_x64-setup.exe` |
| Installer test | silent install, launch from installed location, silent uninstall |
| Signature | not code signed (SmartScreen warning expected) |
| License | MIT, see LICENSE |
| Desktop review | screenshots captured from the release build at 2062x1166, 1366x768 and 1024x768 |

### Remaining gaps

- No import cancellation, no drag-and-drop verification by a human hand (covered by mocked
  webview tests; a real Explorer drag cannot be synthesised).
- Desktop UI is verified by component tests, headless layout probes and captured screenshots;
  there is no scripted GUI automation on this machine.
- See `docs/KNOWN_LIMITATIONS.md` for the full list.