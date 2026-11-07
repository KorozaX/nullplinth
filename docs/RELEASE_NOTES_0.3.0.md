# NULLPLINTH 0.3.0 - complete visual redesign

Local-first security analysis workbench for Windows. Everything runs on your machine: no
account, no cloud backend, no telemetry, no external API.

This release is a full interface redesign on a new design system. The data engine, database
schema and all workflows are unchanged.

## Design system

- **Urbanist** bundled locally (variable font, SIL Open Font License 1.1) for interface text, with
  a system monospace stack for IPs, ports, timestamps, packet bytes and raw records. No remote
  font service.
- **Palette:** black `#000`, surfaces `#141414` / `#1C1C1C`, hairlines `#303030`, text
  `#EAEAEA` / `#929292`; signal colours coral `#FF6F6F`, lime `#A9EB64`, orange `#FF934F`,
  plus teal, cyan, blue and violet for analysis.
- **Semantic colour:** severity critical coral, high orange, medium amber, low blue, info grey;
  protocols TCP blue, UDP violet, DNS teal, HTTP lime, TLS cyan, ICMP orange, unknown grey.
  Colour is never the only signal - every state also carries a label and an icon or shape.
- **Tokens** for spacing, control heights, row density, radii, motion and layers in one file;
  motion collapses under `prefers-reduced-motion`.

## Application shell

- Slim 60px navigation rail with the NULLPLINTH mark, icon sections, cyan active marker and
  tooltips.
- Top bar with section title, live workspace summary, global search (routes to the Event
  Explorer), fullscreen and Beginner/Analyst switch. F11, Alt+1..7 and Alt+M still work.

## Screens

- **Overview** - composed analytics rather than uniform cards: metric strip with sparkline,
  event volume time series with hover detail, alert severity mix, protocol donut, top source and
  destination IPs, event severity distribution, top hosts and ports, recent alerts, and a
  **relationship graph** built from real events and alerts (deterministic layout, severity
  colours and shapes, hover tooltip, selection, legend, honest truncation note).
- **Event Explorer** - search hero, removable filter chips, collapsible guided builder, dense
  results table with severity and protocol chips, inspector drawer with human summary, normalized
  fields and the untouched raw record.
- **Network Analyzer** - capture strip, conversation list with protocol chips, packet table with
  protocol/frame/encrypted chips, expandable protocol hierarchy and hex+ASCII synced to the
  selection.
- **Alerts** - severity icon + label + colour, KPI strip, filters for severity/status/rule/IP/time,
  dense queue, detail with threshold, recommended steps and evidence links.
- **Investigations** - KPI strip, case rail with search and status filter, overview editor,
  attached alerts, merged activity timeline, notes composer and JSON export.
- **Data Sources** - drag-and-drop import zone, import status, supported-format matrix, dataset
  and capture tables with confirmed deletes.
- **Settings** - appearance, experience mode, startup behaviour, detection thresholds, storage
  location and counts, export, clear workspace with backup, about.

## Fixed in this release

- Search page one showed the wrong rows (1-based/0-based pagination mismatch) - fixed with a
  regression test.
- Text filters are case-insensitive.
- Packet capture import is no longer blocked by a text preview of a binary file.
- Relationship graph labels no longer collide in dense clusters.
- Data source import rows separate their facts; investigations auto-select the first case;
  alerts render only the endpoints that exist.

## Upgrade notes

- The database schema stays at v2 - no migration needed from 0.2.0.
- Application version is now 0.3.0.

## Verification

- Rust: 72 tests passing (4 heavy real-file tests ignored by default), including import, packet
  decoding, detection, investigations, workspace and a 100,000-event performance test.
- Frontend: 17 test files, 91+ tests passing; TypeScript and Vite builds clean.
- Rendered-app review at 1024x768, 1280x720, 1366x768 and 1920x1080 across all seven sections
  using true WebView2 screenshots, with a DOM overflow audit at each size (zero offenders).
- Installer verified by install, launch and uninstall.

## Installation

Download `NULLPLINTH_0.3.0_x64-setup.exe` below and run it. Per-user install, no administrator
rights, no system changes. WebView2 is already present on Windows 10 and 11. The installer is
not code signed, so SmartScreen asks for confirmation on first run.

## Known limitations

No live packet capture, no TCP stream reassembly, no TLS decryption, no native EVTX parsing, no
import cancellation. See `docs/KNOWN_LIMITATIONS.md`.

## License

MIT. Use it, modify it, ship it.
