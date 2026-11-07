# NULLPLINTH

**Security evidence, made navigable.**

NULLPLINTH is a local-first security analysis workbench for Windows. It imports security
telemetry and packet captures, normalizes them into one event model, and lets you search,
inspect, detect, and investigate - entirely offline, on your own machine.

Nothing is uploaded. There is no cloud backend, no telemetry, no account, and no external API.

## Download

Get the Windows installer from the [releases page](https://github.com/KorozaX/nullplinth/releases/latest):

- `NULLPLINTH_0.3.0_x64-setup.exe` - per-user install, no administrator rights required.
- The installer is not code signed, so Windows SmartScreen will ask for confirmation.
- The app runs fully offline; the only prerequisite is the WebView2 runtime, which ships with
  Windows 10 and 11.

## What it does

| Area | Capability |
|------|------------|
| Ingestion | Content-based detection: Suricata EVE JSON, Zeek TSV, JSON/NDJSON, CSV mapping wizard, Linux auth logs, syslog, Apache/Nginx access logs, firewall key=value logs, generic text fallback |
| Storage | SQLite with indexed columns and FTS5 full-text search |
| Event Explorer | Guided filter builder, time ranges, sorting, pagination, raw record inspection |
| Network Analyzer | Offline PCAP/PCAPNG import, Ethernet and IEEE 802.11 (plus radiotap) decoding, IPv4/IPv6/TCP/UDP/ICMP/DNS/HTTP/TLS, packet hex view, TCP/UDP conversations, encrypted-frame labelling |
| Detection | Four deterministic rules with configurable thresholds and evidence links |
| Investigations | Incident records with notes, attached alerts, statuses and export |
| Two modes | Beginner mode (guided, plain language) and Analyst mode (dense, technical) |
| Workspace | Startup choice between resuming the previous workspace and starting fresh, with confirmation and optional backup |
| Interface | Redesigned shell: 60px navigation rail, top bar with global search, dense professional tables, semantic colour system, Urbanist typography, and a data-driven relationship graph of observed hosts and conversations |

## Stack

- **Desktop shell:** Tauri 2
- **Backend:** Rust (rusqlite, csv, pcap-parser, chrono, ipnet)
- **Frontend:** React 18, TypeScript, Vite
- **Storage:** SQLite (bundled) with FTS5
- **Icons/UI:** lucide-react, custom CSS design system

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - modules, data flow, contracts
- [docs/USER_GUIDE.md](docs/USER_GUIDE.md) - how to use every screen
- [docs/IMPORT_FORMATS.md](docs/IMPORT_FORMATS.md) - every accepted format and how it is detected
- [docs/DECISIONS.md](docs/DECISIONS.md) - why the stack and shapes were chosen
- [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md) - honest V1 boundaries
- [docs/TEST_DATASETS.md](docs/TEST_DATASETS.md) - external datasets you can test with
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) - local-first security posture
- [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) - phases and acceptance criteria
- [PROGRESS.md](PROGRESS.md) - current status

## Development

Prerequisites: Node.js 20+, Rust stable, and a Windows C++ toolchain (MSVC or the GNU
toolchain used for the reference build), plus the WebView2 runtime (present on Windows 11
and current Windows 10).

```bash
npm install
npm run tauri dev      # run the desktop app in development
npm test               # frontend unit tests (vitest)
npm run build          # typecheck + build the frontend bundle
cd src-tauri
cargo test             # backend tests
```

## Build a Windows installer

```bash
npm run tauri build
```

The NSIS installer is written to `src-tauri/target/release/bundle/nsis/`.

## Data location

The SQLite database lives in the per-user application data directory
(`%APPDATA%\\com.nullplinth.app\\nullplinth.db` on Windows). Imported files are never
modified; only parsed records are copied into the local database.

## License

NULLPLINTH is released under the **MIT License**. You may use, copy, modify, merge, publish,
distribute, sublicense and sell copies of the software, provided the copyright notice and
license text are included. The software is provided "as is", without warranty of any kind.

See [LICENSE](LICENSE) for the full text.