# NULLPLINTH 0.2.0 - quality overhaul

Local-first security analysis workbench for Windows. Everything runs on your machine: no
account, no cloud backend, no telemetry, no external API.

## Highlights

### Imports
- **Content-based format detection.** A `.log` extension is generic, so the detector reads the
  file: Suricata EVE JSON, Zeek TSV, JSON/NDJSON, Linux authentication, syslog (RFC 3164/5424),
  Apache/Nginx access logs, firewall key=value logs, CSV, and a labelled generic-text fallback
  that never invents fields.
- **CSV mapping wizard** with header-alias suggestions, detected delimiter, sample rows,
  estimated row count, type validation, and preserved unmapped columns.
- **Import preview** for any file: detected format, confidence, samples and warnings before
  anything is written.
- **PCAP/PCAPNG import fixed.** Captures are recognised by magic bytes, so the preview no longer
  tries to read binary as text and no longer blocks the import.
- Native drag and drop from Windows Explorer, multiple files, same import route as the button.

### Network analysis
- **IEEE 802.11 (link type 105)** and **radiotap (127)** decoding: full MAC header, management,
  control and data frames, To DS/From DS address handling, QoS, LLC/SNAP into IPv4/IPv6, then
  TCP/UDP/ICMP/DNS/HTTP/TLS.
- Protected frames are labelled encrypted with their wireless metadata and raw bytes, and never
  receive fabricated endpoints or protocols.
- Frame-kind and protocol chips, expandable protocol tree, hex/ASCII view.

### Search and data integrity
- **Fixed a pagination defect** where the first page skipped the first page of results, so a
  search matching one page of rows (for example user equals root) appeared empty.
- Text filters are case-insensitive; numeric and IP filters stay exact.
- Dashboard counters come from database aggregates and import notifications report real counts.
- Deleting a dataset removes derived alerts and dangling investigation links in one transaction.

### Experience
- Semantic colour system: TCP blue, UDP violet, DNS cyan, HTTP green, TLS lavender; critical red,
  high orange, medium amber, low blue, info grey; success green.
- Coloured, data-driven charts with short readable axis labels and legends.
- Responsive containment down to 1024x768; wide tables scroll inside their cards.
- **Workspace startup choice:** resume the previous workspace or start fresh, with explicit
  confirmation, an optional database backup, and a startup preference in Settings. Original
  files on disk are never touched.
- Beginner and Analyst modes both preserved.

## Upgrade notes
- The database schema moves to v2 and is migrated in place; existing datasets, captures, alerts
  and investigations are preserved (verified on a 362 MB workspace with 442,154 packets).
- App version is now 0.2.0.

## Verification
- 72 Rust tests passing (3 heavy real-file tests run manually), 53 frontend tests passing,
  TypeScript and Vite builds clean.
- Real sample files: a 500-line firewall log (500 events, 0 skipped), a 500-row Windows event
  CSV (500 imported, unmapped columns preserved), a 15,512-packet Ethernet capture, and a 65 MB
  IEEE 802.11 capture (426,642 packets: 18,713 management / 204,926 control / 203,003 data,
  200,867 encrypted frames).
- Installer verified by silent install, launch from the installed location and silent uninstall.

## Installation
Download `NULLPLINTH_0.2.0_x64-setup.exe` below and run it. It installs per user, needs no
administrator rights and does not modify system settings. The WebView2 runtime it requires is
already present on Windows 10 and 11. The installer is not code signed, so Windows SmartScreen
will ask for confirmation on first run.

SHA-256 of the installer:
`1DDEAF5499D3F24ED40169A986E940E9FFC07A0A292D724CAC1AE953DEFAB9BB`

## Known limitations
No live packet capture, no TCP stream reassembly, no TLS decryption, no native EVTX parsing, no
import cancellation. See `docs/KNOWN_LIMITATIONS.md` in the repository for the complete list.

## License
MIT. Use it, modify it, ship it.
