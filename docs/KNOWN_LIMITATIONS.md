# Known limitations

This file lists what NULLPLINTH does not do. It is deliberately blunt: a security tool must not
pretend to cover ground it does not.

## Not implemented in V1 (by scope)

- Live packet capture. Only offline PCAP/PCAPNG files can be analysed. Live capture would need
  a kernel driver and administrator rights.
- Full TCP stream reassembly. Packets and conversations are grouped, payloads are not
  reconstructed into streams.
- TLS decryption. Only record and handshake metadata (including SNI when present) is read.
- Native Windows `.evtx` parsing. Convert EVTX to JSON or CSV first, then import.
- YARA scanning, malware sandboxing, or execution of any imported content.
- Splunk SPL or Wireshark display-filter compatibility. Filtering is guided, not a query
  language.
- Machine learning detection. Rules are deterministic and threshold based.
- Cloud sync, remote SIEM integration, threat-intelligence enrichment, multi-user access
  control.

## Gaps inside implemented features

- **Import cancellation** is not implemented. Progress is reported live and imports are
  batched, but a running import cannot be aborted from the UI.
- **Drag and drop import** is not implemented; files are chosen through the native dialog.
- **Packet link types**: Ethernet (with 802.1Q VLAN) is decoded. Other link types are stored as
  raw bytes and labelled unsupported.
- **Protocol coverage**: Ethernet, IPv4, IPv6, TCP, UDP, ICMP/ICMPv6, ARP, DNS, cleartext HTTP
  and TLS record/handshake metadata. Everything else shows as the undecoded remainder.
- **Zeek formats**: the common TSV logs (`conn`, `dns`, `http`, `ssl`, `ssh`) are supported.
  Other Zeek logs import as generic tabular records at best.
- **CSV import** requires explicit column mapping; there is no automatic semantic mapping of
  arbitrary headers.
- **Detection** is heuristic. Thresholds are global, not per-host baselines, so a noisy
  environment can hide activity below the threshold and a quiet one can produce noise.
- **Search** is bounded to 100,000 rows per export and 500 rows per page.
- **Data deletion**: deleting a dataset deletes its events, and any alert that no longer has
  evidence is deleted with them.

## Platform and build notes

- The reference build was produced with the **GNU Rust toolchain**
  (`x86_64-pc-windows-gnu`) because this machine has no MSVC C++ build tools installed. Tauri
  officially recommends MSVC; the GNU build works, and the NSIS installer and application both
  run, but the official toolchain is preferable for maintenance.
- Because of a MinGW linker limitation, the crate does not build Tauri's mobile
  `cdylib`/`staticlib` targets. Desktop builds are unaffected.
- Rust unit tests inside the library target are disabled (`test = false`): the GNU toolchain
  does not apply the Common-Controls manifest link argument to that harness, so it cannot load.
  The entire test suite lives in `src-tauri/tests/` as integration tests and is unaffected.
- The installer is **not code signed**, so Windows SmartScreen will warn on first run.

## Data and privacy limits

- The local SQLite database is not encrypted. Protection is whatever the operating system's
  user profile permissions provide.
- Imported data is treated as untrusted input and rendered as text, but a malicious capture
  could still be large enough to exhaust memory on a very small machine.
- Synthetic test data is labelled as synthetic everywhere; it must never be mistaken for real
  telemetry.
