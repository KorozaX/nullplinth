# NULLPLINTH user guide

## Install

Run `NULLPLINTH_0.1.0_x64-setup.exe` and follow the installer. It installs per user, needs
no administrator rights, and does not modify system settings. The WebView2 runtime it needs is
present on Windows 10 and 11 by default; the installer fetches it if it is missing.

Uninstall through Settings > Apps like any other desktop application. Your imported data stays
in `%APPDATA%\com.nullplinth.app\` until you delete it.

## First run

The Overview screen is empty until you import something. Two ways to start:

- **Load demo dataset** - a small, clearly labelled synthetic dataset that exercises every
  screen and every detection rule. Use it to learn the interface.
- **Import data** - bring your own logs or packet captures.

Everything runs offline. The application never contacts a network.

## Importing logs

Supported formats: JSON arrays, newline-delimited JSON, Suricata EVE JSON, Zeek TSV logs
(`conn`, `dns`, `http`, `ssl`, `ssh`) and CSV.

1. Open **Data Sources** and choose **Import data**, or use **Import data** on the Overview.
2. Pick a file. The importer detects the format automatically; if detection is ambiguous you
   can force the format.
3. For CSV files the wizard opens: preview the rows, confirm the delimiter and header row,
   then map columns to normalized fields. The timestamp column and format are required; every
   other field is optional. Unmapped columns are preserved in each event's attributes.
4. Watch progress, then review imported and skipped counts. Malformed records are skipped with
   a reason instead of failing the whole import.

The original file is never modified. Re-importing the same file is refused because the file
hash is already known.

## Event Explorer

The guided filter builder is the main way to search.

1. Choose a **data source**: all datasets, one dataset, or one source type.
2. Choose a **time range** preset or a custom range.
3. Add filter rows. Each row is field, operator, value. Rows combine with AND. Operators
   include equals, not equals, contains, does not contain, starts with, greater than, less
   than, exists, does not exist, and IP within CIDR range.
4. Values are validated by type: IP fields need an IP or CIDR, port fields need a port
   number, numeric fields need numbers. Invalid filters are reported, never silently ignored.

The text search box searches event messages and the original records with full-text search.
Results are paginated and sortable; the header shows the total match count and how long the
query took.

Select a row to open the event panel. Beginner mode shows friendly labels and a short
explanation of why the event matters; Analyst mode shows every normalized field, the
additional attributes and the untouched original record. **Export** writes the current result
set to CSV or JSON.

## Network Analyzer

1. Choose **Import capture** and pick a `.pcap` or `.pcapng` file.
2. The packet list shows number, time, source, destination, protocol, length and a summary.
   Filter it with the same guided builder (addresses, ports, protocol, TCP flags, length, time
   range).
3. Select a packet to see the decoded layers (for example Ethernet, IPv4, TCP, HTTP) and the
   raw bytes as hex and ASCII.
4. The **Conversations** view groups packets into bidirectional flows with packet and byte
   counts, first and last seen times, and duration. Selecting a flow filters the packet list.

Unsupported link types and truncated frames are kept and labelled; the raw bytes stay
inspectable. TLS is never decrypted.

## Detection

Open **Alerts** and choose **Run detection**. Four rules run over the stored events:

| Rule | Fires when | Default threshold |
|------|-----------|-------------------|
| Authentication brute force | failed authentications from one source in a window | 5 in 300 s |
| Port scanning | distinct destination ports contacted by one source | 15 in 300 s |
| DNS anomaly | NXDOMAIN responses from one source | 10 in 300 s |
| Suspicious connections | blocked or failed connections from one source | 10 in 300 s |

Thresholds are configurable in **Settings**. Every alert states the rule, the threshold, the
observed count, a plain-language explanation, the recommended next steps, and the exact events
that produced it. Click an evidence row to open the underlying event.

Alerts are findings, not conclusions: "potential brute-force activity" means the threshold was
crossed, not that an account was compromised. Mark an alert new, investigating or resolved, and
add an analyst note.

Re-running detection does not duplicate existing alerts.

## Investigations

Create an investigation from an alert or from the Investigations screen. Add a description,
change status (open, investigating, resolved, closed), write notes, attach related alerts, and
export the whole record as a JSON report.

## Data location and privacy

The database lives at `%APPDATA%\com.nullplinth.app\nullplinth.db`. Nothing is uploaded,
there is no telemetry, and there is no account. Deleting a dataset deletes its events; alerts
that lose all their evidence are removed with it.

## Keyboard and layout

Every control is reachable with Tab and activates with Enter or Space; focus is always
visible. The layout works from 1024x768 upwards and respects reduced-motion preferences.

## Troubleshooting

- **"duplicate file"** - that file hash is already imported. Delete the existing dataset first
  if you really want to re-import it.
- **"CSV imports need an explicit column mapping"** - use the CSV wizard rather than a direct
  import.
- **"timestamp column ... could not be parsed"** - choose the matching format in the wizard.
- **Packet decode shows "unsupported"** - the capture uses a link type NULLPLINTH does not
  decode; raw bytes are still stored.
- **Installer blocked by SmartScreen** - the installer is not code signed; choose "More info"
  then "Run anyway" after verifying the download.
