# Supported import formats

NULLPLINTH detects formats from file **content**, not from the extension. A `.log` file is
generic by nature, so the detector reads the first lines and reports what it found: format,
confidence (high / medium / low), an estimated record count, sample lines and warnings. The
import wizard shows that report before anything is written.

Extensions are only a hint. A file named `firewall.log` containing key=value lines imports as a
firewall log, and a JSON event stream named `.log` imports as JSON.

## Log formats

| Format | Key | Detected by | What is extracted |
|--------|-----|-------------|-------------------|
| Suricata EVE JSON | `suricata` | JSON objects with `event_type` plus `src_ip`/`dest_ip`/`proto`/`alert` | alert, dns, http, tls, flow, anomaly, ssh, fileinfo; Suricata severity 1-3 maps to high/medium/low |
| Zeek TSV | `zeek` | Live `#separator`/`#fields`/`#types` headers | conn, dns, http, ssl, ssh; connection state S0/REJ/RSTO/RSTOS0 becomes a failed action |
| JSON / NDJSON | `json`, `ndjson` | JSON array, object stream or one object per line | normalized fields when present, everything else kept in attributes and the raw record |
| CSV | `csv` | every sampled line has the same delimiter count and parses as a table | mapped columns plus preserved unmapped columns; requires the mapping wizard |
| Linux authentication | `linux_auth` | sshd, sudo, su, PAM, login lines | timestamp, hostname, process, PID, username, source IP, success/failure |
| Syslog | `syslog` | RFC 3164 and RFC 5424 headers | timestamp, host, app, PID, severity from PRI, original message |
| Web access | `web_access` | Apache/Nginx common and combined lines | client IP, timestamp, method, path, status, size, user agent |
| Firewall key=value | `firewall` | `timestamp ACTION PROTO src= dst= port= user= failed=` lines | action (ALLOW/DENY/BLOCK, `failed>0` becomes failed), protocol, endpoints, user |
| Generic text | `generic_text` | fallback for unknown `.log`/`.txt` | one event per non-empty line, original line preserved with its line number; timestamp and fields only when they clearly parse |

Files that match nothing are never rejected silently: the generic fallback imports them as raw
lines and is labelled as such. Unknown binary or unsupported files are refused with a clear
message.

### Generic text rules

- Each non-empty line becomes one event with `source_type = generic_text`.
- The complete original line is stored in the raw record, with the original file name and line
  number in the attributes.
- A timestamp is extracted only when a known pattern parses; otherwise the event timestamp is 0
  and the UI shows it as unknown rather than inventing a time.
- No IP address, severity, category or action is invented.

## CSV mapping

The wizard previews the file and pre-fills a mapping from common header aliases:

| Normalized field | Recognised headers |
|------------------|--------------------|
| timestamp | `time`, `timestamp`, `TimeGenerated`, `event_time`, `datetime` |
| srcIp | `src_ip`, `source_ip`, `Source IP`, `SourceIP`, `srcaddr` |
| dstIp | `dst_ip`, `destination_ip`, `Destination IP`, `dest_ip` |
| srcPort / dstPort | `src_port`, `source_port`, `dst_port`, `destination_port` |
| transport | `proto`, `protocol` |
| username | `user`, `username`, `account` |
| hostname | `host`, `hostname`, `Workstation` |
| message | `msg`, `message`, `description` |
| eventType | `event_type`, `EventType`, `type` |
| severity | `severity`, `level`, `priority` |

Every suggestion can be changed. The timestamp column and format are validated before import;
invalid IPs and ports become NULL on the event instead of being dropped, and unmapped columns
are preserved as attributes.

## Packet captures

| Link type | Number | Support |
|-----------|--------|---------|
| Ethernet | 1 | full: 802.1Q VLAN, IPv4, IPv6, TCP, UDP, ICMP, ARP, DNS, HTTP, TLS metadata |
| IEEE 802.11 | 105 | full MAC header (management/control/data, To DS/From DS, QoS), LLC/SNAP into IP; protected frames marked encrypted |
| Radiotap | 127 | radiotap field walk, then the same 802.11 path |

Other link types are stored with their raw bytes and reported as unsupported. Truncated or
malformed frames are kept and labelled; they never abort an import.

## Limits

- Form field, not a full query language: filtering is guided.
- CSV and log imports stream in batches of 1,000 records inside a transaction; malformed rows are
  counted and reported with a reason.
- Duplicate files (same SHA-256) are rejected instead of imported twice.
