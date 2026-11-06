# External test datasets

NULLPLINTH ships with a small synthetic demonstration dataset. Everything below is optional,
third-party material for exercising the importers with real-world telemetry.

**Read this first**

- NULLPLINTH never downloads anything on its own. You download files yourself and import them
  through the UI.
- Do not execute malware. All packet captures and malware artefacts must be treated as inert
  data. NULLPLINTH never executes imported content.
- Public availability is not a licence to redistribute. Each source below keeps its own terms;
  check them before committing data anywhere. Only small, synthetic fixtures are committed to
  this repository.
- All links were reachable at the time this document was written (checked with an HTTP HEAD
  request); availability can change.

## Splunk Boss of the SOC

| | |
|---|---|
| Link | https://github.com/splunk/botsv3 and https://github.com/splunk/securitydatasets |
| Contains | Multi-source security logs (Windows event logs, Sysmon, network, web) from a fictional attack scenario |
| Tests in NULLPLINTH | JSON/NDJSON import, CSV mapping, Event Explorer filtering, detection thresholds |
| Formats | JSON, CSV, some raw logs |
| Size | Hundreds of MB to a few GB depending on version |
| Licence | Check the repository terms; Splunk datasets are shared for research and training |

BOTS is the best end-to-end exercise for the Event Explorer because it has labelled attack
questions with known answers.

## Mordor / OTRF Security-Datasets

| | |
|---|---|
| Link | https://github.com/OTRF/Security-Datasets |
| Contains | Curated, small, attack-labelled datasets produced with Mordor/OTRF tooling |
| Tests in NULLPLINTH | JSON import and time-range filtering; good for reproducible detection checks |
| Formats | JSON, JSONL |
| Size | Individual datasets are usually a few MB |
| Licence | Check the repository licence before redistribution |

These are smaller and easier to iterate on than BOTS.

## EVTX-ATTACK-SAMPLES

| | |
|---|---|
| Link | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES |
| Contains | Windows EVTX files mapped to ATT&CK techniques |
| Tests in NULLPLINTH | V1 does not parse .evtx natively. Export those logs to JSON or CSV with another tool, then import the export |
| Formats | .evtx (unsupported directly), exported JSON/CSV after conversion |
| Size | Small, tens of MB |
| Licence | Check the repository terms |

## CIC-IDS2017

| | |
|---|---|
| Link | https://www.unb.ca/cic/datasets/ids-2017.html |
| Contains | Network flow records with labelled benign and attack traffic |
| Tests in NULLPLINTH | CSV import wizard, column mapping, large-volume filtering and pagination |
| Formats | CSV |
| Size | Several GB uncompressed |
| Licence | Academic use; cite the dataset authors and follow the site terms |

Import a subset first: the CSV wizard handles mapped columns, and the full set is much larger
than a typical laptop wants in a single dataset.

## Malware-Traffic-Analysis.net

| | |
|---|---|
| Link | https://www.malware-traffic-analysis.net/ |
| Contains | Real-world malware traffic exercises: PCAP files plus context |
| Tests in NULLPLINTH | Network Analyzer: PCAP import, protocol decoding, conversations, DNS and HTTP metadata |
| Formats | .pcap |
| Size | A few MB per exercise |
| Licence | Site terms apply; exercises are password-protected ZIPs for safety |

This is the most realistic way to exercise the packet inspector. Keep the files local and do
not redistribute them.

## Zeek sample logs

| | |
|---|---|
| Link | https://mcfp.felk.cvut.cz/publicDatasets/ and https://github.com/zeek/zeek/tree/master/testing/btest/Traces |
| Contains | Zeek logs (conn, dns, http, ssl, ssh) produced from real captures |
| Tests in NULLPLINTH | Zeek TSV ingestion and normalization |
| Formats | TSV (Zeek log format), plus the source .pcap files |
| Size | Varies; a single log file is usually small |
| Licence | Each collection has its own terms; the CTU public dataset collection states its academic-use conditions |

Zeek log files can be imported one by one. The importer reads the header fields, so keep the
original file intact.

## Suricata EVE JSON

If you already run Suricata, point it at a test capture with `-r capture.pcap -l ./logs` and
import the resulting `eve.json`. Alternatively, most public PCAP collections can be replayed
through Suricata locally.

## Utility collections

| | |
|---|---|
| https://www.secrepo.com/ | Security-related PCAPs and logs (Zeek, Suricata, HTTP, DNS) |
| https://docs.zeek.org/en/current/logs/index.html | Reference for the Zeek log format and field meanings |
