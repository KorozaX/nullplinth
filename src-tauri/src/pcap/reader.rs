//! Streaming capture readers for legacy PCAP and PCAPNG.
//!
//! Both container formats are read through pcap-parser's generic streaming reader,
//! which handles little/big endian files and section changes. Packets are copied out
//! of the circular buffer before it is refilled, then decoded one at a time.

use crate::error::{AppError, AppResult};
use pcap_parser::traits::PcapNGPacketBlock;
use pcap_parser::{create_reader, Block, PcapBlockOwned, PcapError};
use std::fs::File;

/// One packet as it was stored in the capture file.
#[derive(Debug, Clone)]
pub struct RawPacket {
    pub packet_no: u32,
    pub ts_ms: i64,
    pub caplen: u32,
    pub origlen: u32,
    /// pcap link type of the interface that produced this packet.
    pub link_type: i32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct CaptureMeta {
    /// "PCAP" or "PCAPNG"
    pub format: String,
    pub link_type: Option<i32>,
    pub warnings: Vec<String>,
}

impl CaptureMeta {
    /// Human readable link type, e.g. "Ethernet (1)" or "IEEE 802.11 (105)".
    pub fn link_type_label(&self) -> Option<String> {
        self.link_type
            .map(|lt| format!("{} ({})", link_type_name(lt), lt))
    }
}

pub fn link_type_name(link_type: i32) -> &'static str {
    match link_type {
        0 => "NULL/Loopback",
        1 => "Ethernet",
        9 => "PPP",
        10 => "FDDI",
        101 => "Raw IP",
        105 => "IEEE 802.11",
        113 => "Linux cooked",
        127 => "IEEE 802.11 radiotap",
        228 => "Raw IPv4",
        229 => "Raw IPv6",
        276 => "Linux cooked v2",
        _ => "LINKTYPE",
    }
}

#[derive(Debug, Clone, Copy)]
struct InterfaceInfo {
    link_type: i32,
    /// Timestamp resolution: units per second.
    resolution: u64,
    /// Timestamp offset, seconds.
    offset: i64,
}

impl Default for InterfaceInfo {
    fn default() -> Self {
        InterfaceInfo {
            link_type: 1,
            resolution: 1_000_000,
            offset: 0,
        }
    }
}

/// Read every packet of a capture file, calling on_packet in file order.
///
/// Returns the capture metadata plus the number of packets handed to the callback.
/// A valid container with a corrupt tail is imported up to the last good packet and
/// records a warning; a file that is not PCAP/PCAPNG at all is an error.
pub fn read_capture<F>(path: &str, mut on_packet: F) -> AppResult<(CaptureMeta, i64)>
where
    F: FnMut(&RawPacket) -> AppResult<()>,
{
    let file = File::open(path)
        .map_err(|e| AppError::msg(format!("cannot open capture file '{path}': {e}")))?;
    let mut reader = match create_reader(1 << 20, file) {
        Ok(r) => r,
        Err(PcapError::Eof) => {
            return Err(AppError::msg(format!(
                "'{path}' is empty and is not a PCAP or PCAPNG capture file"
            )))
        }
        Err(PcapError::HeaderNotRecognized) => {
            return Err(AppError::msg(format!(
                "'{path}' is not a PCAP or PCAPNG capture file (magic number not recognized)"
            )))
        }
        Err(e) => {
            return Err(AppError::msg(format!(
                "'{path}' could not be parsed as a capture file: {e}"
            )))
        }
    };

    let mut meta = CaptureMeta::default();
    let mut interfaces: Vec<InterfaceInfo> = Vec::new();
    let mut packet_no: u32 = 0;
    let mut last_ts: i64 = 0;
    let mut nanosecond_pcap = false;
    let mut warned_spb = false;
    let mut incomplete_rounds = 0usize;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                incomplete_rounds = 0;
                match block {
                    PcapBlockOwned::LegacyHeader(header) => {
                        meta.format = "PCAP".to_string();
                        meta.link_type = Some(header.network.0);
                        nanosecond_pcap = header.is_nanosecond_precision();
                    }
                    PcapBlockOwned::Legacy(frame) => {
                        let ts_ms = legacy_timestamp_ms(frame.ts_sec, frame.ts_usec, nanosecond_pcap);
                        last_ts = ts_ms;
                        let raw = RawPacket {
                            packet_no,
                            ts_ms,
                            caplen: frame.caplen,
                            origlen: frame.origlen,
                            link_type: meta.link_type.unwrap_or(1),
                            data: frame.data.to_vec(),
                        };
                        packet_no += 1;
                        on_packet(&raw)?;
                    }
                    PcapBlockOwned::NG(ng) => match ng {
                        Block::SectionHeader(_) => {
                            meta.format = "PCAPNG".to_string();
                            interfaces.clear();
                        }
                        Block::InterfaceDescription(idb) => {
                            let link_type = idb.linktype.0;
                            if meta.link_type.is_none() {
                                meta.link_type = Some(link_type);
                            }
                            let resolution = match idb.ts_resolution() {
                                Some(r) if r > 0 => r,
                                _ => 1_000_000,
                            };
                            interfaces.push(InterfaceInfo {
                                link_type,
                                resolution,
                                offset: idb.ts_offset(),
                            });
                        }
                        Block::EnhancedPacket(ref epb) => {
                            let iface = interfaces
                                .get(epb.if_id as usize)
                                .copied()
                                .unwrap_or_default();
                            if interfaces.is_empty() && meta.warnings.is_empty() {
                                meta.warnings.push(
                                    "enhanced packet block without an interface description; assuming Ethernet"
                                        .to_string(),
                                );
                            }
                            let (secs, frac) =
                                epb.decode_ts(iface.offset.max(0) as u64, iface.resolution);
                            let ts_ms = pcapng_timestamp_ms(secs, frac, iface.resolution);
                            last_ts = ts_ms;
                            let data = epb.packet_data().to_vec();
                            let caplen = epb.caplen;
                            let raw = RawPacket {
                                packet_no,
                                ts_ms,
                                caplen: caplen.min(data.len() as u32),
                                origlen: epb.origlen,
                                link_type: iface.link_type,
                                data,
                            };
                            packet_no += 1;
                            on_packet(&raw)?;
                        }
                        Block::SimplePacket(ref spb) => {
                            let iface = interfaces.first().copied().unwrap_or_default();
                            if !warned_spb {
                                warned_spb = true;
                                meta.warnings.push(
                                    "simple packet blocks carry no timestamp; using the previous packet time"
                                        .to_string(),
                                );
                            }
                            let data = spb.packet_data().to_vec();
                            let raw = RawPacket {
                                packet_no,
                                ts_ms: last_ts,
                                caplen: data.len() as u32,
                                origlen: spb.origlen,
                                link_type: iface.link_type,
                                data,
                            };
                            packet_no += 1;
                            on_packet(&raw)?;
                        }
                        _ => {}
                    },
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                incomplete_rounds += 1;
                if incomplete_rounds > 4 {
                    meta.warnings
                        .push("capture ends with an incomplete block; partial capture kept".to_string());
                    break;
                }
                if reader.refill().is_err() {
                    meta.warnings
                        .push("capture ends with an incomplete block; partial capture kept".to_string());
                    break;
                }
            }
            Err(PcapError::UnexpectedEof) => {
                meta.warnings
                    .push("capture ends with a truncated packet; partial capture kept".to_string());
                break;
            }
            Err(e) => {
                if packet_no == 0 && meta.link_type.is_none() {
                    return Err(AppError::msg(format!(
                        "'{path}' could not be parsed as a capture file: {e}"
                    )));
                }
                meta.warnings.push(format!(
                    "stopped reading after {packet_no} packet(s): {e}"
                ));
                break;
            }
        }
    }

    Ok((meta, packet_no as i64))
}

fn legacy_timestamp_ms(ts_sec: u32, ts_frac: u32, nanosecond: bool) -> i64 {
    let base = ts_sec as i64 * 1000;
    if nanosecond {
        base + (ts_frac as i64 / 1_000_000)
    } else {
        base + (ts_frac as i64 / 1_000)
    }
}

fn pcapng_timestamp_ms(secs: u32, frac: u32, resolution: u64) -> i64 {
    let resolution = resolution.max(1);
    secs as i64 * 1000 + ((frac as u64).saturating_mul(1000) / resolution) as i64
}
