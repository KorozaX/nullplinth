//! Bounds-checked offline packet decoders.
//!
//! Every read goes through the small helpers below and every length is checked, so
//! truncated or hostile captures can never panic the importer. No payload is ever
//! decrypted and no markup is interpreted: payload text is data, not content.

use crate::types::{LayerNode, ProtoField};

/// Everything one decoded frame contributes to the packet row.
#[derive(Debug, Clone, Default)]
pub struct Decoded {
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<i64>,
    pub dst_port: Option<i64>,
    /// Most specific protocol we could decode (HTTP, DNS, TLS, TCP, UDP, ICMP, ...).
    pub protocol: String,
    pub transport: Option<String>,
    pub tcp_flags: Option<String>,
    pub payload_len: i64,
    pub summary: String,
    pub layers: Vec<LayerNode>,
    /// 802.11 frame class (management | control | data); None for non-wireless frames.
    pub frame_kind: Option<String>,
    /// True when an 802.11 frame was protected/encrypted.
    pub encrypted: bool,
}

// ------------------------------------------------------------------ helpers

pub(crate) fn layer(name: &str, label: impl Into<String>) -> LayerNode {
    LayerNode {
        name: name.to_string(),
        label: label.into(),
        fields: Vec::new(),
        children: Vec::new(),
    }
}

pub(crate) fn fld(name: &str, value: impl Into<String>) -> ProtoField {
    ProtoField {
        name: name.to_string(),
        value: value.into(),
    }
}

fn rd(data: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    let end = off.checked_add(len)?;
    data.get(off..end)
}

pub(crate) fn be16(data: &[u8], off: usize) -> Option<u16> {
    let b = rd(data, off, 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

pub(crate) fn be32(data: &[u8], off: usize) -> Option<u32> {
    let b = rd(data, off, 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

pub(crate) fn mac_str(data: &[u8], off: usize) -> Option<String> {
    let b = rd(data, off, 6)?;
    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    ))
}

fn ipv4_str(data: &[u8], off: usize) -> Option<String> {
    let b = rd(data, off, 4)?;
    Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
}

fn ipv6_str(data: &[u8], off: usize) -> Option<String> {
    let b = rd(data, off, 16)?;
    let mut groups = [0u16; 8];
    for (i, g) in groups.iter_mut().enumerate() {
        *g = u16::from_be_bytes([b[i * 2], b[i * 2 + 1]]);
    }
    Some(std::net::Ipv6Addr::from(groups).to_string())
}

fn printable_text(bytes: &[u8], max: usize) -> Option<String> {
    let head = bytes.get(..bytes.len().min(max))?;
    if head
        .iter()
        .any(|b| *b < 0x20 && *b != b'\r' && *b != b'\n' && *b != b'\t')
    {
        return None;
    }
    Some(String::from_utf8_lossy(head).to_string())
}

fn one_line(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c == '\r' || c == '\n' || c == '\t' { ' ' } else { c })
        .collect();
    cleaned.trim().to_string()
}

// ------------------------------------------------------------- entry point

/// Decode one captured frame for the given pcap link type.
pub fn decode_frame(link_type: i32, data: &[u8]) -> Decoded {
    let mut d = Decoded::default();
    match link_type {
        1 => decode_ethernet(&mut d, data),
        105 => super::wifi::decode_80211(&mut d, data),
        127 => super::wifi::decode_radiotap(&mut d, data),
        101 | 228 => decode_ipv4(&mut d, data, 0),
        229 => decode_ipv6(&mut d, data, 0),
        other => {
            d.protocol = "Unknown".to_string();
            d.summary = format!("Unsupported link type {other} ({} byte frame)", data.len());
            let mut node = layer("frame", "Raw frame");
            node.fields.push(fld("Link type", other.to_string()));
            node.fields.push(fld("Captured length", data.len().to_string()));
            d.layers.push(node);
            return d;
        }
    }
    if d.protocol.is_empty() {
        d.protocol = "Unknown".to_string();
    }
    if d.summary.is_empty() {
        d.summary = format!("{} byte frame", data.len());
    }
    d
}

// --------------------------------------------------------------- ethernet

fn decode_ethernet(d: &mut Decoded, data: &[u8]) {
    let mut eth = layer("eth", "Ethernet II");
    if data.len() < 14 {
        eth.fields
            .push(fld("Note", format!("truncated: {} of 14 header bytes", data.len())));
        d.layers.push(eth);
        d.protocol = "Ethernet".to_string();
        d.summary = format!("Truncated Ethernet frame ({} bytes)", data.len());
        return;
    }
    if let Some(dst) = mac_str(data, 0) {
        eth.fields.push(fld("Destination", dst));
    }
    if let Some(src) = mac_str(data, 6) {
        eth.fields.push(fld("Source", src));
    }
    let mut ethertype = be16(data, 12).unwrap_or(0);
    eth.fields
        .push(fld("Type", format!("0x{ethertype:04x} ({})", ethertype_name(ethertype))));
    d.layers.push(eth);
    let mut off = 14usize;

    // 802.1Q / QinQ tags
    let mut vlan_tags = 0;
    while ethertype == 0x8100 || ethertype == 0x88a8 || ethertype == 0x9100 {
        vlan_tags += 1;
        if vlan_tags > 4 {
            d.protocol = "Ethernet".to_string();
            d.summary = "Ethernet frame with too many VLAN tags".to_string();
            return;
        }
        let mut vlan = layer("vlan", "802.1Q Virtual LAN");
        let tci = match be16(data, off) {
            Some(v) => v,
            None => {
                vlan.fields.push(fld("Note", "truncated VLAN tag"));
                d.layers.push(vlan);
                d.protocol = "Ethernet".to_string();
                d.summary = format!("Truncated VLAN frame ({} bytes)", data.len());
                return;
            }
        };
        vlan.fields
            .push(fld("Priority", format!("{}", (tci >> 13) & 0x7)));
        vlan.fields.push(fld("VLAN ID", format!("{}", tci & 0x0fff)));
        ethertype = be16(data, off + 2).unwrap_or(0);
        vlan.fields
            .push(fld("Type", format!("0x{ethertype:04x} ({})", ethertype_name(ethertype))));
        off += 4;
        d.layers.push(vlan);
    }

    match ethertype {
        0x0800 => decode_ipv4(d, data, off),
        0x86dd => decode_ipv6(d, data, off),
        0x0806 => decode_arp(d, data, off),
        other => {
            d.protocol = "Ethernet".to_string();
            d.summary = format!(
                "Ethernet frame, ethertype 0x{other:04x} ({}), {} bytes",
                ethertype_name(other),
                data.len().saturating_sub(off)
            );
        }
    }
}

// ------------------------------------------------------------------- IPv4

pub(crate) fn decode_ipv4(d: &mut Decoded, data: &[u8], off: usize) {
    let mut ip = layer("ip", "Internet Protocol Version 4");
    if data.len() < off + 20 {
        ip.fields
            .push(fld("Note", format!("truncated: {} of 20 header bytes", data.len().saturating_sub(off))));
        d.layers.push(ip);
        d.protocol = "IPv4".to_string();
        d.summary = "Truncated IPv4 header".to_string();
        return;
    }
    let version = data[off] >> 4;
    let ihl = ((data[off] & 0x0f) as usize) * 4;
    let total_len = be16(data, off + 2).unwrap_or(0) as usize;
    let ident = be16(data, off + 4).unwrap_or(0);
    let flags_frag = be16(data, off + 6).unwrap_or(0);
    let ttl = data[off + 8];
    let proto = data[off + 9];
    let checksum = be16(data, off + 10).unwrap_or(0);
    let src = ipv4_str(data, off + 12);
    let dst = ipv4_str(data, off + 16);

    ip.fields.push(fld("Version", format!("{version}")));
    ip.fields
        .push(fld("Header Length", format!("{ihl} bytes")));
    ip.fields
        .push(fld("Total Length", format!("{total_len} bytes")));
    ip.fields.push(fld("Identification", format!("0x{ident:04x}")));
    let mut flag_names: Vec<&str> = Vec::new();
    if flags_frag & 0x4000 != 0 {
        flag_names.push("DF");
    }
    if flags_frag & 0x2000 != 0 {
        flag_names.push("MF");
    }
    ip.fields.push(fld(
        "Flags",
        if flag_names.is_empty() {
            "none".to_string()
        } else {
            flag_names.join(", ")
        },
    ));
    ip.fields
        .push(fld("Fragment Offset", format!("{}", (flags_frag & 0x1fff) * 8)));
    ip.fields.push(fld("TTL", format!("{ttl}")));
    ip.fields
        .push(fld("Protocol", format!("{} ({})", ip_proto_name(proto), proto)));
    ip.fields.push(fld("Header Checksum", format!("0x{checksum:04x}")));
    if let Some(s) = src.as_ref() {
        ip.fields.push(fld("Source Address", s.clone()));
    }
    if let Some(s) = dst.as_ref() {
        ip.fields.push(fld("Destination Address", s.clone()));
    }

    d.src_ip = src;
    d.dst_ip = dst;

    if ihl < 20 {
        ip.fields.push(fld("Note", "invalid IP header length"));
        d.layers.push(ip);
        d.protocol = "IPv4".to_string();
        d.summary = "Invalid IPv4 header length".to_string();
        return;
    }
    let header_len = ihl;
    if off + header_len > data.len() {
        ip.fields.push(fld("Note", "truncated IP header"));
        d.layers.push(ip);
        d.protocol = "IPv4".to_string();
        d.summary = "Truncated IPv4 header".to_string();
        return;
    }
    // total_len is 0 for some TSO captures; fall back to the captured length.
    let declared_end = off + total_len;
    let captured_end = data.len();
    let payload_end = if total_len >= header_len {
        declared_end.min(captured_end)
    } else {
        captured_end
    }
    .max(off + header_len);
    if total_len >= header_len && declared_end > captured_end {
        ip.fields.push(fld(
            "Note",
            format!(
                "truncated: {} of {} bytes captured",
                captured_end.saturating_sub(off),
                total_len
            ),
        ));
    }
    let payload = &data[off + header_len..payload_end];
    d.layers.push(ip);

    if flags_frag & 0x1fff != 0 {
        d.protocol = "IPv4".to_string();
        d.summary = format!(
            "IPv4 fragment at offset {} (protocol {})",
            (flags_frag & 0x1fff) * 8,
            ip_proto_name(proto)
        );
        return;
    }

    match proto {
        6 => decode_tcp(d, payload),
        17 => decode_udp(d, payload),
        1 => decode_icmp(d, payload, false),
        58 => decode_icmp(d, payload, true),
        other => {
            d.protocol = "IPv4".to_string();
            d.summary = format!(
                "IPv4 {} from {} to {}",
                ip_proto_name(other),
                d.src_ip.as_deref().unwrap_or("?"),
                d.dst_ip.as_deref().unwrap_or("?")
            );
        }
    }
}

// ------------------------------------------------------------------- IPv6

pub(crate) fn decode_ipv6(d: &mut Decoded, data: &[u8], off: usize) {
    let mut ip = layer("ip", "Internet Protocol Version 6");
    if data.len() < off + 40 {
        ip.fields.push(fld("Note", "truncated: fewer than 40 header bytes"));
        d.layers.push(ip);
        d.protocol = "IPv6".to_string();
        d.summary = "Truncated IPv6 header".to_string();
        return;
    }
    let payload_len = be16(data, off + 4).unwrap_or(0) as usize;
    let mut next = data[off + 6];
    let hop = data[off + 7];
    let src = ipv6_str(data, off + 8);
    let dst = ipv6_str(data, off + 24);
    ip.fields
        .push(fld("Version", format!("{}", data[off] >> 4)));
    ip.fields
        .push(fld("Payload Length", format!("{payload_len} bytes")));
    ip.fields.push(fld("Hop Limit", format!("{hop}")));
    if let Some(s) = src.as_ref() {
        ip.fields.push(fld("Source Address", s.clone()));
    }
    if let Some(s) = dst.as_ref() {
        ip.fields.push(fld("Destination Address", s.clone()));
    }
    d.src_ip = src;
    d.dst_ip = dst;

    let declared_end = off + 40 + payload_len;
    let mut cursor = off + 40;
    // Walk a couple of extension headers; bounded so a hostile file cannot loop us.
    let mut ext_count = 0;
    while matches!(next, 0 | 43 | 60) {
        ext_count += 1;
        if ext_count > 8 {
            break;
        }
        let hdr = match rd(data, cursor, 2) {
            Some(h) => h,
            None => {
                ip.fields.push(fld("Note", "truncated IPv6 extension header"));
                d.layers.push(ip);
                d.protocol = "IPv6".to_string();
                d.summary = "Truncated IPv6 extension header".to_string();
                return;
            }
        };
        let next_header = hdr[0];
        let ext_len = (hdr[1] as usize + 1) * 8;
        ip.fields.push(fld(
            "Extension Header",
            format!("{} ({} bytes)", ipv6_ext_name(next), ext_len),
        ));
        if rd(data, cursor, ext_len).is_none() {
            ip.fields.push(fld("Note", "truncated IPv6 extension header"));
            d.layers.push(ip);
            d.protocol = "IPv6".to_string();
            d.summary = "Truncated IPv6 extension header".to_string();
            return;
        }
        cursor += ext_len;
        next = next_header;
    }
    let payload_end = if payload_len > 0 {
        declared_end.min(data.len())
    } else {
        data.len()
    }
    .max(cursor);
    if payload_len > 0 && declared_end > data.len() {
        ip.fields.push(fld(
            "Note",
            format!(
                "truncated: {} of {} bytes captured",
                data.len().saturating_sub(off),
                40 + payload_len
            ),
        ));
    }
    let payload = data.get(cursor..payload_end).unwrap_or(&[]);
    d.layers.push(ip);

    match next {
        6 => decode_tcp(d, payload),
        17 => decode_udp(d, payload),
        58 => decode_icmp(d, payload, true),
        other => {
            d.protocol = "IPv6".to_string();
            d.summary = format!(
                "IPv6 {} from {} to {}",
                ip_proto_name(other),
                d.src_ip.as_deref().unwrap_or("?"),
                d.dst_ip.as_deref().unwrap_or("?")
            );
        }
    }
}

// -------------------------------------------------------------------- TCP

fn decode_tcp(d: &mut Decoded, seg: &[u8]) {
    let mut tcp = layer("tcp", "Transmission Control Protocol");
    d.transport = Some("TCP".to_string());
    if seg.len() < 20 {
        tcp.fields
            .push(fld("Note", format!("truncated: {} of 20 header bytes", seg.len())));
        d.layers.push(tcp);
        d.protocol = "TCP".to_string();
        d.summary = format!(
            "TCP segment, truncated header ({} bytes)",
            seg.len()
        );
        return;
    }
    let sport = be16(seg, 0).unwrap_or(0);
    let dport = be16(seg, 2).unwrap_or(0);
    let seq = be32(seg, 4).unwrap_or(0);
    let ack = be32(seg, 8).unwrap_or(0);
    let data_off = ((seg[12] >> 4) as usize) * 4;
    let flags_byte = seg[13];
    let flags = tcp_flags_string(flags_byte);
    let window = be16(seg, 14).unwrap_or(0);
    let checksum = be16(seg, 16).unwrap_or(0);

    d.src_port = Some(sport as i64);
    d.dst_port = Some(dport as i64);
    d.tcp_flags = Some(flags.clone());

    tcp.fields.push(fld("Source Port", sport.to_string()));
    tcp.fields.push(fld("Destination Port", dport.to_string()));
    tcp.fields.push(fld("Sequence Number", seq.to_string()));
    tcp.fields.push(fld("Acknowledgment Number", ack.to_string()));
    tcp.fields
        .push(fld("Header Length", format!("{} bytes", data_off.max(20))));
    tcp.fields.push(fld("Flags", flags.clone()));
    tcp.fields.push(fld("Window Size", window.to_string()));
    tcp.fields.push(fld("Checksum", format!("0x{checksum:04x}")));

    let header_len = data_off.max(20);
    let mut payload: &[u8] = &[];
    if header_len <= seg.len() {
        payload = &seg[header_len..];
    } else {
        tcp.fields
            .push(fld("Note", format!("truncated: needs {header_len} header bytes, {} captured", seg.len())));
    }
    d.payload_len = payload.len() as i64;
    tcp.fields
        .push(fld("Payload Length", format!("{} bytes", payload.len())));
    d.layers.push(tcp);

    d.protocol = "TCP".to_string();
    d.summary = format!(
        "{}:{} -> {}:{} [{}] len={}",
        d.src_ip.as_deref().unwrap_or("?"),
        sport,
        d.dst_ip.as_deref().unwrap_or("?"),
        dport,
        flags,
        payload.len()
    );

    if payload.is_empty() {
        return;
    }
    if sport == 80 || dport == 80 || sport == 8080 || dport == 8080 {
        if let Some((summary, node)) = decode_http(payload) {
            d.protocol = "HTTP".to_string();
            d.summary = summary;
            d.layers.push(node);
            return;
        }
    }
    if sport == 443 || dport == 443 || sport == 8443 || dport == 8443 {
        if let Some((summary, node)) = decode_tls(payload) {
            d.protocol = "TLS".to_string();
            d.summary = summary;
            d.layers.push(node);
        }
    }
}

fn tcp_flags_string(flags: u8) -> String {
    // Wireshark-ish ordering, so SYN+ACK reads "SYN, ACK".
    const ORDER: [(u8, &str); 8] = [
        (0x02, "SYN"),
        (0x01, "FIN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
        (0x10, "ACK"),
    ];
    let mut out: Vec<&str> = Vec::new();
    for (bit, name) in ORDER {
        if flags & bit != 0 {
            out.push(name);
        }
    }
    if out.is_empty() {
        "none".to_string()
    } else {
        out.join(", ")
    }
}

// -------------------------------------------------------------------- UDP

fn decode_udp(d: &mut Decoded, datagram: &[u8]) {
    let mut udp = layer("udp", "User Datagram Protocol");
    d.transport = Some("UDP".to_string());
    if datagram.len() < 8 {
        udp.fields
            .push(fld("Note", format!("truncated: {} of 8 header bytes", datagram.len())));
        d.layers.push(udp);
        d.protocol = "UDP".to_string();
        d.summary = "UDP datagram, truncated header".to_string();
        return;
    }
    let sport = be16(datagram, 0).unwrap_or(0);
    let dport = be16(datagram, 2).unwrap_or(0);
    let udp_len = be16(datagram, 4).unwrap_or(0) as usize;
    let checksum = be16(datagram, 6).unwrap_or(0);
    let declared_payload = udp_len.saturating_sub(8);
    let payload_end = if udp_len >= 8 {
        (8 + declared_payload).min(datagram.len())
    } else {
        datagram.len()
    };
    let payload = datagram.get(8..payload_end).unwrap_or(&[]);

    d.src_port = Some(sport as i64);
    d.dst_port = Some(dport as i64);
    d.payload_len = payload.len() as i64;

    udp.fields.push(fld("Source Port", sport.to_string()));
    udp.fields.push(fld("Destination Port", dport.to_string()));
    udp.fields.push(fld("Length", format!("{udp_len} bytes")));
    udp.fields.push(fld("Payload Length", format!("{} bytes", payload.len())));
    udp.fields.push(fld("Checksum", format!("0x{checksum:04x}")));
    d.layers.push(udp);

    d.protocol = "UDP".to_string();
    d.summary = format!(
        "{}:{} -> {}:{} len={}",
        d.src_ip.as_deref().unwrap_or("?"),
        sport,
        d.dst_ip.as_deref().unwrap_or("?"),
        dport,
        payload.len()
    );

    if (sport == 53 || dport == 53) && !payload.is_empty() {
        if let Some((summary, node)) = decode_dns(payload) {
            d.protocol = "DNS".to_string();
            d.summary = summary;
            d.layers.push(node);
        }
    }
}

// ------------------------------------------------------------------- ICMP

fn decode_icmp(d: &mut Decoded, msg: &[u8], v6: bool) {
    let name = if v6 { "icmpv6" } else { "icmp" };
    let label = if v6 {
        "Internet Control Message Protocol v6"
    } else {
        "Internet Control Message Protocol"
    };
    let mut icmp = layer(name, label);
    let protocol = if v6 { "ICMPv6" } else { "ICMP" };
    d.protocol = protocol.to_string();
    if msg.len() < 4 {
        icmp.fields
            .push(fld("Note", format!("truncated: {} of 4 header bytes", msg.len())));
        d.layers.push(icmp);
        d.summary = format!("{protocol} message, truncated header");
        return;
    }
    let msg_type = msg[0];
    let code = msg[1];
    let checksum = be16(msg, 2).unwrap_or(0);
    let type_name = icmp_type_name(msg_type, v6);
    icmp.fields.push(fld("Type", format!("{type_name} ({msg_type})")));
    icmp.fields.push(fld("Code", code.to_string()));
    icmp.fields.push(fld("Checksum", format!("0x{checksum:04x}")));
    if msg_type == 8 || msg_type == 0 || msg_type == 128 || msg_type == 129 {
        if let (Some(id), Some(seq)) = (be16(msg, 4), be16(msg, 6)) {
            icmp.fields.push(fld("Identifier", format!("0x{id:04x}")));
            icmp.fields.push(fld("Sequence Number", seq.to_string()));
        }
    }
    d.layers.push(icmp);
    d.summary = format!(
        "{protocol} {type_name} from {} to {}",
        d.src_ip.as_deref().unwrap_or("?"),
        d.dst_ip.as_deref().unwrap_or("?")
    );
}

// -------------------------------------------------------------------- ARP

pub(crate) fn decode_arp(d: &mut Decoded, data: &[u8], off: usize) {
    let mut arp = layer("arp", "Address Resolution Protocol");
    d.protocol = "ARP".to_string();
    if data.len() < off + 28 {
        arp.fields.push(fld("Note", "truncated ARP header"));
        d.layers.push(arp);
        d.summary = "Truncated ARP packet".to_string();
        return;
    }
    let op = be16(data, off + 6).unwrap_or(0);
    let sender_mac = mac_str(data, off + 8);
    let sender_ip = ipv4_str(data, off + 14);
    let target_mac = mac_str(data, off + 18);
    let target_ip = ipv4_str(data, off + 24);
    arp.fields.push(fld(
        "Operation",
        match op {
            1 => "request (1)".to_string(),
            2 => "reply (2)".to_string(),
            other => format!("{other}"),
        },
    ));
    if let Some(v) = sender_mac.as_ref() {
        arp.fields.push(fld("Sender MAC", v.clone()));
    }
    if let Some(v) = sender_ip.as_ref() {
        arp.fields.push(fld("Sender IP", v.clone()));
    }
    if let Some(v) = target_mac.as_ref() {
        arp.fields.push(fld("Target MAC", v.clone()));
    }
    if let Some(v) = target_ip.as_ref() {
        arp.fields.push(fld("Target IP", v.clone()));
    }
    d.src_ip = sender_ip;
    d.dst_ip = target_ip;
    d.layers.push(arp);
    d.summary = format!(
        "ARP {} {} -> {}",
        if op == 1 { "request" } else { "reply" },
        d.src_ip.as_deref().unwrap_or("?"),
        d.dst_ip.as_deref().unwrap_or("?")
    );
}

// -------------------------------------------------------------------- DNS

fn decode_dns(msg: &[u8]) -> Option<(String, LayerNode)> {
    if msg.len() < 12 {
        return None;
    }
    let id = be16(msg, 0)?;
    let flags = be16(msg, 2)?;
    let qr = flags & 0x8000 != 0;
    let rcode = flags & 0x000f;
    let qd = be16(msg, 4)?;
    let an = be16(msg, 6)?;
    let mut node = layer("dns", "Domain Name System");
    node.fields.push(fld("Transaction ID", format!("0x{id:04x}")));
    node.fields
        .push(fld("Message Type", if qr { "response" } else { "query" }));
    node.fields.push(fld(
        "Flags",
        format!(
            "QR={} RD={} RA={} AA={} TC={} AD={} CD={}",
            if qr { 1 } else { 0 },
            (flags >> 8) & 1,
            (flags >> 7) & 1,
            (flags >> 10) & 1,
            (flags >> 9) & 1,
            (flags >> 5) & 1,
            (flags >> 4) & 1
        ),
    ));
    node.fields
        .push(fld("Rcode", format!("{rcode} ({})", rcode_name(rcode))));
    node.fields.push(fld("Questions", qd.to_string()));
    node.fields.push(fld("Answers", an.to_string()));

    let mut qname: Option<String> = None;
    let mut qtype: Option<u16> = None;
    if qd > 0 {
        if let Some((name, next_off)) = dns_name(msg, 12) {
            if let Some(t) = be16(msg, next_off) {
                node.fields.push(fld("Query Name", name.clone()));
                node.fields
                    .push(fld("Query Type", format!("{} ({t})", dns_type_name(t))));
                if let Some(class) = be16(msg, next_off + 2) {
                    node.fields.push(fld("Query Class", dns_class_name(class)));
                }
                qname = Some(name);
                qtype = Some(t);
            }
        }
    }

    let summary = match (&qname, qr) {
        (Some(name), false) => format!(
            "DNS query {} {}",
            qtype.map(dns_type_name).unwrap_or("TYPE"),
            name
        ),
        (Some(name), true) => format!(
            "DNS response {} {} rcode={} ({})",
            qtype.map(dns_type_name).unwrap_or("TYPE"),
            name,
            rcode,
            rcode_name(rcode)
        ),
        (None, false) => "DNS query".to_string(),
        (None, true) => format!("DNS response rcode={} ({})", rcode, rcode_name(rcode)),
    };
    Some((summary, node))
}

/// Parse a (possibly compressed) DNS name. Returns the name and the offset just past it.
fn dns_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut end_after: Option<usize> = None;
    let mut jumps = 0usize;
    loop {
        let len = *msg.get(pos)?;
        if len == 0 {
            if end_after.is_none() {
                end_after = Some(pos + 1);
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            let next = *msg.get(pos + 1)?;
            if end_after.is_none() {
                end_after = Some(pos + 2);
            }
            jumps += 1;
            if jumps > 32 {
                return None;
            }
            pos = (((len as usize) & 0x3f) << 8) | next as usize;
            continue;
        }
        if len > 63 {
            return None;
        }
        let start = pos + 1;
        let stop = start + len as usize;
        let label = msg.get(start..stop)?;
        labels.push(String::from_utf8(label.to_vec()).ok()?);
        if labels.len() > 128 {
            return None;
        }
        pos = stop;
    }
    let offset = end_after.unwrap_or(pos + 1);
    Some((labels.join("."), offset))
}

// ------------------------------------------------------------------- HTTP

fn is_http_method(s: &str) -> bool {
    matches!(
        s,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "CONNECT" | "TRACE"
    )
}

fn decode_http(payload: &[u8]) -> Option<(String, LayerNode)> {
    let text = printable_text(payload, 8192)?;
    let mut lines = text.split("\r\n");
    let first = lines.next()?;
    if first.is_empty() {
        return None;
    }
    let mut node = layer("http", "Hypertext Transfer Protocol");

    if first.starts_with("HTTP/") {
        // Response: HTTP/1.1 200 OK
        let mut parts = first.splitn(3, ' ');
        let version = parts.next().unwrap_or("");
        let code = parts.next().unwrap_or("");
        let reason = parts.next().unwrap_or("").trim();
        node.fields.push(fld("Type", "response"));
        node.fields.push(fld("Status Line", first.trim()));
        node.fields.push(fld("Version", version));
        node.fields.push(fld("Status Code", code));
        node.fields.push(fld("Reason", reason));
        for line in lines.take(64) {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim();
                if matches!(
                    name.to_ascii_lowercase().as_str(),
                    "server" | "content-type" | "content-length" | "location" | "set-cookie"
                ) {
                    node.fields
                        .push(fld(name, one_line(value).chars().take(300).collect::<String>()));
                }
            }
        }
        let summary = format!(
            "HTTP {} {}",
            code,
            if reason.is_empty() { "(no reason)" } else { reason }
        );
        return Some((one_line(&summary), node));
    }

    let method = first.split(' ').next().unwrap_or("");
    if !is_http_method(method) {
        return None;
    }
    let mut parts = first.splitn(3, ' ');
    let _method = parts.next().unwrap_or("");
    let uri = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("").trim();
    node.fields.push(fld("Type", "request"));
    node.fields.push(fld("Request Line", first.trim()));
    node.fields.push(fld("Method", method));
    node.fields.push(fld("URI", uri));
    node.fields.push(fld("Version", version));
    let mut host = String::new();
    for line in lines.take(64) {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let lname = name.trim().to_ascii_lowercase();
            let lvalue = one_line(value);
            match lname.as_str() {
                "host" => {
                    host = lvalue.clone();
                    node.fields.push(fld("Host", host.clone()));
                }
                "user-agent" | "accept" | "content-type" | "content-length" | "referer" => {
                    node.fields
                        .push(fld(name.trim(), lvalue.chars().take(300).collect::<String>()));
                }
                _ => {}
            }
        }
    }
    let summary = if host.is_empty() {
        format!("HTTP {method} {uri}")
    } else {
        format!("HTTP {method} {uri} Host: {host}")
    };
    Some((one_line(&summary), node))
}

// -------------------------------------------------------------------- TLS

fn decode_tls(payload: &[u8]) -> Option<(String, LayerNode)> {
    if payload.len() < 5 {
        return None;
    }
    let content_type = payload[0];
    if !(20..=24).contains(&content_type) {
        return None;
    }
    if payload[1] != 3 {
        return None;
    }
    let record_version = be16(payload, 1)?;
    let record_len = be16(payload, 3)? as usize;
    let mut node = layer("tls", "Transport Layer Security");
    node.fields
        .push(fld("Record Content Type", format!("{} ({content_type})", tls_content_type(content_type))));
    node.fields
        .push(fld("Record Version", tls_version(record_version)));
    node.fields.push(fld("Record Length", format!("{record_len} bytes")));

    let mut summary = format!(
        "TLS {} record ({record_len} bytes)",
        tls_content_type(content_type)
    );

    if content_type == 22 && payload.len() >= 9 {
        let hs_type = payload[5];
        let hs_len = ((payload[6] as usize) << 16) | ((payload[7] as usize) << 8) | payload[8] as usize;
        node.fields
            .push(fld("Handshake Type", format!("{} ({hs_type})", tls_handshake_type(hs_type))));
        node.fields.push(fld("Handshake Length", format!("{hs_len} bytes")));
        summary = format!("TLS {}", tls_handshake_type(hs_type));
        if hs_type == 1 {
            if let Some(body) = payload.get(9..9 + hs_len.min(payload.len().saturating_sub(9))) {
                if let Some(sni) = tls_client_hello_sni(body) {
                    node.fields.push(fld("Server Name (SNI)", sni.clone()));
                    summary = format!("TLS ClientHello SNI {sni}");
                }
            }
        }
    }
    Some((one_line(&summary), node))
}

/// Extract the SNI host name from a ClientHello body (bounds-checked at every step).
fn tls_client_hello_sni(body: &[u8]) -> Option<String> {
    let mut pos = 0usize;
    // legacy_version (2) + random (32)
    pos = pos.checked_add(34)?;
    // session id
    let sid_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1 + sid_len)?;
    // cipher suites
    let cipher_len = be16(body, pos)? as usize;
    pos = pos.checked_add(2 + cipher_len)?;
    // compression methods
    let comp_len = *body.get(pos)? as usize;
    pos = pos.checked_add(1 + comp_len)?;
    // extensions
    let ext_total = be16(body, pos)? as usize;
    pos = pos.checked_add(2)?;
    let ext_end = pos.checked_add(ext_total)?.min(body.len());
    while pos + 4 <= ext_end {
        let ext_type = be16(body, pos)?;
        let ext_len = be16(body, pos + 2)? as usize;
        pos = pos.checked_add(4)?;
        let ext_data = body.get(pos..pos.checked_add(ext_len)?.min(body.len()))?;
        pos = pos.checked_add(ext_len)?;
        if ext_type == 0 {
            // server_name list
            let list_len = be16(ext_data, 0)? as usize;
            let mut p = 2usize;
            let end = (2 + list_len).min(ext_data.len());
            while p + 3 <= end {
                let name_type = ext_data[p];
                let name_len = be16(ext_data, p + 1)? as usize;
                let start = p + 3;
                let name = ext_data.get(start..start.checked_add(name_len)?.min(ext_data.len()))?;
                if name_type == 0 {
                    return Some(String::from_utf8_lossy(name).to_string());
                }
                p = start + name_len;
            }
            return None;
        }
    }
    None
}

// ------------------------------------------------------------- name tables

fn ethertype_name(etype: u16) -> &'static str {
    match etype {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86dd => "IPv6",
        0x8100 => "802.1Q VLAN",
        0x88a8 => "802.1ad QinQ",
        0x9100 => "802.1Q QinQ",
        _ => "unknown",
    }
}

fn ip_proto_name(proto: u8) -> &'static str {
    match proto {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        41 => "IPv6",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        89 => "OSPF",
        132 => "SCTP",
        _ => "IP",
    }
}

fn ipv6_ext_name(next: u8) -> &'static str {
    match next {
        0 => "Hop-by-Hop Options",
        43 => "Routing",
        60 => "Destination Options",
        _ => "Extension",
    }
}

fn icmp_type_name(t: u8, v6: bool) -> &'static str {
    if v6 {
        match t {
            1 => "Destination Unreachable",
            2 => "Packet Too Big",
            3 => "Time Exceeded",
            128 => "Echo Request",
            129 => "Echo Reply",
            133 => "Router Solicitation",
            134 => "Router Advertisement",
            135 => "Neighbor Solicitation",
            136 => "Neighbor Advertisement",
            _ => "ICMPv6",
        }
    } else {
        match t {
            0 => "Echo Reply",
            3 => "Destination Unreachable",
            5 => "Redirect",
            8 => "Echo Request",
            11 => "Time Exceeded",
            _ => "ICMP",
        }
    }
}

fn dns_type_name(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        41 => "OPT",
        255 => "ANY",
        _ => "TYPE",
    }
}

fn rcode_name(rcode: u16) -> &'static str {
    match rcode {
        0 => "NoError",
        1 => "FormErr",
        2 => "ServFail",
        3 => "NXDomain",
        4 => "NotImp",
        5 => "Refused",
        _ => "Unknown",
    }
}

fn dns_class_name(class: u16) -> &'static str {
    match class {
        1 => "IN",
        3 => "CH",
        4 => "HS",
        255 => "ANY",
        _ => "CLASS",
    }
}

fn tls_content_type(t: u8) -> &'static str {
    match t {
        20 => "ChangeCipherSpec",
        21 => "Alert",
        22 => "Handshake",
        23 => "ApplicationData",
        24 => "Heartbeat",
        _ => "Unknown",
    }
}

fn tls_version(v: u16) -> &'static str {
    match v {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "unknown",
    }
}

fn tls_handshake_type(t: u8) -> &'static str {
    match t {
        0 => "HelloRequest",
        1 => "ClientHello",
        2 => "ServerHello",
        4 => "NewSessionTicket",
        8 => "EncryptedExtensions",
        11 => "Certificate",
        12 => "ServerKeyExchange",
        13 => "CertificateRequest",
        14 => "ServerHelloDone",
        15 => "CertificateVerify",
        16 => "ClientKeyExchange",
        20 => "Finished",
        _ => "Handshake",
    }
}
