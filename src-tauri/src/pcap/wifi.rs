//! IEEE 802.11 (link type 105) and radiotap (link type 127) decoders.
//!
//! Wireless frames are decoded in layers: radiotap -> 802.11 MAC -> LLC/SNAP ->
//! IPv4/IPv6 -> transport -> application. Protected frames are reported honestly:
//! their metadata is decoded, their payload is kept as raw bytes and never guessed.
//! Every read is bounds-checked; hostile or truncated frames cannot panic.

use super::decode::{
    be16, decode_arp, decode_ipv4, decode_ipv6, fld, layer, mac_str, Decoded,
};

const TYPE_MGMT: u8 = 0;
const TYPE_CTRL: u8 = 1;
const TYPE_DATA: u8 = 2;

/// Decode a radiotap capture (link type 127): radiotap header followed by 802.11.
pub(crate) fn decode_radiotap(d: &mut Decoded, data: &[u8]) {
    let header_len = match parse_radiotap(d, data) {
        Some(len) => len,
        None => return,
    };
    if header_len >= data.len() {
        d.protocol = "802.11".to_string();
        d.summary = "Radiotap header without an 802.11 frame (truncated)".to_string();
        return;
    }
    decode_80211(d, &data[header_len..]);
}

/// Decode a bare IEEE 802.11 frame (link type 105).
pub(crate) fn decode_80211(d: &mut Decoded, data: &[u8]) {
    if data.len() < 2 {
        d.protocol = "802.11".to_string();
        d.summary = format!("Truncated 802.11 frame ({} bytes)", data.len());
        let mut wlan = layer("wlan", "IEEE 802.11");
        wlan.fields
            .push(fld("Note", "truncated: frame control needs 2 bytes"));
        d.layers.push(wlan);
        return;
    }
    let fc = u16::from_le_bytes([data[0], data[1]]);
    let version = (fc & 0x0003) as u8;
    let frame_type = ((fc >> 2) & 0x0003) as u8;
    let subtype = ((fc >> 4) & 0x000f) as u8;
    let flags = (fc >> 8) as u8;
    let to_ds = flags & 0x01 != 0;
    let from_ds = flags & 0x02 != 0;
    let more_frag = flags & 0x04 != 0;
    let retry = flags & 0x08 != 0;
    let pwr_mgmt = flags & 0x10 != 0;
    let more_data = flags & 0x20 != 0;
    let protected = flags & 0x40 != 0;
    let order = flags & 0x80 != 0;

    let qt = subtype & 0x08 != 0;
    let header_len = match frame_type {
        TYPE_MGMT => 24usize,
        TYPE_CTRL => control_header_len(subtype),
        TYPE_DATA => {
            let mut len = 24usize;
            if to_ds && from_ds {
                len += 6;
            }
            if qt {
                len += 2;
                if order {
                    len += 4; // HT control
                }
            }
            len
        }
        _ => 0,
    };

    let mut wlan = layer("wlan", "IEEE 802.11");
    wlan.fields.push(fld("Protocol Version", version.to_string()));
    let kind = match frame_type {
        TYPE_MGMT => "management",
        TYPE_CTRL => "control",
        TYPE_DATA => "data",
        _ => "reserved",
    };
    wlan.fields.push(fld("Type", kind));
    wlan.fields.push(fld(
        "Type/Subtype",
        format!("{} ({})", kind, subtype_name(frame_type, subtype)),
    ));
    wlan.fields.push(fld("Subtype", subtype.to_string()));
    let mut flag_names: Vec<&str> = Vec::new();
    if to_ds {
        flag_names.push("ToDS");
    }
    if from_ds {
        flag_names.push("FromDS");
    }
    if more_frag {
        flag_names.push("MoreFragments");
    }
    if retry {
        flag_names.push("Retry");
    }
    if pwr_mgmt {
        flag_names.push("PowerManagement");
    }
    if more_data {
        flag_names.push("MoreData");
    }
    if protected {
        flag_names.push("Protected");
    }
    if order {
        flag_names.push("Order");
    }
    wlan.fields.push(fld(
        "Flags",
        if flag_names.is_empty() {
            "none".to_string()
        } else {
            flag_names.join(", ")
        },
    ));

    // Duration / receiver address are shared by every 802.11 frame.
    if let Some(duration) = be16(data, 2) {
        wlan.fields.push(fld("Duration", format!("{duration} us")));
    }
    let addr1 = mac_str(data, 4);
    let (addr2, addr3, addr4) = match frame_type {
        TYPE_CTRL => (mac_str(data, 10), None, None),
        _ => (mac_str(data, 10), mac_str(data, 16), mac_str(data, 22)),
    };
    if let Some(mac) = addr1.as_ref() {
        wlan.fields.push(fld(
            if frame_type == TYPE_CTRL {
                "Receiver Address"
            } else {
                "Address 1"
            },
            mac.clone(),
        ));
    }
    if let Some(mac) = addr2.as_ref() {
        wlan.fields.push(fld(
            if frame_type == TYPE_CTRL {
                "Transmitter Address"
            } else {
                "Address 2"
            },
            mac.clone(),
        ));
    }
    if let Some(mac) = addr3.as_ref() {
        wlan.fields.push(fld("Address 3", mac.clone()));
    }
    if let Some(mac) = addr4.as_ref() {
        wlan.fields.push(fld("Address 4", mac.clone()));
    }
    if frame_type != TYPE_CTRL {
        if let Some(seq_ctl) = be16(data, 22) {
            wlan.fields
                .push(fld("Sequence Number", (seq_ctl >> 4).to_string()));
            wlan.fields
                .push(fld("Fragment Number", (seq_ctl & 0x000f).to_string()));
        }
    }

    d.frame_kind = if frame_type <= TYPE_DATA {
        Some(kind.to_string())
    } else {
        None
    };
    d.encrypted = protected;
    if frame_type == TYPE_DATA {
        // Map the four address roles according to the DS bits.
        let role = match (to_ds, from_ds) {
            (false, false) => "IBSS",
            (true, false) => "to DS",
            (false, true) => "from DS",
            (true, true) => "WDS",
        };
        wlan.fields.push(fld("Direction", role));
        if qt {
            let qos = be16(data, header_len.saturating_sub(if order { 6 } else { 2 }));
            if let Some(qos) = qos {
                wlan.fields.push(fld("QoS TID", (qos & 0x000f).to_string()));
            }
        }
        // Address roles follow the ToDS / FromDS matrix.
        let (da, sa, bssid) = match (to_ds, from_ds) {
            (false, false) => (addr1.clone(), addr2.clone(), addr3.clone()),
            (true, false) => (addr3.clone(), addr2.clone(), addr1.clone()),
            (false, true) => (addr1.clone(), addr3.clone(), addr2.clone()),
            (true, true) => (addr3.clone(), addr4.clone(), None),
        };
        if let Some(mac) = da.as_ref() {
            wlan.fields.push(fld("Destination Address", mac.clone()));
        }
        if let Some(mac) = sa.as_ref() {
            wlan.fields.push(fld("Source Address", mac.clone()));
        }
        if let Some(mac) = bssid.as_ref() {
            wlan.fields.push(fld("BSSID", mac.clone()));
        }
    }
    d.layers.push(wlan);

    if data.len() < header_len {
        d.protocol = format!("802.11 {}", subtype_name(frame_type, subtype));
        d.summary = format!(
            "Truncated 802.11 {} frame: {} of {} header bytes",
            kind,
            data.len(),
            header_len
        );
        let mut note = layer("wlan_note", "802.11 Note");
        note.fields
            .push(fld("Note", format!("truncated: needs {header_len} header bytes, {} captured", data.len())));
        d.layers.push(note);
        return;
    }

    let payload = &data[header_len..];
    match frame_type {
        TYPE_MGMT => decode_management(d, subtype, payload),
        TYPE_CTRL => decode_control(d, subtype, addr1.as_deref(), addr2.as_deref()),
        TYPE_DATA => decode_data_payload(d, subtype, payload, protected, qt),
        _ => {
            d.protocol = "802.11".to_string();
            d.summary = "802.11 frame with reserved type".to_string();
        }
    }
}

// ----------------------------------------------------------------- radiotap

/// Parse the radiotap header into a layer node. Returns the total header length.
fn parse_radiotap(d: &mut Decoded, data: &[u8]) -> Option<usize> {
    let mut node = layer("radiotap", "Radiotap");
    if data.len() < 8 {
        node.fields.push(fld("Note", "truncated radiotap header"));
        d.layers.push(node);
        d.protocol = "802.11".to_string();
        d.summary = format!("Truncated radiotap header ({} bytes)", data.len());
        return None;
    }
    let version = data[0];
    let pad = data[1];
    let header_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    node.fields.push(fld("Version", version.to_string()));
    node.fields.push(fld("Header Length", format!("{header_len} bytes")));
    if pad != 0 {
        node.fields.push(fld("Pad", pad.to_string()));
    }
    if header_len < 8 || header_len > data.len() {
        node.fields
            .push(fld("Note", format!("invalid radiotap length {header_len} for {} bytes", data.len())));
        d.layers.push(node);
        d.protocol = "802.11".to_string();
        d.summary = "Invalid radiotap header length".to_string();
        return None;
    }

    // Present bitmaps: bit 31 of a word means another word follows.
    let mut words: Vec<u32> = Vec::new();
    let mut off = 4usize;
    while off + 4 <= header_len {
        let word = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        words.push(word);
        off += 4;
        if word & 0x8000_0000 == 0 || words.len() >= 4 {
            break;
        }
    }
    let present_hex: Vec<String> = words.iter().map(|w| format!("0x{w:08x}")).collect();
    node.fields
        .push(fld("Present Flags", present_hex.join(" ")));

    // Walk the fields of the first namespace in bit order, honouring alignment.
    let mut cursor = 4 + words.len() * 4;
    let first = words.first().copied().unwrap_or(0);
    'fields: for bit in 0..31u32 {
        if first & (1u32 << bit) == 0 {
            continue;
        }
        if bit == 27 || bit == 28 || bit >= 29 {
            // Variable length / vendor namespace: stop extracting named fields.
            node.fields.push(fld("Radiotap fields", "extended fields present"));
            break 'fields;
        }
        let Some((size, align)) = radiotap_field_layout(bit) else {
            break 'fields;
        };
        cursor = align_up(cursor, align);
        let Some(bytes) = data.get(cursor..cursor + size) else {
            node.fields.push(fld("Note", "radiotap fields are truncated"));
            break 'fields;
        };
        match bit {
            0 => {
                let mut tsft = [0u8; 8];
                tsft.copy_from_slice(bytes);
                node.fields
                    .push(fld("TSFT", u64::from_le_bytes(tsft).to_string()));
            }
            1 => {
                let f = bytes[0];
                let mut names: Vec<&str> = Vec::new();
                if f & 0x01 != 0 {
                    names.push("CFP");
                }
                if f & 0x02 != 0 {
                    names.push("ShortPreamble");
                }
                if f & 0x04 != 0 {
                    names.push("WEP");
                }
                if f & 0x08 != 0 {
                    names.push("Fragmentation");
                }
                if f & 0x10 != 0 {
                    names.push("FCS");
                }
                if f & 0x20 != 0 {
                    names.push("DataPad");
                }
                if f & 0x40 != 0 {
                    names.push("BadFCS");
                }
                if f & 0x80 != 0 {
                    names.push("ShortGI");
                }
                node.fields.push(fld(
                    "Flags",
                    format!(
                        "0x{f:02x}{}",
                        if names.is_empty() {
                            String::new()
                        } else {
                            format!(" ({})", names.join(", "))
                        }
                    ),
                ));
            }
            2 => {
                let rate = bytes[0];
                node.fields
                    .push(fld("Data Rate", format!("{} Mbps", rate as f64 * 0.5)));
            }
            3 => {
                let freq = u16::from_le_bytes([bytes[0], bytes[1]]);
                let ch_flags = u16::from_le_bytes([bytes[2], bytes[3]]);
                node.fields
                    .push(fld("Channel Frequency", format!("{freq} MHz")));
                node.fields
                    .push(fld("Channel Flags", format!("0x{ch_flags:04x}")));
            }
            5 => {
                let signal = bytes[0] as i8;
                node.fields
                    .push(fld("Antenna Signal", format!("{signal} dBm")));
            }
            6 => {
                let noise = bytes[0] as i8;
                node.fields.push(fld("Antenna Noise", format!("{noise} dBm")));
            }
            11 => {
                node.fields.push(fld("Antenna", bytes[0].to_string()));
            }
            _ => {}
        }
        cursor += size;
    }
    let _ = pad;
    d.layers.push(node);
    Some(header_len)
}

/// Field size and alignment for the fixed radiotap fields, indexed by bit number.
fn radiotap_field_layout(bit: u32) -> Option<(usize, usize)> {
    let layout = match bit {
        0 => (8, 8),  // TSFT
        1 => (1, 1),  // Flags
        2 => (1, 1),  // Rate
        3 => (4, 2),  // Channel
        4 => (2, 2),  // FHSS
        5 => (1, 1),  // dBm antenna signal
        6 => (1, 1),  // dBm antenna noise
        7 => (2, 2),  // lock quality
        8 => (2, 2),  // TX attenuation
        9 => (2, 2),  // dB TX attenuation
        10 => (1, 1), // dBm TX power
        11 => (1, 1), // antenna
        12 => (1, 1), // dB antenna signal
        13 => (1, 1), // dB antenna noise
        14 => (2, 2), // RX flags
        15 => (2, 2), // TX flags
        16 => (1, 1), // RTS retries
        17 => (1, 1), // data retries
        18 => (8, 8), // XChannel
        19 => (3, 1), // MCS
        20 => (8, 8), // A-MPDU status
        21 => (12, 2), // VHT
        22 => (12, 8), // timestamp
        23 => (12, 2), // HE
        24 => (12, 2), // HE-MU
        25 => (1, 1),  // zero-length PSDU
        26 => (4, 4),  // L-SIG
        _ => return None,
    };
    Some(layout)
}

fn align_up(value: usize, align: usize) -> usize {
    if align <= 1 {
        value
    } else {
        value + (align - value % align) % align
    }
}

// --------------------------------------------------------------- management

fn decode_management(d: &mut Decoded, subtype: u8, body: &[u8]) {
    let name = subtype_name(TYPE_MGMT, subtype);
    d.protocol = format!("802.11 {name}");
    d.summary = format!("{name} frame");
    let mut mgmt = layer("wlan_mgmt", "802.11 Management");
    mgmt.fields.push(fld("Subtype", name));

    // Fixed parameters that precede the tagged parameters.
    let fixed_len: usize = match subtype {
        0 => 4,           // association request
        1 => 6,           // association response
        2 => 10,          // reassociation request
        3 => 6,           // reassociation response
        4 => 0,           // probe request
        5 | 8 => 12,      // probe response / beacon
        11 => 6,          // authentication
        10 | 12 => 2,     // disassociation / deauthentication
        13 | 14 => 2,     // action
        _ => 0,
    };

    match subtype {
        5 | 8 => {
            if body.len() >= 12 {
                let interval = be16(body, 8).unwrap_or(0);
                let capability = be16(body, 10).unwrap_or(0);
                mgmt.fields
                    .push(fld("Beacon Interval", format!("{interval} TU")));
                mgmt.fields
                    .push(fld("Capability", format!("0x{capability:04x}")));
            }
        }
        0 | 2 => {
            if body.len() >= 2 {
                let capability = be16(body, 0).unwrap_or(0);
                let listen = be16(body, 2).unwrap_or(0);
                mgmt.fields
                    .push(fld("Capability", format!("0x{capability:04x}")));
                mgmt.fields
                    .push(fld("Listen Interval", format!("{listen} TU")));
            }
        }
        11 => {
            if body.len() >= 6 {
                mgmt.fields.push(fld(
                    "Auth Algorithm",
                    match be16(body, 0).unwrap_or(0) {
                        0 => "Open System (0)".to_string(),
                        1 => "Shared Key (1)".to_string(),
                        3 => "Fast BSS Transition (3)".to_string(),
                        other => format!("{other}"),
                    },
                ));
                mgmt.fields
                    .push(fld("Auth Sequence", be16(body, 2).unwrap_or(0).to_string()));
                mgmt.fields.push(fld(
                    "Status Code",
                    format!("{} ({})", be16(body, 4).unwrap_or(0), status_name(be16(body, 4).unwrap_or(0))),
                ));
            }
        }
        10 | 12 => {
            if body.len() >= 2 {
                let reason = be16(body, 0).unwrap_or(0);
                mgmt.fields.push(fld(
                    "Reason Code",
                    format!("{reason} ({})", reason_name(reason)),
                ));
            }
        }
        13 | 14 => {
            if body.len() >= 2 {
                mgmt.fields
                    .push(fld("Category", body[0].to_string()));
                mgmt.fields.push(fld("Action", body[1].to_string()));
            }
        }
        _ => {}
    }

    // Tagged parameters (SSID, rates, channel, RSN, ...).
    let mut ssid: Option<String> = None;
    let mut channel: Option<u8> = None;
    let mut rates: Vec<String> = Vec::new();
    let mut rsn = false;
    let mut tags_start = fixed_len.min(body.len());
    let mut tag_count = 0;
    while tags_start + 2 <= body.len() && tag_count < 40 {
        tag_count += 1;
        let tag_id = body[tags_start];
        let tag_len = body[tags_start + 1] as usize;
        let value_start = tags_start + 2;
        let Some(value) = body.get(value_start..value_start + tag_len) else {
            mgmt.fields.push(fld("Note", "truncated tagged parameters"));
            break;
        };
        match tag_id {
            0 => {
                let text = String::from_utf8_lossy(value).trim().to_string();
                let label = if text.is_empty() {
                    "<hidden>".to_string()
                } else {
                    text
                };
                mgmt.fields.push(fld("SSID", label.clone()));
                ssid = Some(label);
            }
            1 => {
                for rate in value {
                    rates.push(format!("{} Mbps", *rate as f64 * 0.5));
                }
            }
            3 => {
                if let Some(first) = value.first() {
                    channel = Some(*first);
                    mgmt.fields.push(fld("DS Parameter", format!("channel {first}")));
                }
            }
            48 => {
                rsn = true;
                mgmt.fields.push(fld("RSN", "present (WPA2/WPA3)"));
            }
            221 => {
                mgmt.fields.push(fld("Vendor Specific", format!("{} bytes", tag_len)));
            }
            _ => {}
        }
        tags_start = value_start + tag_len;
    }
    if !rates.is_empty() {
        mgmt.fields.push(fld("Supported Rates", rates.join(", ")));
    }
    let _ = rsn;
    d.layers.push(mgmt);

    d.summary = match (&ssid, channel, subtype) {
        (Some(ssid), Some(ch), 8) => format!("Beacon frame, SSID {ssid}, channel {ch}"),
        (Some(ssid), None, 8) => format!("Beacon frame, SSID {ssid}"),
        (Some(ssid), Some(ch), 5) => {
            format!("Probe Response, SSID {ssid}, channel {ch}")
        }
        (Some(ssid), _, _) => format!("{name}, SSID {ssid}"),
        (None, Some(ch), 8) => format!("Beacon frame, channel {ch}"),
        _ => format!("{name} frame"),
    };
}

// ------------------------------------------------------------------ control

fn control_header_len(subtype: u8) -> usize {
    match subtype {
        11 => 16,        // RTS: RA + TA
        8 | 9 | 10 => 16, // Block Ack Request / Block Ack / PS-Poll
        14 | 15 => 16,   // CF-End / CF-End + CF-Ack: RA + BSSID
        _ => 10,         // CTS, ACK and reserved control frames
    }
}

fn decode_control(d: &mut Decoded, subtype: u8, addr1: Option<&str>, addr2: Option<&str>) {
    let name = subtype_name(TYPE_CTRL, subtype);
    d.protocol = format!("802.11 {name}");
    let ra = addr1.unwrap_or("?");
    d.summary = match subtype {
        11 => format!("RTS, RA {ra}, TA {}", addr2.unwrap_or("?")),
        12 => format!("CTS, RA {ra}"),
        13 => format!("ACK, RA {ra}"),
        8 => format!("Block Ack Request, RA {ra}"),
        9 => format!("Block Ack, RA {ra}"),
        10 => format!("PS-Poll, RA {ra}"),
        14 => format!("CF-End, RA {ra}"),
        15 => format!("CF-End + CF-Ack, RA {ra}"),
        _ => format!("{name}, RA {ra}"),
    };
}

// --------------------------------------------------------------------- data

fn decode_data_payload(d: &mut Decoded, subtype: u8, payload: &[u8], protected: bool, qos: bool) {
    let data_name = subtype_name(TYPE_DATA, subtype);
    d.protocol = format!("802.11 {data_name}");
    d.payload_len = payload.len() as i64;

    if protected {
        d.encrypted = true;
        d.summary = "Protected 802.11 data frame (encrypted; decryption required)".to_string();
        let mut note = layer("wlan_note", "802.11 Note");
        note.fields.push(fld(
            "Note",
            "payload is encrypted (WPA/WPA2/WPA3); no IP addresses or protocols can be decoded without the key",
        ));
        note.fields
            .push(fld("Encrypted Payload", format!("{} bytes", payload.len())));
        d.layers.push(note);
        return;
    }

    let is_qos = qos;
    if payload.is_empty() {
        d.summary = format!("{data_name} frame, no payload");
        if is_qos {
            d.summary = format!("QoS {data_name} frame, no payload");
        }
        return;
    }

    // LLC/SNAP: AA AA 03 <OUI:3> <EtherType:2>
    if payload.len() >= 8 && payload[0] == 0xaa && payload[1] == 0xaa && payload[2] == 0x03 {
        let oui = [payload[3], payload[4], payload[5]];
        let ethertype = u16::from_be_bytes([payload[6], payload[7]]);
        let mut llc = layer("llc", "LLC / SNAP");
        llc.fields.push(fld("DSAP", "0xaa"));
        llc.fields.push(fld("SSAP", "0xaa"));
        llc.fields.push(fld("Control", "0x03"));
        llc.fields.push(fld(
            "OUI",
            format!("{:02x}:{:02x}:{:02x}", oui[0], oui[1], oui[2]),
        ));
        llc.fields
            .push(fld("EtherType", format!("0x{ethertype:04x} ({})", ethertype_name(ethertype))));
        d.layers.push(llc);
        if oui == [0, 0, 0] {
            let inner = &payload[8..];
            match ethertype {
                0x0800 => decode_ipv4(d, inner, 0),
                0x86dd => decode_ipv6(d, inner, 0),
                0x0806 => decode_arp(d, inner, 0),
                other => {
                    d.protocol = "802.11 Data".to_string();
                    d.summary = format!(
                        "802.11 data, EtherType 0x{other:04x} ({}), {} bytes",
                        ethertype_name(other),
                        inner.len()
                    );
                }
            }
            return;
        }
        d.protocol = "802.11 Data".to_string();
        d.summary = format!(
            "802.11 data, LLC with OUI {:02x}:{:02x}:{:02x}",
            oui[0], oui[1], oui[2]
        );
        return;
    }

    if payload.starts_with(&[0xaa, 0xaa, 0x03]) {
        d.protocol = "802.11 Data".to_string();
        d.summary = "802.11 data, truncated LLC/SNAP header".to_string();
        let mut note = layer("wlan_note", "802.11 Note");
        note.fields
            .push(fld("Note", "LLC/SNAP header is truncated; payload not decoded"));
        d.layers.push(note);
        return;
    }

    // No SNAP header: do not guess an upper layer from arbitrary bytes.
    d.protocol = format!("802.11 {data_name}");
    d.summary = format!(
        "802.11 data frame, {} byte payload without LLC/SNAP header",
        payload.len()
    );
}

fn ethertype_name(ethertype: u16) -> &'static str {
    match ethertype {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86dd => "IPv6",
        0x8100 => "802.1Q",
        _ => "unknown",
    }
}

// ------------------------------------------------------------- name tables

fn subtype_name(frame_type: u8, subtype: u8) -> &'static str {
    match frame_type {
        TYPE_MGMT => match subtype {
            0 => "Association Request",
            1 => "Association Response",
            2 => "Reassociation Request",
            3 => "Reassociation Response",
            4 => "Probe Request",
            5 => "Probe Response",
            6 => "Timing Advertisement",
            8 => "Beacon",
            9 => "ATIM",
            10 => "Disassociation",
            11 => "Authentication",
            12 => "Deauthentication",
            13 => "Action",
            14 => "Action No Ack",
            _ => "Management",
        },
        TYPE_CTRL => match subtype {
            2 => "Trigger",
            3 => "TACK",
            4 => "Beamforming Report Poll",
            5 => "VHT NDP Announcement",
            7 => "Control Wrapper",
            8 => "Block Ack Request",
            9 => "Block Ack",
            10 => "PS-Poll",
            11 => "RTS",
            12 => "CTS",
            13 => "ACK",
            14 => "CF-End",
            15 => "CF-End + CF-Ack",
            _ => "Control",
        },
        TYPE_DATA => match subtype {
            0 => "Data",
            1 => "Data + CF-ACK",
            2 => "Data + CF-Poll",
            3 => "Data + CF-Ack + CF-Poll",
            4 => "Null",
            5 => "CF-ACK",
            6 => "CF-Poll",
            7 => "CF-Ack + CF-Poll",
            8 => "QoS Data",
            9 => "QoS Data + CF-ACK",
            10 => "QoS Data + CF-Poll",
            11 => "QoS Data + CF-Ack + CF-Poll",
            12 => "QoS Null",
            14 => "QoS CF-Poll",
            15 => "QoS CF-Ack + CF-Poll",
            _ => "Data",
        },
        _ => "Reserved",
    }
}

fn reason_name(code: u16) -> &'static str {
    match code {
        1 => "Unspecified",
        2 => "Authentication no longer valid",
        3 => "Deauthenticated: station leaving",
        4 => "Disassociated: inactivity",
        5 => "Disassociated: AP unable to handle stations",
        6 => "Class 2 frame from non-authenticated station",
        7 => "Class 3 frame from non-associated station",
        8 => "Disassociated: station leaving",
        _ => "Reason",
    }
}

fn status_name(code: u16) -> &'static str {
    match code {
        0 => "Successful",
        1 => "Unspecified failure",
        10 => "Cannot support capabilities",
        11 => "Reassociation denied",
        12 => "Association denied (reason outside scope)",
        _ => "Status",
    }
}
