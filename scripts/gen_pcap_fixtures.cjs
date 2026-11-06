#!/usr/bin/env node
// Deterministic PCAP / PCAPNG fixture generator for the NULLPLINTH pcap tests.
//
// Every byte is written here on purpose so the tests can assert exact values.
// Run: node scripts/gen_pcap_fixtures.cjs
// Output: fixtures/pcap/{basic.pcap,basic.pcapng,truncated.pcap,unsupported_linktype.pcap,malformed.pcap,vlan_ipv6.pcap}

const fs = require("fs");
const path = require("path");

const OUT = path.join(__dirname, "..", "fixtures", "pcap");
fs.mkdirSync(OUT, { recursive: true });

const BASE_SEC = 1700000000; // 2023-11-14T22:13:20Z
const BASE_US = BASE_SEC * 1000000;

// ---------------------------------------------------------------- byte helpers
const u8 = (n) => Buffer.from([n & 0xff]);
const u16be = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n & 0xffff); return b; };
const u16le = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n & 0xffff); return b; };
const u32be = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };
const u32le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const u64le = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt.asUintN(64, BigInt(v))); return b; };

function mac(s) {
  const parts = s.split(":").map((h) => parseInt(h, 16));
  if (parts.length !== 6) throw new Error("bad mac " + s);
  return Buffer.from(parts);
}

function ipv4(s) {
  const parts = s.split(".").map((n) => parseInt(n, 10));
  if (parts.length !== 4) throw new Error("bad ipv4 " + s);
  return Buffer.from(parts);
}

function ipv6(s) {
  const [head, tail] = s.split("::");
  let groups;
  if (tail === undefined) {
    groups = head.split(":");
  } else {
    const h = head ? head.split(":") : [];
    const t = tail ? tail.split(":") : [];
    groups = [...h, ...new Array(8 - h.length - t.length).fill("0"), ...t];
  }
  if (groups.length !== 8) throw new Error("bad ipv6 " + s);
  const b = Buffer.alloc(16);
  groups.forEach((g, i) => b.writeUInt16BE(parseInt(g, 16), i * 2));
  return b;
}

function ipv4Checksum(hdr) {
  let sum = 0;
  for (let i = 0; i < hdr.length; i += 2) sum += (hdr[i] << 8) + (i + 1 < hdr.length ? hdr[i + 1] : 0);
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}

// ---------------------------------------------------------------- frame builders
function eth(dstMac, srcMac, ethertype, payload, vlanId) {
  const parts = [mac(dstMac), mac(srcMac)];
  if (vlanId !== undefined) {
    parts.push(u16be(0x8100), u16be(vlanId & 0x0fff), u16be(ethertype));
  } else {
    parts.push(u16be(ethertype));
  }
  parts.push(payload);
  return Buffer.concat(parts);
}

function ipv4Packet({ src, dst, proto, payload, ttl = 64, id = 1, flagsFrag = 0x4000 }) {
  const totalLen = 20 + payload.length;
  const hdr = Buffer.alloc(20);
  hdr[0] = 0x45;
  hdr[1] = 0x00;
  hdr.writeUInt16BE(totalLen, 2);
  hdr.writeUInt16BE(id, 4);
  hdr.writeUInt16BE(flagsFrag, 6);
  hdr[8] = ttl;
  hdr[9] = proto;
  hdr.writeUInt16BE(0, 10);
  ipv4(src).copy(hdr, 12);
  ipv4(dst).copy(hdr, 16);
  hdr.writeUInt16BE(ipv4Checksum(hdr), 10);
  return Buffer.concat([hdr, payload]);
}

function ipv6Packet({ src, dst, next, payload, hop = 64 }) {
  const hdr = Buffer.alloc(40);
  hdr[0] = 0x60;
  hdr.writeUInt16BE(payload.length, 4);
  hdr[6] = next;
  hdr[7] = hop;
  ipv6(src).copy(hdr, 8);
  ipv6(dst).copy(hdr, 24);
  return Buffer.concat([hdr, payload]);
}

function tcp({ sport, dport, seq = 0, ack = 0, flags, window = 64240, payload = Buffer.alloc(0) }) {
  const hdr = Buffer.alloc(20);
  hdr.writeUInt16BE(sport, 0);
  hdr.writeUInt16BE(dport, 2);
  hdr.writeUInt32BE(seq >>> 0, 4);
  hdr.writeUInt32BE(ack >>> 0, 8);
  hdr[12] = 5 << 4; // data offset 5, no options
  hdr[13] = flags;
  hdr.writeUInt16BE(window, 14);
  hdr.writeUInt16BE(0, 16); // checksum (not validated by the decoder)
  hdr.writeUInt16BE(0, 18);
  return Buffer.concat([hdr, payload]);
}

function udp({ sport, dport, payload }) {
  const hdr = Buffer.alloc(8);
  hdr.writeUInt16BE(sport, 0);
  hdr.writeUInt16BE(dport, 2);
  hdr.writeUInt16BE(8 + payload.length, 4);
  hdr.writeUInt16BE(0, 6); // checksum unused for IPv4
  return Buffer.concat([hdr, payload]);
}

function dnsName(name) {
  const parts = [];
  // split on '.' but stop at an escaped dot
  const labels = [];
  let cur = "";
  for (const ch of name) {
    if (ch === "\\") { cur += ch; continue; }
    if (ch === ".") { labels.push(cur); cur = ""; } else cur += ch;
  }
  if (cur.length) labels.push(cur);
  for (const label of labels) {
    const buf = Buffer.from(label, "utf8");
    if (buf.length > 63) throw new Error("dns label too long");
    parts.push(u8(buf.length), buf);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function dnsMessage({ id, flags, qname, qtype = 1, qclass = 1, answers = [] }) {
  const parts = [u16be(id), u16be(flags), u16be(1), u16be(answers.length), u16be(0), u16be(0)];
  parts.push(dnsName(qname), u16be(qtype), u16be(qclass));
  for (const a of answers) {
    parts.push(Buffer.from([0xc0, 0x0c])); // pointer to the question name
    parts.push(u16be(a.type), u16be(a.class), u32be(a.ttl), u16be(a.rdata.length), a.rdata);
  }
  return Buffer.concat(parts);
}

function tlsClientHello(host) {
  const random = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) random[i] = i + 1;
  const hostBuf = Buffer.from(host, "utf8");
  // SNI extension: type 0, data = server_name_list
  const nameEntry = Buffer.concat([u8(0), u16be(hostBuf.length), hostBuf]);
  const nameList = Buffer.concat([u16be(nameEntry.length), nameEntry]);
  const sniExt = Buffer.concat([u16be(0), u16be(nameList.length), nameList]);
  const extensions = sniExt;
  const body = Buffer.concat([
    u16be(0x0303),
    random,
    u8(0), // session id length
    u16be(2), u16be(0x002f), // cipher suites
    u8(1), Buffer.from([0]), // compression methods
    u16be(extensions.length),
    extensions,
  ]);
  const hs = Buffer.concat([u8(0x01), u8((body.length >> 16) & 0xff), u8((body.length >> 8) & 0xff), u8(body.length & 0xff), body]);
  return Buffer.concat([u8(0x16), u16be(0x0301), u16be(hs.length), hs]);
}

function icmpEcho({ type = 8, code = 0, id = 0x4242, seq = 1, payload = Buffer.from("nullplinth") }) {
  const hdr = Buffer.alloc(8);
  hdr[0] = type; hdr[1] = code;
  hdr.writeUInt16BE(0, 2); // checksum, unused by the decoder
  hdr.writeUInt16BE(id, 4);
  hdr.writeUInt16BE(seq, 6);
  return Buffer.concat([hdr, payload]);
}

// ---------------------------------------------------------------- capture writers
function writePcap(file, linktype, packets) {
  const global = Buffer.alloc(24);
  global.writeUInt32LE(0xa1b2c3d4, 0); // magic, microsecond, little endian
  global.writeUInt16LE(2, 4);
  global.writeUInt16LE(4, 6);
  global.writeInt32LE(0, 8);
  global.writeUInt32LE(0, 12);
  global.writeUInt32LE(262144, 16);
  global.writeUInt32LE(linktype >>> 0, 20);
  const parts = [global];
  for (const p of packets) {
    const caplen = p.caplen === undefined ? p.data.length : p.caplen;
    const origlen = p.origlen === undefined ? p.data.length : p.origlen;
    const hdr = Buffer.alloc(16);
    hdr.writeUInt32LE(Math.floor(p.ts / 1000000), 0);
    hdr.writeUInt32LE(p.ts % 1000000, 4);
    hdr.writeUInt32LE(caplen, 8);
    hdr.writeUInt32LE(origlen, 12);
    parts.push(hdr, p.data.subarray(0, caplen));
  }
  fs.writeFileSync(file, Buffer.concat(parts));
  return fs.statSync(file).size;
}

function ngBlock(type, body) {
  const total = 12 + body.length;
  const b = Buffer.alloc(total);
  b.writeUInt32LE(type >>> 0, 0);
  b.writeUInt32LE(total, 4);
  body.copy(b, 8);
  b.writeUInt32LE(total, total - 4);
  return b;
}

function writePcapng(file, linktype, packets) {
  const blocks = [];
  // Section Header Block
  blocks.push(ngBlock(0x0a0d0d0a, Buffer.concat([u32le(0x1a2b3c4d), u16le(1), u16le(0), u64le(-1)])));
  // Interface Description Block: linktype, reserved, snaplen, if_tsresol=6 (microseconds)
  const tsresol = Buffer.concat([u16le(9), u16le(1), Buffer.from([6, 0, 0, 0])]);
  const optEnd = Buffer.alloc(4);
  blocks.push(ngBlock(0x00000001, Buffer.concat([u16le(linktype), u16le(0), u32le(262144), tsresol, optEnd])));
  for (const p of packets) {
    const data = p.data;
    const caplen = data.length;
    const origlen = p.origlen === undefined ? caplen : p.origlen;
    const pad = (4 - (caplen % 4)) % 4;
    const padded = Buffer.concat([data, Buffer.alloc(pad)]);
    const us = BigInt(p.ts);
    const high = Number(us >> 32n);
    const low = Number(us & 0xffffffffn);
    const body = Buffer.concat([
      u32le(0), // interface id
      u32le(high),
      u32le(low),
      u32le(caplen),
      u32le(origlen),
      padded,
    ]);
    blocks.push(ngBlock(0x00000006, body)); // Enhanced Packet Block
  }
  fs.writeFileSync(file, Buffer.concat(blocks));
  return fs.statSync(file).size;
}

// ---------------------------------------------------------------- fixtures
const CLIENT_MAC = "02:00:00:00:00:05";
const SERVER_MAC = "02:00:00:00:00:77";
const CLIENT_IP = "10.0.0.5";
const SERVER_IP = "93.184.216.34";
const DNS_IP = "8.8.8.8";

const httpPayload = Buffer.from(
  "GET /index.html HTTP/1.1\r\n" +
    "Host: example.com\r\n" +
    "User-Agent: nullplinth-test/1.0\r\n" +
    "Accept: */*\r\n" +
    "\r\n",
  "utf8"
);

function basicPackets() {
  const pkts = [];
  // 1: TCP SYN client -> server:80
  pkts.push({ ts: BASE_US + 0, data: eth(SERVER_MAC, CLIENT_MAC, 0x0800, ipv4Packet({ src: CLIENT_IP, dst: SERVER_IP, proto: 6, id: 0x0001, payload: tcp({ sport: 54321, dport: 80, seq: 1000, ack: 0, flags: 0x02 }) })) });
  // 2: TCP SYN, ACK server:80 -> client
  pkts.push({ ts: BASE_US + 1000, data: eth(CLIENT_MAC, SERVER_MAC, 0x0800, ipv4Packet({ src: SERVER_IP, dst: CLIENT_IP, proto: 6, id: 0x0002, payload: tcp({ sport: 80, dport: 54321, seq: 5000, ack: 1001, flags: 0x12, window: 65535 }) })) });
  // 3: DNS query A example.com
  pkts.push({ ts: BASE_US + 2000, data: eth(SERVER_MAC, CLIENT_MAC, 0x0800, ipv4Packet({ src: CLIENT_IP, dst: DNS_IP, proto: 17, id: 0x0003, payload: udp({ sport: 55000, dport: 53, payload: dnsMessage({ id: 0x1234, flags: 0x0100, qname: "example.com", qtype: 1 }) }) })) });
  // 4: DNS response with one A record
  pkts.push({ ts: BASE_US + 3000, data: eth(CLIENT_MAC, SERVER_MAC, 0x0800, ipv4Packet({ src: DNS_IP, dst: CLIENT_IP, proto: 17, id: 0x0004, payload: udp({ sport: 53, dport: 55000, payload: dnsMessage({ id: 0x1234, flags: 0x8180, qname: "example.com", qtype: 1, answers: [{ type: 1, class: 1, ttl: 300, rdata: ipv4(SERVER_IP) }] }) }) })) });
  // 5: HTTP GET
  pkts.push({ ts: BASE_US + 4000, data: eth(SERVER_MAC, CLIENT_MAC, 0x0800, ipv4Packet({ src: CLIENT_IP, dst: SERVER_IP, proto: 6, id: 0x0005, payload: tcp({ sport: 54321, dport: 80, seq: 1001, ack: 5001, flags: 0x18, payload: httpPayload }) })) });
  // 6: TCP ACK back
  pkts.push({ ts: BASE_US + 5000, data: eth(CLIENT_MAC, SERVER_MAC, 0x0800, ipv4Packet({ src: SERVER_IP, dst: CLIENT_IP, proto: 6, id: 0x0006, payload: tcp({ sport: 80, dport: 54321, seq: 5001, ack: 1001 + httpPayload.length, flags: 0x10, window: 65535 }) })) });
  // 7: TLS ClientHello with SNI example.com
  pkts.push({ ts: BASE_US + 6000, data: eth(SERVER_MAC, CLIENT_MAC, 0x0800, ipv4Packet({ src: CLIENT_IP, dst: SERVER_IP, proto: 6, id: 0x0007, payload: tcp({ sport: 54322, dport: 443, seq: 2000, ack: 0, flags: 0x18, payload: tlsClientHello("example.com") }) })) });
  return pkts;
}

const basic = basicPackets();

const written = [];
written.push(["basic.pcap", writePcap(path.join(OUT, "basic.pcap"), 1, basic)]);
written.push(["basic.pcapng", writePcapng(path.join(OUT, "basic.pcapng"), 1, basic)]);

// truncated.pcap: two frames where origlen > caplen.
{
  const fullTcp = eth(SERVER_MAC, CLIENT_MAC, 0x0800, ipv4Packet({
    src: CLIENT_IP, dst: SERVER_IP, proto: 6, id: 0x0101,
    payload: tcp({ sport: 40001, dport: 80, seq: 10, ack: 1, flags: 0x18, payload: Buffer.alloc(100, 0x41) }),
  }));
  const pkts = [
    // TCP header itself truncated: only 40 of 154 captured bytes.
    { ts: BASE_US + 10000, data: fullTcp, caplen: 40, origlen: fullTcp.length },
    // Payload truncated: full 54 byte headers captured, 20 of 100 payload bytes.
    { ts: BASE_US + 11000, data: fullTcp, caplen: 74, origlen: fullTcp.length },
  ];
  written.push(["truncated.pcap", writePcap(path.join(OUT, "truncated.pcap"), 1, pkts)]);
}

// unsupported_linktype.pcap: LINKTYPE_IEEE802_11 (105) is not decoded by us.
{
  const raw = Buffer.alloc(24, 0x08);
  const pkts = [{ ts: BASE_US + 20000, data: raw }];
  written.push(["unsupported_linktype.pcap", writePcap(path.join(OUT, "unsupported_linktype.pcap"), 105, pkts)]);
}

// malformed.pcap: not a capture file at all.
{
  const junk = Buffer.from("this is definitely not a pcap file, no magic here.", "utf8");
  fs.writeFileSync(path.join(OUT, "malformed.pcap"), junk);
  written.push(["malformed.pcap", junk.length]);
}

// vlan_ipv6.pcap: VLAN tagged IPv4/UDP, plain IPv6/TCP, IPv4/ICMP echo.
{
  const pkts = [
    { ts: BASE_US + 30000, data: eth(SERVER_MAC, CLIENT_MAC, 0x0800, ipv4Packet({
        src: CLIENT_IP, dst: "10.0.0.99", proto: 17, id: 0x0201,
        payload: udp({ sport: 40000, dport: 5353, payload: Buffer.from("mdns-hello", "utf8") }),
      }), 100) },
    { ts: BASE_US + 31000, data: eth(SERVER_MAC, CLIENT_MAC, 0x86dd, ipv6Packet({
        src: "2001:db8::1", dst: "2001:db8::2", next: 6,
        payload: tcp({ sport: 1234, dport: 443, seq: 7, flags: 0x02 }),
      })) },
    { ts: BASE_US + 32000, data: eth(SERVER_MAC, CLIENT_MAC, 0x0800, ipv4Packet({
        src: CLIENT_IP, dst: DNS_IP, proto: 1, id: 0x0203,
        payload: icmpEcho({ type: 8, code: 0, id: 0x4242, seq: 1 }),
      })) },
  ];
  written.push(["vlan_ipv6.pcap", writePcap(path.join(OUT, "vlan_ipv6.pcap"), 1, pkts)]);
}

for (const [name, size] of written) console.log(name.padEnd(28), size, "bytes");
console.log("wrote fixtures to", OUT);
