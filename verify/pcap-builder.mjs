/**
 * pcap-builder.mjs — 仅测试/样例生成使用：手工构造 Ethernet II / IPv4 / TCP
 * classic PCAP，可注入分片、乱序、重传、回绕、坏校验和等情形。
 */
import { ipv4HeaderChecksum } from '../public/pcap-engine.mjs';

export function ip(s) { return s.split('.').map(Number); }

export function encodeCommands(texts) {
  const parts = [];
  for (const t of texts) {
    const p = new TextEncoder().encode(t);
    const h = new Uint8Array(2);
    h[0] = (p.length >> 8) & 0xff;
    h[1] = p.length & 0xff;
    parts.push(h, p);
  }
  return concat(parts);
}

export function concat(arrs) {
  const n = arrs.reduce((a, b) => a + b.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

export function tcpPacket({
  sport = 40123, dport = 5010, seq = 0, ack = 0, flags = 0x10,
  payload = new Uint8Array(0),
}) {
  const hdr = new Uint8Array(20);
  const dv = new DataView(hdr.buffer);
  dv.setUint16(0, sport);
  dv.setUint16(2, dport);
  dv.setUint32(4, seq >>> 0);
  dv.setUint32(8, ack >>> 0);
  hdr[12] = 5 << 4;
  hdr[13] = flags;
  dv.setUint16(14, 64240); // window
  // checksum/urgent 保持 0（本题不要求 TCP 校验和仲裁）
  return concat([hdr, payload]);
}

export function ipv4Frame({
  src = '10.0.0.10', dst = '10.0.0.20', id = 0,
  flagsFrag = 0, proto = 6, ttl = 64, payload,
  badChecksum = false,
}) {
  const ihl = 20;
  const total = ihl + payload.length;
  const ipHdr = new Uint8Array(ihl);
  const dv = new DataView(ipHdr.buffer);
  ipHdr[0] = 0x45;
  ipHdr[1] = 0;
  dv.setUint16(2, total);
  dv.setUint16(4, id);
  dv.setUint16(6, flagsFrag);
  ipHdr[8] = ttl;
  ipHdr[9] = proto;
  const sa = ip(src), da = ip(dst);
  ipHdr.set(sa, 12);
  ipHdr.set(da, 16);
  let cksum = ipv4HeaderChecksum(ipHdr, ihl);
  if (badChecksum) cksum = (cksum + 1) & 0xffff; // 确定不同于正确校验和
  dv.setUint16(10, cksum);
  const eth = new Uint8Array(14);
  eth[12] = 0x08; eth[13] =0x00; // Ethernet II IPv4
  return concat([eth, ipHdr, payload]);
}

/** 把一个完整 TCP 数据报按 8 字节 IP 载荷边界拆成分片帧。 */
export function fragmentedTcpFrames(fullTcp, { id = 7, mtuPayload = 24, ...rest } = {}) {
  const frames = [];
  let off = 0;
  while (off < fullTcp.length) {
    const chunk = fullTcp.subarray(off, Math.min(off + mtuPayload, fullTcp.length));
    const isLast = off + chunk.length >= fullTcp.length;
    const flagsFrag = (isLast ? 0 : 0x2000) | ((off / 8) & 0x1fff);
    frames.push(ipv4Frame({
      ...rest, id, flagsFrag,
      payload: chunk.slice(),
    }));
    off += chunk.length;
  }
  return frames;
}

export class PcapBuilder {
  constructor() { this.frames = []; }
  add(frame) { this.frames.push(frame); return this.frames.length; } // 返回原始包号
  addAll(frames) { frames.forEach((f) => this.add(f)); }

  build() {
    const gh = new Uint8Array(24);
    const dv = new DataView(gh.buffer);
    dv.setUint32(0, 0xa1b2c3d4, true); // magic, little endian
    dv.setUint16(4, 2, true);
    dv.setUint16(6, 4, true);
    dv.setUint32(16, 65535, true); // snaplen
    dv.setUint32(20, 1, true); // LINKTYPE_ETHERNET
    const recs = this.frames.map((f, i) => {
      const rh = new Uint8Array(16);
      const rdv = new DataView(rh.buffer);
      rdv.setUint32(0, 0, true);
      rdv.setUint32(4, i * 1000, true);
      rdv.setUint32(8, f.length, true);
      rdv.setUint32(12, f.length, true);
      return concat([rh, f]);
    });
    return concat([gh, ...recs]);
  }

  base64() {
    return Buffer.from(this.build()).toString('base64');
  }
}

/* 常用五元和标志 */
export const FLOW = { srcIp: '10.0.0.10', dstIp: '10.0.0.20', srcPort: 40123, dstPort: 5010, protocol: 'TCP' };
export const FL = { SYN: 0x02, ACK: 0x10, FIN: 0x01, PSH: 0x08 };
