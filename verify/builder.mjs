// 测试/样例构造工具：手工搭建 Ethernet II / IPv4(含分片) / TCP 报文与 classic PCAP。
import { computeIpChecksum } from '../lib/checksum.js';

export function ip(s) {
  const p = s.split('.').map(Number);
  return Buffer.from(p);
}

export function eth(payload, ethertype = 0x0800, {
  srcMac = Buffer.from('020000000001', 'hex'),
  dstMac = Buffer.from('020000000002', 'hex'),
} = {}) {
  const f = Buffer.alloc(14 + payload.length);
  dstMac.copy(f, 0);
  srcMac.copy(f, 6);
  f.writeUInt16BE(ethertype, 12);
  payload.copy(f, 14);
  return f;
}

export function arpFrame() {
  const body = Buffer.alloc(28);
  body.writeUInt16BE(1, 0); // ethernet
  body.writeUInt16BE(0x0800, 2);
  body[4] = 4; body[5] = 6;
  body.writeUInt16BE(1, 6); // request
  return eth(body, 0x0806, {
    srcMac: Buffer.from('0200000000aa', 'hex'),
    dstMac: Buffer.from('ffffffffffff', 'hex'),
  });
}

export function tcp({ sport, dport, seq, ack = 0, flags = 0x10, data = Buffer.alloc(0), window = 8192 }) {
  const h = Buffer.alloc(20);
  h.writeUInt16BE(sport, 0);
  h.writeUInt16BE(dport, 2);
  h.writeUInt32BE(seq >>> 0, 4);
  h.writeUInt32BE(ack >>> 0, 8);
  h[12] = 0x50; // data offset 5 (20 字节)
  h[13] = flags;
  h.writeUInt16BE(window, 14);
  return Buffer.concat([h, data]);
}

// 单个 IPv4 分片（含 Ethernet II）。part 为本片 IP 载荷，offset 以 8 字节为单位。
export function ipFragment({
  srcIp, dstIp, id = 1, part, offset = 0, mf = false, ttl = 64,
  badChecksum = false, proto = 6,
}) {
  const head = Buffer.alloc(20);
  head[0] = 0x45;
  head[1] = 0;
  head.writeUInt16BE(20 + part.length, 2);
  head.writeUInt16BE(id, 4);
  head.writeUInt16BE((mf ? 0x2000 : 0) | (offset & 0x1fff), 6);
  head[8] = ttl;
  head[9] = proto;
  srcIp.copy(head, 12);
  dstIp.copy(head, 16);
  const cksum = badChecksum ? 0xffff : computeIpChecksum(head);
  head.writeUInt16BE(cksum, 10);
  return eth(Buffer.concat([head, part]));
}

// 把一个完整 IP 载荷（TCP 段）按 chunkSize（8 的倍数）自动切片
export function fragmentPayload({ srcIp, dstIp, id = 1, payload, chunkSize = 32 }) {
  if (chunkSize % 8 !== 0) throw new Error('chunkSize 必须是 8 的倍数');
  const out = [];
  let off = 0;
  while (off < payload.length) {
    const n = Math.min(chunkSize, payload.length - off);
    const last = off + n === payload.length;
    out.push(ipFragment({
      srcIp, dstIp, id,
      part: payload.subarray(off, off + n),
      offset: off / 8,
      mf: !last,
    }));
    off += n;
  }
  return out;
}

export function ipv4Packet(args) {
  return ipFragment({ ...args, offset: 0, mf: false });
}

export function commandFrame(text) {
  const payload = Buffer.from(text, 'ascii');
  const f = Buffer.alloc(2 + payload.length);
  f.writeUInt16BE(payload.length, 0);
  payload.copy(f, 2);
  return f;
}

// 组装 classic PCAP
export function pcap(frames, { le = true, linktype = 1, origLens = null } = {}) {
  const gh = Buffer.alloc(24);
  gh.writeUInt32LE(0xa1b2c3d4, 0);
  gh.writeUInt16LE(2, 4);
  gh.writeUInt16LE(4, 6);
  gh.writeUInt32LE(0, 16);
  gh.writeUInt32LE(65535, 20); // snaplen
  gh.writeUInt32LE(linktype, 20);
  if (!le) {
    gh.writeUInt32BE(0xa1b2c3d4, 0);
    gh.writeUInt16BE(2, 4);
    gh.writeUInt16BE(4, 6);
    gh.writeUInt32BE(0, 16);
    gh.writeUInt32BE(65535, 20);
    gh.writeUInt32BE(linktype, 20);
  }
  const recs = frames.map((f, i) => {
    const r = Buffer.alloc(16);
    const incl = f.length;
    const orig = origLens && origLens[i] != null ? origLens[i] : incl;
    if (le) {
      r.writeUInt32LE(1, 0); r.writeUInt32LE(i * 1000, 4);
      r.writeUInt32LE(incl, 8); r.writeUInt32LE(orig, 12);
    } else {
      r.writeUInt32BE(1, 0); r.writeUInt32BE(i * 1000, 4);
      r.writeUInt32BE(incl, 8); r.writeUInt32BE(orig, 12);
    }
    // 若 origLen > incl，截断 incl 字节写入
    return Buffer.concat([r, f.subarray(0, Math.min(incl, f.length))]);
  });
  return Buffer.concat([gh, ...recs]);
}

// 造一个方向完整的会话帧序列（同步给出帧，调用方自行打乱/增删）
export function makeSession({
  srcIpS = '10.0.0.10', dstIpS = '10.0.0.20',
  sport = 5100, dport = 8080, isn = 0xfffffff4,
  id = 0x1111, commands = ['PING', 'ARM GRID-07', 'SAFE'],
} = {}) {
  const srcIp = ip(srcIpS);
  const dstIp = ip(dstIpS);
  const stream = Buffer.concat(commands.map(commandFrame));
  const dataStart = (isn + 1) >>> 0;
  const segAt = (rel, len) => {
    const seq = (dataStart + rel) >>> 0;
    return { rel, seq, data: stream.subarray(rel, rel + len) };
  };
  return {
    srcIpS, dstIpS, srcIp, dstIp, sport, dport, isn, id, stream, dataStart,
    syn: () => ipv4Packet({
      srcIp, dstIp, id: id + 1,
      part: tcp({ sport, dport, seq: isn, flags: 0x02 }),
    }),
    synack: () => ipv4Packet({
      srcIp: dstIp, dstIp: srcIp, id: id + 2,
      part: tcp({ sport: dport, dport: sport, seq: 0x0100, ack: (isn + 1) >>> 0, flags: 0x12 }),
    }),
    dataFrags: (rel, len, chunkSize = 32, fragId = id) => {
      const s = segAt(rel, len);
      const seg = tcp({ sport, dport, seq: s.seq, flags: 0x18, data: s.data });
      return fragmentPayload({ srcIp, dstIp, id: fragId, payload: seg, chunkSize });
    },
    data: (rel, len, opts = {}) => {
      const s = segAt(rel, len);
      const data = opts.data ?? s.data;
      const seq = opts.seq ?? s.seq;
      return ipv4Packet({
        srcIp, dstIp, id: opts.id ?? (id + 10 + rel),
        part: tcp({ sport, dport, seq, flags: opts.flags ?? 0x18, data }),
        badChecksum: opts.badChecksum ?? false,
      });
    },
    fin: (rel = stream.length) => ipv4Packet({
      srcIp, dstIp, id: id + 3,
      part: tcp({ sport, dport, seq: (dataStart + rel) >>> 0, flags: 0x11 }),
    }),
    serverFin: () => ipv4Packet({
      srcIp: dstIp, dstIp: srcIp, id: id + 4,
      part: tcp({ sport: dport, dport: sport, seq: 0x0101, flags: 0x11 }),
    }),
    serverData: (bytes) => ipv4Packet({
      srcIp: dstIp, dstIp: srcIp, id: id + 5,
      part: tcp({ sport: dport, dport: sport, seq: 0x0101, data: bytes }),
    }),
  };
}
