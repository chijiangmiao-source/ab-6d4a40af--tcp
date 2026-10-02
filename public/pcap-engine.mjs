/**
 * pcap-engine.mjs
 *
 * 纯 ESM、零依赖，可同时在浏览器与 Node 中运行。
 *
 * 复核流水线：
 *   1. classic PCAP（libpcap，非 pcapng），仅接受 LINKTYPE_ETHERNET；
 *   2. 链路层仅接受 Ethernet II，网络层仅接受 IPv4，传输层仅接受 TCP；
 *   3. 逐包核对 IPv4 头校验和；
 *   4. 按 <源地址, 目的地址, 协议, 标识> 重组 IP 分片，缺片 / 空洞 / 重叠即失败；
 *   5. 按受检 TCP 五元组（带方向）挑段，以 SYN 锚定 ISN，处理乱序段、
 *      32 位序号回绕、内容相同的重传；
 *   6. 缺失起始 SYN、流内空洞、同序号不同字节的冲突一律失败，
 *      并给出首个原始包号、帧偏移与冲突区间，绝不二选一继续；
 *   7. 有效流以 FIN 前的连续字节为准；按两字节大端长度切分 ASCII 指令，
 *      长度越界、非可打印 ASCII、尾随残字节一律失败。
 */

const MAX_PASTE_BYTES = 256 * 1024; // 粘贴 Base64 文本上限 256 KiB

const ETHERTYPE_IPV4 = 0x0800;
const IP_PROTO_TCP = 6;

const TCP_FIN = 0x01;
const TCP_SYN = 0x02;
const TCP_RST = 0x04;

const MOD32 = 0x100000000;

/* ------------------------------------------------------------------ */
/* 错误类型与基础工具                                                   */
/* ------------------------------------------------------------------ */

export class VerifyError extends Error {
  constructor(message, loc = null) {
    super(message);
    this.name = 'VerifyError';
    this.loc = loc; // { packet, offset, range, detail }
  }
}

function fail(message, loc = null) {
  throw new VerifyError(message, loc);
}

function u16be(b, o) {
  return (b[o] << 8) | b[o + 1];
}

function u32be(b, o) {
  return (((b[o] << 8) | b[o + 1]) << 16 | (b[o + 2] << 8) | b[o + 3]) >>> 0;
}

/** IPv4 头校验和：正确时全头按反码求和为 0。 */
export function ipv4HeaderChecksum(bytes, ihlBytes) {
  let sum = 0;
  for (let i = 0; i + 1 < ihlBytes; i += 2) {
    sum += (bytes[i] << 8) | bytes[i + 1];
  }
  if (ihlBytes & 1) sum += bytes[ihlBytes - 1] << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
}

/** 有符号 32 位差：a - b (mod 2^32)，结果落在 [-2^31, 2^31)。 */
export function seqDiff32(a, b) {
  return ((a - b) | 0);
}

function wrap32(abs) {
  return ((abs % MOD32) + MOD32) % MOD32;
}

function hex2(v) {
  return v.toString(16).padStart(2, '0');
}

function parseIpv4Literal(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(s ?? '').trim());
  if (!m) return null;
  const p = [m[1], m[2], m[3], m[4]].map(Number);
  return p.every((x) => x <= 255) ? p : null;
}

/* ------------------------------------------------------------------ */
/* Base64 classic（浏览器 atob / Node >=16 全局 atob）                  */
/* ------------------------------------------------------------------ */

const B64_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function decodeBase64Strict(text) {
  if (typeof text !== 'string') fail('需要 Base64 文本');
  if (text.length > MAX_PASTE_BYTES) {
    fail(`粘贴内容为 ${text.length} 字节，超过 ${MAX_PASTE_BYTES} 字节（256 KiB）上限`);
  }
  const cleaned = text.replace(/\s+/g, '');
  if (cleaned.length === 0) fail('内容为空，请先粘贴 Base64 PCAP');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(cleaned)) {
    fail('不是合法的 Base64 classic 字符集（仅允许 A-Z a-z 0-9 + / 与结尾 =）');
  }
  if (cleaned.length % 4 !== 0) fail('Base64 长度不是 4 的倍数，载荷可能被截断');
  const pad = cleaned.endsWith('==') ? 2 : cleaned.endsWith('=') ? 1 : 0;
  let bin;
  try {
    bin = atob(cleaned);
  } catch (e) {
    fail('Base64 解码失败（填充或字符非法）');
  }
  // 非末位填充位必须为零，否则说明尾部字节被截断/篡改
  if (pad >= 1) {
    const needZeroBits = pad === 2 ? 2 : 4;
    const idx = cleaned.length - 1 - pad;
    const v = B64_ALPHABET.indexOf(cleaned[idx]);
    if (v < 0) fail('Base64 字符非法');
    if (v & ((1 << needZeroBits) - 1)) {
      fail('Base64 末组填充位不为零，PCAP 尾部被截断');
    }
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff;
  return out;
}

/* ------------------------------------------------------------------ */
/* classic PCAP 解析                                                    */
/* ------------------------------------------------------------------ */

/**
 * @returns {{packet:number, frame:Uint8Array, truncated:boolean}[]}
 */
export function parsePcap(buf) {
  if (buf.length < 24) fail('PCAP 全局头不足 24 字节（文件被截断）');
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const magic = dv.getUint32(0, true);
  let little;
  let nano;
  if (magic === 0xa1b2c3d4) { little = true; nano = false; }
  else if (magic === 0xd4c3b2a1) { little = false; nano = false; }
  else if (magic === 0xa1b23c4d) { little = true; nano = true; }
  else if (magic === 0x4d3cb2a1) { little = false; nano = true; }
  else fail('魔数不匹配：不是 classic PCAP（不接受 pcapng 或其他格式）');

  const versionMajor = dv.getUint16(4, little);
  const versionMinor = dv.getUint16(6, little);
  const snaplen = dv.getUint32(16, little);
  const linkType = dv.getUint32(20, little);
  if (versionMajor !== 2 || versionMinor !== 4) {
    fail(`不支持的 PCAP 版本 ${versionMajor}.${versionMinor}（仅接受 2.4）`);
  }
  if (linkType !== 1) {
    fail(`仅接受 Ethernet II 链路层（LINKTYPE_ETHERNET=1，实际 LINKTYPE=${linkType}）`);
  }

  const packets = [];
  let off = 24;
  let idx = 0;
  while (off < buf.length) {
    idx += 1;
    if (buf.length - off < 16) {
      fail('记录头不足 16 字节（PCAP 被截断）',
        { packet: idx, offset: off, detail: 'truncated-record' });
    }
    const inclLen = dv.getUint32(off + 8, little);
    const origLen = dv.getUint32(off + 12, little);
    off += 16;
    if (inclLen > buf.length - off) {
      fail(`第 ${idx} 包记录长度 ${inclLen}，文件仅剩 ${buf.length - off} 字节（截断）`,
        { packet: idx, offset: off, detail: 'truncated-packet' });
    }
    if (inclLen < origLen) {
      fail(`第 ${idx} 包抓包长度 ${inclLen} 小于线上长度 ${origLen}（snaplen 截断，不可复核）`,
        { packet: idx, offset: 0, detail: 'snaplen-truncated' });
    }
    packets.push({
      packet: idx,
      frame: buf.slice(off, off + inclLen),
      truncated: false,
    });
    off += inclLen;
  }
  return packets;
}

/* ------------------------------------------------------------------ */
/* Ethernet II / IPv4                                                   */
/* ------------------------------------------------------------------ */

/** 返回 IPv4 报文的 Uint8Array（帧内偏移 14 起）；非 IPv4 直接失败。 */
function extractEthernetIpv4(frame, packetNo) {
  if (frame.length < 14) {
    fail(`第 ${packetNo} 包 Ethernet 帧头不足 14 字节（截断）`,
      { packet: packetNo, offset: 0, detail: 'truncated-ethernet' });
  }
  const ethertype = u16be(frame, 12);
  if (ethertype <= 1500) {
    fail(`第 ${packetNo} 包 EtherType 位置为长度字段 ${ethertype}（802.3 帧，仅接受 Ethernet II）`,
      { packet: packetNo, offset: 12, detail: 'not-ethernet-ii' });
  }
  if (ethertype !== ETHERTYPE_IPV4) {
    fail(`第 ${packetNo} 包 EtherType=0x${ethertype.toString(16)}，仅接受 IPv4(0x0800)`,
      { packet: packetNo, offset: 12, detail: 'not-ipv4' });
  }
  return { ip: frame.subarray(14), ipFrameBase: 14 };
}

/**
 * 解析并校验单个 IPv4 报文（可能是分片）。
 * @returns IPv4 信息对象；非 TCP 协议直接失败（浏览器仅接受 TCP）。
 */
function parseIpv4(frame, packetNo) {
  const { ip, ipFrameBase } = extractEthernetIpv4(frame, packetNo);
  if (ip.length < 20) {
    fail(`第 ${packetNo} 包 IPv4 头不足 20 字节（截断）`,
      { packet: packetNo, offset: ipFrameBase, detail: 'truncated-ipv4' });
  }
  const version = ip[0] >> 4;
  const ihl = ip[0] & 0x0f;
  if (version !== 4) {
    fail(`第 ${packetNo} 包 IP 版本字段=${version}，仅接受 IPv4`,
      { packet: packetNo, offset: ipFrameBase, detail: 'not-ipv4' });
  }
  if (ihl < 5) {
    fail(`第 ${packetNo} 包 IPv4 IHL=${ihl} 非法（小于 5）`,
      { packet: packetNo, offset: ipFrameBase, detail: 'bad-ihl' });
  }
  const ihlBytes = ihl * 4;
  if (ip.length < ihlBytes) {
    fail(`第 ${packetNo} 包 IPv4 头声明 ${ihlBytes} 字节，帧内被截断`,
      { packet: packetNo, offset: ipFrameBase, detail: 'truncated-ipv4' });
  }
  if (ipv4HeaderChecksum(ip, ihlBytes) !== 0) {
    const got = ((ip[10] << 8) | ip[11]);
    fail(`第 ${packetNo} 包 IPv4 头校验和错误（头部校验字段 0x${got.toString(16)}，按头部重算不为 0）`,
      { packet: packetNo, offset: ipFrameBase + 10, range: 'IPv4 header checksum', detail: 'bad-ipv4-checksum' });
  }
  const totalLen = u16be(ip, 2);
  if (totalLen < ihlBytes) {
    fail(`第 ${packetNo} 包 total-length=${totalLen} 小于 IHL=${ihlBytes}`,
      { packet: packetNo, offset: ipFrameBase + 2, detail: 'bad-total-length' });
  }
  if (totalLen > ip.length) {
    fail(`第 ${packetNo} 包 IPv4 载荷截断（total-length=${totalLen}，帧内 IPv4 仅 ${ip.length} 字节）`,
      { packet: packetNo, offset: ipFrameBase + 2,
        range: `IP 字节 ${ihlBytes}..${totalLen} 缺失`, detail: 'truncated-ipv4-payload' });
  }
  const proto = ip[9];
  if (proto !== IP_PROTO_TCP) {
    fail(`第 ${packetNo} 包 IP 协议号=${proto}，仅接受 TCP(6)`,
      { packet: packetNo, offset: ipFrameBase + 9, detail: 'not-tcp' });
  }
  const ident = u16be(ip, 4);
  const flagsFrag = u16be(ip, 6);
  const moreFrags = (flagsFrag & 0x2000) !== 0;
  const fragOff = (flagsFrag & 0x1fff) * 8;
  return {
    packetNo,
    src: `${ip[12]}.${ip[13]}.${ip[14]}.${ip[15]}`,
    dst: `${ip[16]}.${ip[17]}.${ip[18]}.${ip[19]}`,
    proto,
    ident,
    fragOff,
    moreFrags,
    isFragment: moreFrags || fragOff !== 0,
    ihlBytes,
    payload: ip.subarray(ihlBytes, totalLen),
  };
}

/* ------------------------------------------------------------------ */
/* IP 分片重组                                                          */
/* ------------------------------------------------------------------ */

/**
 * 按 <src,dst,proto,id> 重组。返回完整数据报：
 * { firstPacket, src, dst, proto, data:Uint8Array, ownerAt(dgramOff) }
 * ownerAt 返回该数据报字节对应的原始包号与帧内偏移。
 */
function reassembleFragments(infos) {
  const complete = [];
  const groups = new Map();

  for (const info of infos) {
    if (!info.isFragment) {
      const ihl = info.ihlBytes;
      const pkt = info.packetNo;
      complete.push({
        firstPacket: pkt,
        src: info.src, dst: info.dst, proto: info.proto,
        data: info.payload,
        ownerAt: (off) => ({ packet: pkt, frameOffset: 14 + ihl + off }),
      });
      continue;
    }
    const key = `${info.src}>${info.dst}|${info.proto}|${info.ident}`;
    let g = groups.get(key);
    if (!g) {
      g = { src: info.src, dst: info.dst, proto: info.proto, ident: info.ident,
            firstPacket: info.packetNo, parts: [], totalLen: null };
      groups.set(key, g);
    }
    if (info.packetNo < g.firstPacket) g.firstPacket = info.packetNo;

    const start = info.fragOff;
    const end = start + info.payload.length;
    // 任何分片交叠都拒绝：交叠区无法仲裁，属于“覆盖同一偏移”的冲突
    for (const p of g.parts) {
      if (start < p.end && p.start < end) {
        const lo = Math.max(start, p.start);
        const hi = Math.min(end, p.end);
        fail(`IP 分片交叠冲突：包 ${info.packetNo} 偏移区间 [${start},${end}) 与包 ${p.packet} [${p.start},${p.end}) 重叠，拒绝拼合`,
          { packet: Math.min(info.packetNo, p.packet),
            offset: 14 + 20 + lo,
            range: `IP 数据报偏移 [${lo},${hi})（包 ${p.packet} 与包 ${info.packetNo}）`,
            detail: 'fragment-overlap' });
      }
    }
    g.parts.push({
      start, end, packet: info.packetNo, ihlBytes: info.ihlBytes,
      data: info.payload,
    });
    if (!info.moreFrags) g.totalLen = end;
  }

  for (const g of groups.values()) {
    g.parts.sort((a, b) => a.start - b.start);
    if (g.totalLen === null) {
      let missOff = 0;
      let witness = g.parts.length ? g.parts[g.parts.length - 1].packet : g.firstPacket;
      for (const p of g.parts) {
        if (p.start > missOff) { witness = p.packet; break; }
        missOff = p.end;
      }
      fail(`IP 数据报 ${g.src} > ${g.dst} id=0x${g.ident.toString(16).padStart(4, '0')} 缺少尾片，重组不完整`,
        { packet: witness,
          offset: 14 + 20 + missOff,
          range: `IP 偏移 ${missOff} 起缺片（未见 MF=0 尾片）`,
          detail: 'missing-fragment' });
    }
    let expect = 0;
    for (const p of g.parts) {
      if (p.start !== expect) {
        fail(`IP 数据报 ${g.src} > ${g.dst} id=0x${g.ident.toString(16).padStart(4, '0')} 存在分片空洞`,
          { packet: p.packet,
            offset: 14 + 20 + expect,
            range: `IP 数据报偏移 [${expect},${p.start}) 缺片`,
            detail: 'missing-fragment' });
      }
      expect = p.end;
    }
    if (expect !== g.totalLen) {
      fail(`IP 分片重组长度 ${expect} 与尾片结束位置 ${g.totalLen} 不一致`,
        { packet: g.firstPacket, offset: 14 + 20 + expect, detail: 'fragment-length' });
    }
    const data = new Uint8Array(g.totalLen);
    for (const p of g.parts) data.set(p.data, p.start);
    const parts = g.parts;
    complete.push({
      firstPacket: g.firstPacket,
      src: g.src, dst: g.dst, proto: g.proto,
      data,
      ownerAt(off) {
        // parts 已按 start 排序，线性/二分查找所属分片
        let lo = 0, hi = parts.length - 1;
        while (lo < hi) {
          const mid = (lo + hi + 1) >> 1;
          if (parts[mid].start <= off) lo = mid; else hi = mid - 1;
        }
        const p = parts[lo];
        return { packet: p.packet, frameOffset: 14 + p.ihlBytes + (off - p.start) };
      },
    });
  }

  complete.sort((a, b) => a.firstPacket - b.firstPacket);
  return complete;
}

/* ------------------------------------------------------------------ */
/* TCP 段                                                               */
/* ------------------------------------------------------------------ */

function parseTcpSegment(datagram) {
  const d = datagram.data;
  const firstPacket = datagram.firstPacket;
  if (d.length < 20) {
    fail(`第 ${firstPacket} 包重组后的 IP 数据报不足 TCP 头 20 字节（截断）`,
      { packet: firstPacket,
        offset: datagram.ownerAt(0).frameOffset,
        detail: 'truncated-tcp' });
  }
  const sport = u16be(d, 0);
  const dport = u16be(d, 2);
  const seq = u32be(d, 4);
  const ack = u32be(d, 8);
  const tcpHdrLen = (d[12] >> 4) * 4;
  if (tcpHdrLen < 20) {
    fail(`第 ${firstPacket} 包 TCP 数据偏移=${tcpHdrLen} 非法（小于 20）`,
      { packet: firstPacket, offset: datagram.ownerAt(12).frameOffset, detail: 'bad-tcp-offset' });
  }
  if (tcpHdrLen > d.length) {
    fail(`第 ${firstPacket} 包 TCP 头声明 ${tcpHdrLen} 字节但数据报被截断`,
      { packet: firstPacket, offset: datagram.ownerAt(12).frameOffset, detail: 'truncated-tcp' });
  }
  const flags = d[13];
  const payload = d.subarray(tcpHdrLen);
  const owners = new Array(payload.length);
  for (let i = 0; i < payload.length; i++) {
    owners[i] = datagram.ownerAt(tcpHdrLen + i);
  }
  return {
    firstPacket,
    sport, dport, seq, ack, flags,
    syn: (flags & TCP_SYN) !== 0,
    fin: (flags & TCP_FIN) !== 0,
    rst: (flags & TCP_RST) !== 0,
    payload, owners,
  };
}

/* ------------------------------------------------------------------ */
/* 主入口                                                               */
/* ------------------------------------------------------------------ */

/**
 * 复核一条粘贴的 PCAP。
 * @param {string} base64Text
 * @param {{srcIp:string,dstIp:string,srcPort:(number|string),dstPort:(number|string),protocol?:string}} flow
 * @returns 结构化结果（含每条指令的包号与字节区间）
 */
export function reviewPcap(base64Text, flow) {
  /* 1) 五元组（带方向）*/
  const src = parseIpv4Literal(flow?.srcIp);
  const dst = parseIpv4Literal(flow?.dstIp);
  const sp = Number(flow?.srcPort);
  const dp = Number(flow?.dstPort);
  if (!src) fail('源 IPv4 地址非法（需要 a.b.c.d，各段 0..255）');
  if (!dst) fail('目的 IPv4 地址非法（需要 a.b.c.d，各段 0..255）');
  if (!Number.isInteger(sp) || sp < 0 || sp > 65535) fail('源端口必须是 0..65535 的整数');
  if (!Number.isInteger(dp) || dp < 0 || dp > 65535) fail('目的端口必须是 0..65535 的整数');
  if (String(flow.protocol ?? 'TCP').toUpperCase() !== 'TCP') {
    fail('协议仅接受 TCP');
  }
  const srcS = src.join('.'), dstS = dst.join('.');

  /* 2) Base64 -> PCAP -> 帧 */
  const buf = decodeBase64Strict(base64Text);
  const frames = parsePcap(buf);
  if (frames.length === 0) fail('PCAP 中没有任何数据包');

  /* 3) 逐包解析：仅接受 Ethernet II / IPv4 / TCP（非匹配方向的 TCP 段稍后过滤）*/
  const ipInfos = [];
  for (const f of frames) {
    ipInfos.push(parseIpv4(f.frame, f.packet));
  }

  /* 4) 先校验和（parseIpv4 内已做），再按 src/dst/proto/id 重组分片 */
  const datagrams = reassembleFragments(ipInfos);

  /* 5) 受检五元组方向的 TCP 段；反向（对端）段不属于受检流 */
  const segments = [];
  for (const dg of datagrams) {
    if (dg.src !== srcS || dg.dst !== dstS) continue;
    const seg = parseTcpSegment(dg);
    if (seg.sport !== sp || seg.dport !== dp) continue;
    segments.push(seg);
  }
  if (segments.length === 0) {
    fail('受检五元组方向（源→目的）上没有任何 TCP 段；请确认地址与端口方向（反向流量不计入）',
      null);
  }

  /* 6) SYN 锚定 ISN */
  const synSegs = segments.filter((s) => s.syn);
  if (synSegs.length === 0) {
    fail('受检流缺失起始 SYN，无法确定初始序号（拒绝猜测起点）',
      { packet: segments[0].firstPacket, offset: 14 + 13, detail: 'missing-syn' });
  }
  const isn = synSegs[0].seq;
  for (const s of synSegs) {
    if (s.seq !== isn) {
      fail(`受检流出现不同 ISN 的 SYN：包 ${synSegs[0].firstPacket} ISN=0x${isn.toString(16)} 与包 ${s.firstPacket} ISN=0x${s.seq.toString(16)} 冲突`,
        { packet: Math.min(synSegs[0].firstPacket, s.firstPacket),
          offset: 14 + 4,
          range: `ISN 0x${isn.toString(16)} vs 0x${s.seq.toString(16)}`,
          detail: 'syn-conflict' });
    }
  }

  /**
   * 绝对序号：SYN 占 abs=0；数据首字节 abs=1，允许 >2^32 表示回绕之后。
   * byteOwner: abs -> { byte, packet, frameOffset }
   */
  const byteOwner = new Map();
  let maxEnd = 1; // 已见数据的最大绝对端点
  let finAbs = null;
  let finPacket = null;

  for (const seg of segments) {
    /* 纯 ACK / 窗口通告等零载荷且无 SYN/FIN 的段：不携带任何字节，
       其陈旧序号不参与锚定，直接跳过。 */
    if (seg.payload.length === 0 && !seg.syn && !seg.fin) continue;

    /* 把 32 位 seq 解到最接近当前水位的绝对序号（处理 32 位回绕）*/
    const d = seqDiff32(seg.seq, isn); // SYN => 0
    const pivot = maxEnd - 1;
    const k = Math.round((pivot - d) / MOD32);
    const segAbs = d + k * MOD32;
    if (segAbs < 0 && (seg.payload.length > 0 || seg.fin)) {
      fail(`第 ${seg.firstPacket} 包序号 0x${seg.seq.toString(16)} 早于 SYN 的 ISN，拒绝纳入`,
        { packet: seg.firstPacket, offset: 14 + 4, detail: 'seq-before-syn' });
    }
    // SYN 自身消耗一个序号：其数据（若有）从 SYN 后一个绝对序号开始
    const dataBase = segAbs + (seg.syn ? 1 : 0);

    for (let i = 0; i < seg.payload.length; i++) {
      const abs = dataBase + i;
      const b = seg.payload[i];
      const owner = seg.owners[i];
      const old = byteOwner.get(abs);
      if (old !== undefined) {
        if (old.byte !== b) {
          fail(`TCP 序号 0x${wrap32(isn + abs).toString(16)} 处字节冲突：包 ${old.packet} 为 0x${hex2(old.byte)}，包 ${seg.firstPacket} 为 0x${hex2(b)}；两段覆盖同一序号且字节不同，拒绝择一继续`,
            { packet: Math.min(old.packet, seg.firstPacket),
              offset: old.frameOffset,
              range: `冲突首现序号 0x${wrap32(isn + abs).toString(16)}（绝对 ${abs}）；包 ${old.packet} 帧偏移 ${old.frameOffset} ↔ 包 ${seg.firstPacket} 帧偏移 ${owner.frameOffset}`,
              detail: 'byte-conflict' });
        }
        // 字节相同 => 内容一致的重传，接受，归属保留首见段
        continue;
      }
      byteOwner.set(abs, { byte: b, packet: owner.packet, frameOffset: owner.frameOffset });
    }
    const endAbs = dataBase + seg.payload.length;
    if (endAbs > maxEnd) maxEnd = endAbs;

    if (seg.fin) {
      const f = endAbs; // FIN 消耗数据之后的一个序号（SYN+FIN 时在 SYN 之后）
      if (finAbs !== null && f !== finAbs) {
        fail(`FIN 序号冲突：包 ${finPacket} FIN@0x${wrap32(isn + finAbs).toString(16)} 与包 ${seg.firstPacket} FIN@0x${wrap32(isn + f).toString(16)}`,
          { packet: Math.min(finPacket, seg.firstPacket), offset: 14 + 13, detail: 'fin-conflict' });
      }
      finAbs = f;
      finPacket = seg.firstPacket;
    }
  }

  /* 7) FIN 与连续性 */
  if (finAbs === null) {
    fail('受检流未捕获 FIN，无法确认“FIN 前连续字节”的有效边界（拒绝输出未终结数据）',
      { packet: segments[segments.length - 1].firstPacket,
        offset: 14 + 13, detail: 'missing-fin' });
  }
  let contiguous = 0;
  while (byteOwner.has(contiguous + 1)) contiguous++;
  if (contiguous + 1 < finAbs) {
    const holeAbs = contiguous + 1;
    let witness = segments[segments.length - 1].firstPacket;
    for (const s of segments) {
      if (s.payload.length === 0) continue;
      const d2 = seqDiff32(s.seq, isn);
      const k2 = Math.round(((maxEnd - 1) - d2) / MOD32);
      const a0 = d2 + k2 * MOD32;
      if (a0 > holeAbs || (a0 <= holeAbs && a0 + s.payload.length > holeAbs)) {
        witness = s.firstPacket;
        break;
      }
    }
    fail(`流内空洞：TCP 序号 0x${wrap32(isn + holeAbs).toString(16)} 起缺字节，FIN 要求连续至 0x${wrap32(isn + finAbs).toString(16)}`,
      { packet: witness,
        offset: 14,
        range: `缺失序号 [0x${wrap32(isn + holeAbs).toString(16)}, 0x${wrap32(isn + finAbs).toString(16)}) 中尚未到齐的部分`,
        detail: 'stream-gap' });
  }
  for (const abs of byteOwner.keys()) {
    if (abs >= finAbs) {
      const o = byteOwner.get(abs);
      fail(`FIN（结束序号 0x${wrap32(isn + finAbs).toString(16)}）之后仍出现数据字节，拒绝拼入指令流`,
        { packet: o.packet, offset: o.frameOffset,
          range: `流序号 0x${wrap32(isn + abs).toString(16)}（绝对 ${abs}）`,
          detail: 'data-after-fin' });
    }
  }

  /* 8) 连续字节缓冲与属主 */
  const streamLen = finAbs - 1;
  const stream = new Uint8Array(streamLen);
  const owners = new Array(streamLen);
  for (let a = 1; a < finAbs; a++) {
    const o = byteOwner.get(a);
    stream[a - 1] = o.byte;
    owners[a - 1] = o;
  }

  /* 9) 两字节大端长度前缀 + 可打印 ASCII 载荷 */
  const commands = [];
  let pos = 0;
  while (pos < streamLen) {
    if (streamLen - pos < 2) {
      const o = owners[pos];
      fail(`流尾残留 ${streamLen - pos} 个残字节，不足两字节长度前缀（拒绝残字节）`,
        { packet: o.packet, offset: o.frameOffset,
          range: `流字节 [${pos}, ${streamLen})，TCP seq [0x${wrap32(isn + 1 + pos).toString(16)}, 0x${wrap32(isn + 1 + streamLen).toString(16)})`,
          detail: 'trailing-bytes' });
    }
    const len = (stream[pos] << 8) | stream[pos + 1];
    const payStart = pos + 2;
    const payEnd = payStart + len;
    if (payEnd > streamLen) {
      fail(`流偏移 ${pos} 处长度前缀声明 ${len} 字节，需要到流偏移 ${payEnd}，FIN 前连续流仅 ${streamLen} 字节（指令截断）`,
        { packet: owners[pos].packet, offset: owners[pos].frameOffset,
          range: `流字节 [${pos}, ${payEnd}) 超出流末尾 ${streamLen}；TCP seq 起 0x${wrap32(isn + 1 + pos).toString(16)}`,
          detail: 'length-overrun' });
    }
    for (let i = payStart; i < payEnd; i++) {
      const c = stream[i];
      if (c < 0x20 || c > 0x7e) {
        const o = owners[i];
        fail(`流偏移 ${pos} 的指令含非可打印 ASCII 字节 0x${hex2(c)}（载荷必须为 ASCII 0x20..0x7e）`,
          { packet: o.packet, offset: o.frameOffset,
            range: `流字节 ${i}，TCP seq 0x${wrap32(isn + 1 + i).toString(16)}`,
            detail: 'non-ascii' });
      }
    }
    const text = new TextDecoder('ascii').decode(stream.subarray(payStart, payEnd));
    commands.push({
      index: commands.length + 1,
      lengthPrefix: len,
      text,
      ...locateRange(owners, pos, payEnd, isn),
    });
    pos = payEnd;
  }

  return {
    ok: true,
    flow: { srcIp: srcS, dstIp: dstS, srcPort: sp, dstPort: dp, protocol: 'TCP' },
    isn: `0x${isn.toString(16).padStart(8, '0')}`,
    packetsTotal: frames.length,
    segmentsMatched: segments.length,
    streamBytes: streamLen,
    finSeq: `0x${wrap32(isn + finAbs).toString(16).padStart(8, '0')}`,
    commands,
  };
}

/**
 * 汇总一条指令（含长度前缀）覆盖的原始包号与字节区间。
 * 连续且同包的相邻字节合并为一个区间。
 */
function locateRange(owners, from, to, isn) {
  const spans = [];
  let cur = null;
  for (let i = from; i < to; i++) {
    const o = owners[i];
    if (cur && cur.packet === o.packet && cur.to === i) {
      cur.to = i + 1;
      cur.frameEnd = o.frameOffset + 1;
    } else {
      if (cur) spans.push(cur);
      cur = { packet: o.packet, from: i, to: i + 1,
              frameStart: o.frameOffset, frameEnd: o.frameOffset + 1 };
    }
  }
  if (cur) spans.push(cur);
  return {
    packets: spans.map((s) => s.packet),
    streamOffset: [from, to],
    tcpSeqRange: [
      `0x${wrap32(isn + 1 + from).toString(16).padStart(8, '0')}`,
      `0x${wrap32(isn + 1 + to).toString(16).padStart(8, '0')}`,
    ],
    spans: spans.map((s) => ({
      packet: s.packet,
      streamOffset: [s.from, s.to],
      frameOffset: [s.frameStart, s.frameEnd],
      tcpSeq: [
        `0x${wrap32(isn + 1 + s.from).toString(16).padStart(8, '0')}`,
        `0x${wrap32(isn + 1 + s.to).toString(16).padStart(8, '0')}`,
      ],
    })),
  };
}

export const _internals = {
  MAX_PASTE_BYTES,
  ipv4HeaderChecksum,
  seqDiff32,
  wrap32,
  parsePcap,
  parseIpv4,
  reassembleFragments,
};
