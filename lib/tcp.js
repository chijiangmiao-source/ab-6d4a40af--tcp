import { fail } from './errors.js';
import { ipEqual } from './tuple.js';

const FLAG_FIN = 0x01;
const FLAG_SYN = 0x02;
const FLAG_RST = 0x04;
const FLAG_ACK = 0x10;

// 从重组后的 IP 数据报中解析 TCP（端口须匹配受检五元组的某一方向）。
// 每个数据字节都带来源原始包号（由 IP 重组层的 origin 映射给出）。
export function parseTcpSegments(datagrams, tuple) {
  const segments = [];
  for (const dg of datagrams) {
    const p = dg.data;
    if (p.length < 20) {
      throw fail('TRUNCATED_PACKET', `首包 ${dg.firstPacket} 重组后的 IP 数据报不足 20 字节，无法承载 TCP 头`, {
        packet: dg.firstPacket,
        offset: p.length,
      });
    }
    const srcPort = (p[0] << 8) | p[1];
    const dstPort = (p[2] << 8) | p[3];
    const seq = ((p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7]) >>> 0;
    const dataOffsetWords = p[12] >> 4;
    const flags = p[13];
    const dataOffset = dataOffsetWords * 4;
    if (dataOffsetWords < 5) {
      throw fail('BAD_TCP_HEADER', `首包 ${dg.firstPacket} 的 TCP 数据偏移 ${dataOffsetWords} 小于 5，头非法`, {
        packet: dg.firstPacket,
      });
    }
    if (p.length < dataOffset) {
      throw fail('TRUNCATED_PACKET', `首包 ${dg.firstPacket} 的 TCP 头声明 ${dataOffset} 字节，但数据报仅 ${p.length} 字节`, {
        packet: dg.firstPacket,
        offset: p.length,
        range: [p.length, dataOffset],
      });
    }

    let direction = null;
    const fwd = ipEqual(dg.src, tuple.srcIp) && ipEqual(dg.dst, tuple.dstIp)
      && srcPort === tuple.srcPort && dstPort === tuple.dstPort;
    const rev = ipEqual(dg.src, tuple.dstIp) && ipEqual(dg.dst, tuple.srcIp)
      && srcPort === tuple.dstPort && dstPort === tuple.srcPort;
    if (fwd) direction = 1;       // 受检方向：客户端 → 服务端（指令流方向）
    else if (rev) direction = -1;
    else continue;               // 同地址对上端口不属于本五元组的其他连接，跳过

    const tcpPayload = p.subarray(dataOffset);
    const firstPacket = dg.origin[dataOffset] || dg.firstPacket;
    const bytePackets = new Uint32Array(tcpPayload.length);
    for (let i = 0; i < tcpPayload.length; i++) {
      bytePackets[i] = dg.origin[dataOffset + i];
    }
    segments.push({
      packet: firstPacket,
      packets: dg.packets,
      direction,
      seq,
      flags,
      data: tcpPayload,
      bytePackets,
    });
  }
  return segments;
}

const MOD = 0x100000000;

// 受检方向的 TCP 流重组。
// 规则：
//  - 必须有 SYN，其 seq 即 ISN；数据流从 ISN+1 开始；
//  - 32 位序号回绕按模 2^32 距离折算到有符号相对位置；
//  - 乱序段按序号安放；同序号重叠字节必须逐字节相同（重传），不同即整体拒绝；
//  - FIN 给出有效流终点；FIN 前字节必须自 0 起连续，存在空洞即拒绝。
export function reassembleStream(segments) {
  const fwd = segments.filter((s) => s.direction === 1);

  let isn = null;
  let synPacket = null;
  for (const s of fwd) {
    if (s.flags & FLAG_SYN) {
      if (isn !== null && s.seq !== isn) {
        const [p1, p2] = synPacket < s.packet ? [synPacket, s.packet] : [s.packet, synPacket];
        throw fail('CONFLICT',
          `包 ${p1} 与包 ${p2} 的 SYN 序号不一致（${isn >>> 0} vs ${s.seq >>> 0}），无法确定起始序号`, {
            packet: p1, packet2: p2, offset: 0,
          });
      }
      if (isn === null) {
        isn = s.seq;
        synPacket = s.packet;
      }
    }
  }
  if (isn === null) {
    const first = fwd[0];
    throw fail('NO_SYN', '受检方向缺少起始 SYN：无法确定初始序号，禁止猜测流起点', {
      packet: first ? first.packet : null,
    });
  }

  const dataStart = (isn + 1) >>> 0;
  // pieces: {rel, end, bytes(Uint8Array), packets(Uint32Array), packet}
  const pieces = [];
  let finRel = null;
  let finPacket = null;

  for (const s of fwd) {
    if (s.data.length > 0) {
      // SYN 占据一个序号：SYN 段若携带数据，数据实际从 seq+1 开始
      const dataSeq = (s.flags & FLAG_SYN) ? ((s.seq + 1) >>> 0) : s.seq;
      let delta = (dataSeq - dataStart) % MOD;
      if (delta < 0) delta += MOD;
      if (delta > 0x7fffffff) delta -= MOD; // 位于起点之前的回绕段（如保活探测）
      const rel = delta;
      const end = rel + s.data.length;
      if (end > 0) {
        const cut0 = rel < 0 ? -rel : 0;
        const piece = {
          rel: rel + cut0,
          end,
          bytes: s.data.subarray(cut0),
          packets: s.bytePackets.subarray(cut0),
          packet: s.packet,
        };
        // 与已安放段逐字节核对
        for (const q of pieces) {
          const lo = Math.max(piece.rel, q.rel);
          const hi = Math.min(piece.end, q.end);
          for (let i = lo; i < hi; i++) {
            const a = piece.bytes[i - piece.rel];
            const b = q.bytes[i - q.rel];
            if (a !== b) {
              let runEnd = i;
              while (runEnd < hi &&
                     piece.bytes[runEnd - piece.rel] !== q.bytes[runEnd - q.rel]) runEnd++;
              const [p1, p2] = q.packet < piece.packet
                ? [q.packet, piece.packet]
                : [piece.packet, q.packet];
              throw fail('CONFLICT',
                `序号重叠但字节不同：包 ${p1} 与包 ${p2} 覆盖流内偏移 ${i}（TCP 相对序号 ${i}）时字节冲突（0x${a.toString(16).padStart(2, '0')} ≠ 0x${b.toString(16).padStart(2, '0')}），禁止任选一段继续`, {
                  packet: p1, packet2: p2, offset: i, range: [i, runEnd],
                });
            }
          }
        }
        pieces.push(piece);
      }
    }
    if (s.flags & FLAG_FIN) {
      // FIN 的序号：SYN 占一个序号，若 FIN 段携带数据则 FIN 位于数据之后
      const finSeq = (s.seq + (s.flags & FLAG_SYN ? 1 : 0) + s.data.length) >>> 0;
      let d = (finSeq - dataStart) % MOD;
      if (d < 0) d += MOD;
      if (d > 0x7fffffff) d -= MOD;
      if (finRel !== null && d !== finRel) {
        const [p1, p2] = finPacket < s.packet ? [finPacket, s.packet] : [s.packet, finPacket];
        throw fail('CONFLICT', `两个 FIN 指向不同流终点（包 ${p1} 与包 ${p2}）`, {
          packet: p1, packet2: p2, offset: Math.min(finRel, d),
        });
      }
      finRel = d;
      finPacket = s.packet;
    }
  }

  if (finRel === null) {
    throw fail('NO_FIN', `受检流缺少 FIN：无法确认有效流终点（SYN 在包 ${synPacket}）`, {
      packet: synPacket,
    });
  }
  if (finRel < 0) {
    throw fail('CONFLICT', 'FIN 位于流起点之前，流状态异常', { packet: finPacket, offset: 0 });
  }

  // 安放 FIN 前的字节并检查空洞
  const stream = new Uint8Array(finRel);
  const origin = new Uint32Array(finRel);
  for (const p of pieces) {
    const lo = Math.max(0, p.rel);
    const hi = Math.min(finRel, p.end);
    for (let i = lo; i < hi; i++) {
      if (origin[i] === 0) {
        stream[i] = p.bytes[i - p.rel];
        origin[i] = p.packets[i - p.rel];
      }
    }
  }
  for (let i = 0; i < finRel; i++) {
    if (origin[i] === 0) {
      let holeEnd = i;
      while (holeEnd < finRel && origin[holeEnd] === 0) holeEnd++;
      throw fail('STREAM_HOLE',
        `流内空洞：相对序号 ${i}…${holeEnd}（FIN 前长度 ${finRel}）没有任何已接收字节，禁止跳过空洞拼接指令`, {
          packet: synPacket,
          offset: i,
          range: [i, holeEnd],
        });
    }
  }

  return { stream, origin, isn, synPacket, finPacket, length: finRel };
}
