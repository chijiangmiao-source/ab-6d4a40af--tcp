import { fail } from './errors.js';
import { ipHeaderChecksum } from './checksum.js';
import { ipEqual } from './tuple.js';

const ETHERTYPE_IPV4 = 0x0800;
const ETHERTYPE_VLAN = new Set([0x8100, 0x88a8, 0x9100]);
const PROTO_TCP = 6;

// 解析 Ethernet II + IPv4（允许 802.1Q/QinQ 标签这一 Ethernet II 惯用形式）。
// 仅返回与受检 IP 对、协议 TCP 相关的 IPv4 包（含分片）；无关帧返回 null。
// 所有“相关”包在此完成长度与 IPv4 头校验和的严格核对。
export function parseIpv4Frame(frame, num, tuple) {
  const data = frame.data;
  if (data.length < 14) {
    throw fail('TRUNCATED_FRAME', `第 ${num} 个包不足 14 字节，连 Ethernet 头都不完整`, {
      packet: num,
      offset: data.length,
      range: [data.length, 14],
    });
  }
  let l3 = 14;
  let ethertype = (data[12] << 8) | data[13];
  // 802.3 长度型帧（<=1500）不是 Ethernet II，无法承载 IPv4 流量，跳过。
  if (ethertype <= 0x05dc) return null;
  while (ETHERTYPE_VLAN.has(ethertype)) {
    if (data.length < l3 + 4) {
      throw fail('TRUNCATED_FRAME', `第 ${num} 个包 VLAN 标签被截断`, { packet: num, offset: l3 });
    }
    ethertype = (data[l3 + 2] << 8) | data[l3 + 3];
    l3 += 4;
  }
  if (ethertype !== ETHERTYPE_IPV4) return null; // ARP、IPv6 等无关帧

  if (data.length - l3 < 20) {
    throw fail('TRUNCATED_PACKET', `第 ${num} 个包声称承载 IPv4，但 IP 固定头被截断`, {
      packet: num,
      offset: l3 + (data.length - l3),
    });
  }
  const vih = data[l3];
  const version = vih >> 4;
  const ihlWords = vih & 0x0f;
  const totalLen = (data[l3 + 2] << 8) | data[l3 + 3];
  const ident = ((data[l3 + 4] << 8) | data[l3 + 5]) >>> 0;
  const flagsFragment = ((data[l3 + 6] << 8) | data[l3 + 7]) >>> 0;
  const mf = (flagsFragment & 0x2000) !== 0;
  const fragOffset = flagsFragment & 0x1fff;
  const proto = data[l3 + 9];
  const src = data.subarray(l3 + 12, l3 + 16);
  const dst = data.subarray(l3 + 16, l3 + 20);

  const pairForward = ipEqual(src, tuple.srcIp) && ipEqual(dst, tuple.dstIp);
  const pairReverse = ipEqual(src, tuple.dstIp) && ipEqual(dst, tuple.srcIp);
  if ((!pairForward && !pairReverse) || proto !== PROTO_TCP) {
    return null; // 与受检 TCP 五元组无关
  }

  if (version !== 4) {
    throw fail('NOT_IPV4', `第 ${num} 个包 IP 版本字段为 ${version}，仅接受 IPv4`, {
      packet: num,
      offset: l3,
    });
  }
  if (ihlWords < 5) {
    throw fail('BAD_IP_HEADER', `第 ${num} 个包 IHL=${ihlWords} 小于 5，IPv4 头非法`, {
      packet: num,
      offset: l3,
    });
  }
  const ihl = ihlWords * 4;
  if (data.length - l3 < ihl) {
    throw fail('TRUNCATED_PACKET', `第 ${num} 个包 IPv4 头（${ihl} 字节）被截断`, {
      packet: num,
      offset: data.length,
      range: [data.length, l3 + ihl],
    });
  }
  if (totalLen < ihl) {
    throw fail('BAD_IP_HEADER', `第 ${num} 个包 IP 总长度 ${totalLen} 小于头长度 ${ihl}`, {
      packet: num,
      offset: l3 + 2,
    });
  }
  if (data.length - l3 < totalLen) {
    throw fail('TRUNCATED_PACKET', `第 ${num} 个包 IP 总长度声明 ${totalLen} 字节，帧内仅捕获 ${data.length - l3} 字节`, {
      packet: num,
      offset: l3 + (data.length - l3),
      range: [l3 + (data.length - l3), l3 + totalLen],
    });
  }
  const header = data.subarray(l3, l3 + ihl);
  if (!ipHeaderChecksum(header)) {
    throw fail('IP_CHECKSUM', `第 ${num} 个包 IPv4 头校验和错误（接收即作废，不得参与重组）`, {
      packet: num,
      offset: l3 + 10,
    });
  }

  const payload = data.subarray(l3 + ihl, l3 + totalLen);
  return {
    num,
    src: src.slice(),
    dst: dst.slice(),
    proto,
    id: ident,
    mf,
    fragOffset, // 以 8 字节为单位
    payload,
    headerOffset: l3,
  };
}
