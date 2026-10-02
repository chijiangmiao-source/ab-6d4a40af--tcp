import { decodeBase64Classic } from './base64.js';
import { parsePcap } from './pcap.js';
import { parseIpv4Frame } from './decode.js';
import { reassembleDatagrams } from './ipdefrag.js';
import { parseTcpSegments, reassembleStream } from './tcp.js';
import { parseCommands } from './commands.js';
import { normalizeTuple, ipv4ToText } from './tuple.js';
import { AnalysisError } from './errors.js';

const MAX_BASE64_BYTES = 256 * 1024;
const LINKTYPE_ETHERNET = 1;

// 主复核入口。成功返回结构化结论；任何规则违例抛 AnalysisError（含首个包号/偏移/区间）。
export function analyze(input) {
  const tuple = normalizeTuple(input);
  const b64 = typeof input === 'object' ? (input.pcapBase64 ?? input.pcap) : '';
  if (typeof b64 !== 'string' || b64.replace(/\s/g, '').length === 0) {
    throw new AnalysisError('BAD_BASE64', '缺少 PCAP 的 Base64 内容');
  }
  if (b64.length > MAX_BASE64_BYTES) {
    throw new AnalysisError('TOO_LARGE',
      `Base64 输入 ${b64.length} 字节，超过 ${MAX_BASE64_BYTES} 字节（256 KiB）上限`, {
        extra: { size: b64.length, limit: MAX_BASE64_BYTES },
      });
  }

  const raw = decodeBase64Classic(b64);
  const pcap = parsePcap(raw);
  if (pcap.linktype !== LINKTYPE_ETHERNET) {
    throw new AnalysisError('UNSUPPORTED_LINKTYPE',
      `链路层类型 ${pcap.linktype} 不受支持：浏览器仅接受 Ethernet II（linktype=1）`);
  }

  const ipPackets = [];
  for (const frame of pcap.packets) {
    if (frame.truncated) {
      throw new AnalysisError('TRUNCATED_CAPTURE',
        `第 ${frame.num} 个原始包在抓包时即被截断（捕获 ${frame.inclLen}/${frame.origLen} 字节），不得参与复核`, {
          packet: frame.num,
          offset: frame.inclLen,
          range: [frame.inclLen, frame.origLen],
        });
    }
    const ip = parseIpv4Frame(frame, frame.num, tuple);
    if (ip) ipPackets.push(ip);
  }

  if (ipPackets.length === 0) {
    throw new AnalysisError('NO_MATCH',
      `捕获中没有任何属于 ${ipv4ToText(tuple.srcIp)}:${tuple.srcPort} ↔ ${ipv4ToText(tuple.dstIp)}:${tuple.dstPort} 的 IPv4/TCP 报文`);
  }

  const datagrams = reassembleDatagrams(ipPackets);
  const segments = parseTcpSegments(datagrams, tuple);
  if (!segments.some((s) => s.direction === 1)) {
    throw new AnalysisError('NO_MATCH',
      `没有源为 ${ipv4ToText(tuple.srcIp)}:${tuple.srcPort}、目的为 ${ipv4ToText(tuple.dstIp)}:${tuple.dstPort} 的 TCP 段，无法复核该方向指令流`);
  }
  const { stream, origin, isn, synPacket, finPacket, length } = reassembleStream(segments);
  const commands = parseCommands(stream, origin);
  if (commands.length === 0) {
    throw new AnalysisError('EMPTY_STREAM',
      `SYN（包 ${synPacket}）与 FIN（包 ${finPacket}）之间没有任何数据字节，无指令可重建`, {
        packet: synPacket, packet2: finPacket,
      });
  }

  return {
    ok: true,
    tuple: {
      srcIp: ipv4ToText(tuple.srcIp),
      dstIp: ipv4ToText(tuple.dstIp),
      srcPort: tuple.srcPort,
      dstPort: tuple.dstPort,
    },
    streamLength: length,
    isn: isn >>> 0,
    synPacket,
    finPacket,
    packetCount: pcap.packets.length,
    datagramCount: datagrams.length,
    commands,
  };
}

export { AnalysisError };
export const LIMITS = { MAX_BASE64_BYTES };
