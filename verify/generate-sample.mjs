/**
 * generate-sample.mjs — 生成“本题捕获样例”：
 * 一次断续链路上行捕获，包含
 *   · 起始 SYN（锚定 ISN，ISN 接近 32 位回绕边界）
 *   · 三段数据乱序到达
 *   · 其中一段在 IPv4 层被分成两个分片且分片乱序
 *   · 一段内容完全相同的重传
 *   · 数据全部到齐后的 FIN
 * 输出 public/samples/avionics-capture.b64（Base64 classic PCAP）。
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PcapBuilder, tcpPacket, ipv4Frame, fragmentedTcpFrames,
  encodeCommands, FLOW,
} from './pcap-builder.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const outPath = resolve(__dirname, '../public/samples/avionics-capture.b64');

const COMMANDS = [
  'UPLINK:ARM=0;SQUAWK=0421',
  'ROUTE:WP1=ZSPD;WP2=ZSSS;CRZ=FL350',
  'LINK:RETRANSMIT=OK;SEQ=WRAP0',
];

const ISN = 0xfffffffa;

function main() {
  const stream = encodeCommands(COMMANDS);
  // 切成三段：[0,12) [12,34) [34,end)
  const cuts = [0, 12, 34, stream.length];
  const segs = [];
  for (let i = 0; i < 3; i++) {
    segs.push(stream.subarray(cuts[i], cuts[i + 1]));
  }
  const seqOf = (off) => ((ISN + 1 + off) >>> 0);

  const pb = new PcapBuilder();
  // 1) SYN
  pb.add(ipv4Frame({ src: FLOW.srcIp, dst: FLOW.dstIp, id: 1,
    payload: tcpPacket({ sport: FLOW.srcPort, dport: FLOW.dstPort,
      seq: ISN, flags: 0x02 }) }));

  // 2) 中段先到（乱序）
  pb.add(ipv4Frame({ src: FLOW.srcIp, dst: FLOW.dstIp, id: 2,
    payload: tcpPacket({ sport: FLOW.srcPort, dport: FLOW.dstPort,
      seq: seqOf(12), flags: 0x18, payload: segs[1].slice() }) }));

  // 3) 首段：IPv4 分片（24 字节载荷一片，TCP 头 20 + 12 数据 = 32 → 24+8），
  //    且第二片先到（分片乱序）
  const firstTcp = tcpPacket({ sport: FLOW.srcPort, dport: FLOW.dstPort,
    seq: seqOf(0), flags: 0x18, payload: segs[0].slice() });
  const frags = fragmentedTcpFrames(firstTcp, {
    src: FLOW.srcIp, dst: FLOW.dstIp, id: 3, mtuPayload: 24,
  });
  pb.add(frags[1]);
  pb.add(frags[0]);

  // 4) 首段内容完全相同的重传（不分片）
  pb.add(ipv4Frame({ src: FLOW.srcIp, dst: FLOW.dstIp, id: 4,
    payload: tcpPacket({ sport: FLOW.srcPort, dport: FLOW.dstPort,
      seq: seqOf(0), flags: 0x18, payload: segs[0].slice() }) }));

  // 5) 末段后到
  pb.add(ipv4Frame({ src: FLOW.srcIp, dst: FLOW.dstIp, id: 5,
    payload: tcpPacket({ sport: FLOW.srcPort, dport: FLOW.dstPort,
      seq: seqOf(34), flags: 0x18, payload: segs[2].slice() }) }));

  // 6) FIN（无数据）
  pb.add(ipv4Frame({ src: FLOW.srcIp, dst: FLOW.dstIp, id: 6,
    payload: tcpPacket({ sport: FLOW.srcPort, dport: FLOW.dstPort,
      seq: seqOf(stream.length), flags: 0x11 }) }));

  mkdirSync(dirname(outPath), { recursive: true });
  const b64 = pb.base64();
  // 每行 76 列，模拟典型 base64 命令输出，同时验证页面容忍换行
  const wrapped = b64.replace(/(.{76})/g, '$1\n') + '\n';
  writeFileSync(outPath, wrapped);
  console.log(`sample written: ${outPath} (${Buffer.byteLength(wrapped)} bytes base64, ${pb.frames.length} frames)`);
}

main();
