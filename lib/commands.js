import { fail } from './errors.js';

// 长度前缀 ASCII 指令解析。
// 帧格式：[2 字节大端长度 n][n 字节 ASCII 载荷]，帧首尾相接。
// 要求：
//  - n 必须恰好被剩余字节容纳（长度不完整即截断指令，拒绝）；
//  - 载荷全部为可见 ASCII（0x20-0x7E）；
//  - 整段流必须被指令恰好耗尽，任何尾随残字节（连一个长度前缀都凑不齐）也拒绝。
export function parseCommands(stream, origin) {
  const commands = [];
  let pos = 0;
  const total = stream.length;
  while (pos < total) {
    if (total - pos < 2) {
      throw fail('TRAILING_BYTES',
        `流尾残留 ${total - pos} 字节，凑不出 2 字节长度前缀，拒绝输出任何半截指令`, {
          offset: pos,
          range: [pos, total],
          packet: origin[pos] ?? null,
        });
    }
    const n = (stream[pos] << 8) | stream[pos + 1];
    const prefixStart = pos;
    const payloadStart = pos + 2;
    const payloadEnd = payloadStart + n;
    if (n === 0) {
      throw fail('INVALID_COMMAND', '长度前缀为 0：空指令不构成有效 ASCII 指令', {
        offset: prefixStart,
        range: [prefixStart, payloadStart],
        packet: origin[prefixStart] ?? null,
      });
    }
    if (payloadEnd > total) {
      throw fail('TRUNCATED_COMMAND',
        `偏移 ${prefixStart} 处长度前缀声明 ${n} 字节载荷，但 FIN 前流只剩 ${total - payloadStart} 字节，指令被截断`, {
          offset: prefixStart,
          range: [prefixStart, total],
          packet: origin[prefixStart] ?? null,
          extra: { declaredLength: n, remaining: total - payloadStart },
        });
    }
    let text = '';
    for (let i = payloadStart; i < payloadEnd; i++) {
      const b = stream[i];
      if (b < 0x20 || b > 0x7e) {
        throw fail('NON_ASCII',
          `第 ${commands.length + 1} 条指令载荷偏移 ${i} 处字节 0x${b.toString(16).padStart(2, '0')} 不是可见 ASCII，拒绝输出`, {
            offset: i,
            range: [i, i + 1],
            packet: origin[i] ?? null,
          });
      }
      text += String.fromCharCode(b);
    }
    const packets = new Set();
    for (let i = prefixStart; i < payloadEnd; i++) packets.add(origin[i]);
    commands.push({
      index: commands.length,
      text,
      length: n,
      byteRange: [prefixStart, payloadEnd],      // 含 2 字节长度前缀（流内半开区间）
      payloadRange: [payloadStart, payloadEnd],  // ASCII 载荷区间
      packets: [...packets].sort((a, b) => a - b),
    });
    pos = payloadEnd;
  }
  return commands;
}
