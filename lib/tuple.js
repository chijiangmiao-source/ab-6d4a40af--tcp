import { fail } from './errors.js';

// 严格解析点分十进制 IPv4，返回 4 字节数组
export function parseIpv4(text) {
  if (typeof text !== 'string') {
    throw fail('BAD_TUPLE', 'IP 地址必须是字符串');
  }
  const parts = text.trim().split('.');
  if (parts.length !== 4) {
    throw fail('BAD_TUPLE', `不是合法 IPv4 地址：${text}`);
  }
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const p = parts[i];
    if (!/^\d{1,3}$/.test(p)) {
      throw fail('BAD_TUPLE', `不是合法 IPv4 地址：${text}`);
    }
    const v = Number(p);
    if (v > 255) {
      throw fail('BAD_TUPLE', `IPv4 段超出 0-255：${text}`);
    }
    out[i] = v;
  }
  return out;
}

export function ipv4ToText(bytes) {
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}

export function ipEqual(a, b) {
  return a[0] === b[0] && a[1] === b[1] && a[2] === b[2] && a[3] === b[3];
}

export function parsePort(text, label) {
  if (typeof text !== 'string' || !/^\d{1,5}$/.test(text.trim())) {
    throw fail('BAD_TUPLE', `${label}必须是 1-65535 的整数`);
  }
  const v = Number(text.trim());
  if (v < 1 || v > 65535) {
    throw fail('BAD_TUPLE', `${label}必须在 1-65535 之间`);
  }
  return v;
}

export function normalizeTuple(input) {
  if (!input || typeof input !== 'object') {
    throw fail('BAD_TUPLE', '缺少受检 TCP 五元组');
  }
  return {
    srcIp: parseIpv4(input.srcIp ?? input.src_ip),
    dstIp: parseIpv4(input.dstIp ?? input.dst_ip),
    srcPort: parsePort(String(input.srcPort ?? input.src_port ?? ''), '源端口'),
    dstPort: parsePort(String(input.dstPort ?? input.dst_port ?? ''), '目的端口'),
    protocol: 'TCP',
  };
}
