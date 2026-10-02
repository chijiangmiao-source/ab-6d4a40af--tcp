// 一位反码求和校验和（IPv4 头校验）
export function onesComplementSum(bytes) {
  let sum = 0;
  const n = bytes.length;
  const even = n - (n % 2);
  for (let i = 0; i < even; i += 2) {
    sum += (bytes[i] << 8) | bytes[i + 1];
    if (sum > 0xffff) sum -= 0xffff;
  }
  if (n % 2 === 1) {
    sum += bytes[n - 1] << 8;
    if (sum > 0xffff) sum -= 0xffff;
  }
  return sum & 0xffff;
}

export function ipHeaderChecksum(header) {
  return onesComplementSum(header) === 0xffff;
}

// 计算正确的 IPv4 头校验和（构造样例用）
export function computeIpChecksum(header) {
  const h = header.slice();
  h[10] = 0;
  h[11] = 0;
  const s = onesComplementSum(h);
  return (~s) & 0xffff;
}
