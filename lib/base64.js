import { fail } from './errors.js';

// 仅接受 Base64 classic（字母表 A-Za-z0-9+/，结尾 0/1/2 个 '='）。
// 允许粘贴时夹带空白字符（换行/空格/制表符），其余字符一律拒绝。
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const DECODE = new Int16Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) DECODE[ALPHABET.charCodeAt(i)] = i;

const CANONICAL =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$/;

export function decodeBase64Classic(input) {
  if (typeof input !== 'string') {
    throw fail('BAD_BASE64', 'Base64 输入必须是字符串');
  }
  const s = input.replace(/[\t\n\f\r ]+/g, '');
  if (s.length === 0) {
    throw fail('BAD_BASE64', 'Base64 内容为空');
  }
  if (!CANONICAL.test(s)) {
    throw fail('BAD_BASE64', '不是合法的 Base64 classic 编码（含非法字符、错误填充或长度不是 4 的倍数）', {
      length: s.length,
    });
  }
  const pad = s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0;
  const out = new Uint8Array((s.length >> 2) * 3 - pad);
  let o = 0;
  for (let i = 0; i < s.length; i += 4) {
    const last = i + 4 === s.length;
    const c0 = DECODE[s.charCodeAt(i)];
    const c1 = DECODE[s.charCodeAt(i + 1)];
    const c2 = s[i + 2] === '=' ? 0 : DECODE[s.charCodeAt(i + 2)];
    const c3 = s[i + 3] === '=' ? 0 : DECODE[s.charCodeAt(i + 3)];
    if ((c0 | c1 | c2 | c3) < 0) {
      throw fail('BAD_BASE64', 'Base64 字母表之外的字符');
    }
    // 规范编码要求填充对应的低位必须为 0，拒绝 'AB==' 这类混入置位位的尾组
    if (last && pad === 2 && (c1 & 0x0f) !== 0) {
      throw fail('BAD_BASE64', 'Base64 尾组在填充位上携带了非零比特，不是规范编码');
    }
    if (last && pad === 1 && (c2 & 0x03) !== 0) {
      throw fail('BAD_BASE64', 'Base64 尾组在填充位上携带了非零比特，不是规范编码');
    }
    const triple = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
    if (o < out.length) out[o++] = (triple >> 16) & 0xff;
    if (o < out.length) out[o++] = (triple >> 8) & 0xff;
    if (o < out.length) out[o++] = triple & 0xff;
  }
  return out;
}
