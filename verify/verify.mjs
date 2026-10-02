/**
 * verify.mjs — 一次性复核服务（随 `docker compose run --rm verify` 或
 * `npm run verify` 执行，结束后以退出码 0/1 终止）：
 *
 *   A. 重组规则单元/集成测试（reviewPcap 全部分支）
 *   B. 页面构建检查（index.html / pcap-engine.mjs 完整且互相引用）
 *   C. HTTP 冒烟：启动静态服务，打 /healthz、/、引擎脚本与捕获样例，
 *      并用引擎在 Node 侧复核样例（浏览器同一份 ESM）
 */
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import net from 'node:net';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

import { reviewPcap, VerifyError, _internals } from '../public/pcap-engine.mjs';
import {
  PcapBuilder, tcpPacket, ipv4Frame, fragmentedTcpFrames,
  encodeCommands, FLOW,
} from './pcap-builder.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

let passed = 0;
const failures = [];

function ok(name, cond, extra = '') {
  if (cond) { passed += 1; console.log(`  \x1b[32m✓\x1b[0m ${name}`); }
  else { failures.push(name + (extra ? ` — ${extra}` : '')); console.log(`  \x1b[31m✗ ${name}${extra ? ' — ' + extra : ''}\x1b[0m`); }
}
function eq(name, actual, expected) {
  const cond = JSON.stringify(actual) === JSON.stringify(expected);
  ok(name, cond, cond ? '' : `got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)}`);
}
function expectFail(name, fn, detail) {
  try { fn(); ok(name, false, '应当失败但通过了'); }
  catch (e) {
    const good = e instanceof VerifyError && (detail ? e.loc && e.loc.detail === detail : true);
    ok(name, good, good ? '' : `VerifyError detail=${e.loc ? e.loc.detail : '(none)'} msg=${e.message}`);
    return e;
  }
}

/* ------------------------------------------------------------------ */
/* PCAP 构造辅助                                                        */
/* ------------------------------------------------------------------ */

const ISN_DEFAULT = 1000;
const S = (off) => ((ISN_DEFAULT + 1 + off) >>> 0);

/** 构造一条仅含受检方向段的 PCAP（SYN 自动添加在前）。*/
function buildPcap(segments, { isn = ISN_DEFAULT, idFrom = 10 } = {}) {
  const pb = new PcapBuilder();
  pb.add(ipv4Frame({ id: 1, payload: tcpPacket({ seq: isn, flags: 0x02 }) }));
  segments.forEach((seg, i) => {
    pb.add(ipv4Frame({ id: idFrom + i,
      payload: tcpPacket({
        seq: seg.seq, flags: seg.flags ?? 0x18,
        payload: seg.data ?? new Uint8Array(0),
      }) }));
  });
  return pb.base64();
}

function withFin(segments, isn = ISN_DEFAULT) {
  const maxOff = Math.max(...segments.map((s) => {
    const rel = _internals.seqDiff32(s.seq, ((isn + 1) >>> 0));
    return rel + s.data.length;
  }), 0);
  return [
    ...segments,
    { seq: ((isn + 1 + maxOff) >>> 0), flags: 0x11, data: new Uint8Array(0) },
  ];
}

/* ================================================================ */
console.log('\n[A] 重组规则测试');

/* ---- A1 本题捕获样例：乱序 + 分片乱序 + 重传 + 32 位回绕 -------- */
{
  const b64 = readFileSync(resolve(ROOT, 'public/samples/avionics-capture.b64'), 'utf8');
  const r = reviewPcap(b64, FLOW);
  ok('A1 样例复核通过', r.ok === true);
  eq('A1 指令条数', r.commands.length, 3);
  eq('A1 指令 1 文本', r.commands[0].text, 'UPLINK:ARM=0;SQUAWK=0421');
  eq('A1 指令 2 文本', r.commands[1].text, 'ROUTE:WP1=ZSPD;WP2=ZSSS;CRZ=FL350');
  eq('A1 指令 3 文本', r.commands[2].text, 'LINK:RETRANSMIT=OK;SEQ=WRAP0');
  // 指令 1 跨：首段（分片包 #4/#5，重组首片按到达顺序——这里是 #4 先）与中段 #2
  // 抓包顺序：#1 SYN, #2 中段, #3 第二分片, #4 第一分片, #5 重传, #6 末段, #7 FIN
  ok('A1 指令 1 覆盖多个原始包', r.commands[0].packets.length >= 2,
    `packets=${JSON.stringify(r.commands[0].packets)}`);
  ok('A1 每包区间带帧偏移与 TCP seq',
    r.commands[0].spans.every((s) => Array.isArray(s.frameOffset) && s.tcpSeq[0].startsWith('0x')));
  eq('A2 长度前缀正确', r.commands.map((c) => c.lengthPrefix), [24, 33, 28]);
  eq('A1 FIN 回绕后序号', r.finSeq, '0x00000056');
  eq('A1 总包数', r.packetsTotal, 7);
  // 流偏移连续拼接
  let cursor = 0;
  const aligned = r.commands.every((c) => c.streamOffset[0] === cursor &&
    (cursor = c.streamOffset[1]) === c.streamOffset[1]);
  ok('A1 指令按序且无缝覆盖', aligned && cursor === r.streamBytes);
}

/* ---- A2 顺序到达，单包多指令 ------------------------------------ */
{
  const data = encodeCommands(['PING', 'PONG']);
  const r = reviewPcap(buildPcap(withFin([{ seq: S(0), data }])), FLOW);
  eq('A2 两条指令', r.commands.map((c) => c.text), ['PING', 'PONG']);
  eq('A2 均出自包 #2（SYN 为 #1）', r.commands[0].packets, [2]);
  eq('A2 流偏移', [r.commands[0].streamOffset, r.commands[1].streamOffset],
    [[0, 6], [6, 12]]);
}

/* ---- A3 乱序段按序重建 ------------------------------------------ */
{
  const data = encodeCommands(['ABCDEFGH']); // 10 bytes frame
  const a = data.subarray(0, 4), b = data.subarray(4, 7), c = data.subarray(7, 10);
  const r = reviewPcap(buildPcap(withFin([
    { seq: S(7), data: c },
    { seq: S(0), data: a },
    { seq: S(4), data: b },
  ])), FLOW);
  eq('A3 乱序重建文本', r.commands[0].text, 'ABCDEFGH');
  // 到达顺序 #2=c(尾), #3=a(头), #4=b(中)；区间按流顺序归属为 3,4,2
  eq('A3 覆盖包号按流区间', r.commands[0].packets, [3, 4, 2]);
}

/* ---- A4 内容相同的重传：通过且归属首见包 ------------------------- */
{
  const data = encodeCommands(['REPEAT']);
  const r = reviewPcap(buildPcap(withFin([
    { seq: S(0), data: data.subarray(0, 5) },
    { seq: S(0), data: data.subarray(0, 5) },   // 完全相同重传
    { seq: S(5), data: data.subarray(5) },
  ])), FLOW);
  eq('A4 文本', r.commands[0].text, 'REPEAT');
  // 首见包 #2 拥有全部重叠字节；#3 不出现
  ok('A4 冲突重传不重复计包', !r.commands[0].packets.includes(3),
    JSON.stringify(r.commands[0].packets));
}

/* ---- A5 同序号不同字节：必须失败并定位 --------------------------- */
{
  const data = encodeCommands(['CONFLICT']); // 2 + 8 = 10 字节
  const evil = data.slice();
  evil[4] = evil[4] === 0x58 ? 0x59 : 0x58; // 改动落在重叠区 [3,6)
  const err = expectFail('A5 字节冲突拒绝且不择一', () =>
    reviewPcap(buildPcap(withFin([
      { seq: S(0), data: data.subarray(0, 6) },
      { seq: S(3), data: evil.subarray(3, 8) }, // 重叠 [3,6) 且字节不同
      { seq: S(8), data: data.subarray(8) },
    ])), FLOW), 'byte-conflict');
  ok('A5 定位首个原始包号（两冲突包较小者 #2）', err.loc.packet === 2,
    `packet=${err.loc.packet}`);
  ok('A5 给帧偏移', typeof err.loc.offset === 'number');
  ok('A5 给冲突区间且含两包号',
    /包 2/.test(err.loc.range) && /包 3/.test(err.loc.range), err.loc.range);
}

/* ---- A6 32 位回绕：ISN 临近 0xffffffff -------------------------- */
{
  const isn = 0xffffff00;
  const text = 'W' + 'A'.repeat(258) + 'Z'; // 260 字符 → frame 262，越过回绕点
  const data = encodeCommands([text]);
  const mk = (off, len, flags = 0x18) => ({
    seq: ((isn + 1 + off) >>> 0), flags, data: data.subarray(off, off + len),
  });
  const segs = [mk(100, 80), mk(0, 50), mk(200, 62), mk(50, 50), mk(180, 20)];
  segs.push({ seq: ((isn + 1 + data.length) >>> 0), flags: 0x11, data: new Uint8Array(0) });
  const b64 = (() => {
    const pb = new PcapBuilder();
    pb.add(ipv4Frame({ id: 1, payload: tcpPacket({ seq: isn, flags: 0x02 }) }));
    segs.forEach((s, i) => pb.add(ipv4Frame({ id: 10 + i,
      payload: tcpPacket({ seq: s.seq, flags: s.flags, payload: s.data }) })));
    return pb.base64();
  })();
  const r = reviewPcap(b64, FLOW);
  eq('A6 回绕后指令长度', r.commands[0].lengthPrefix, 260);
  eq('A6 回绕后指令首尾字符',
    r.commands[0].text[0] + r.commands[0].text.at(-1), 'WZ');
  eq('A6 总字节', r.streamBytes, 262);
}

/* ---- A7 IP 分片：跨片 TCP 头与数据正常重组 ----------------------- */
{
  const data = encodeCommands(['FRAGMENTED-DATA']);
  const full = tcpPacket({ seq: S(0), flags: 0x18, payload: data });
  const frags = fragmentedTcpFrames(full, { id: 77, mtuPayload: 16 }); // 16+16+?
  const pb = new PcapBuilder();
  pb.add(ipv4Frame({ id: 1, payload: tcpPacket({ seq: ISN_DEFAULT, flags: 0x02 }) }));
  frags.forEach((f) => pb.add(f));
  pb.add(ipv4Frame({ id: 9, payload: tcpPacket({ seq: S(data.length), flags: 0x11 }) }));
  const r = reviewPcap(pb.base64(), FLOW);
  eq('A7 分片重组后指令', r.commands[0].text, 'FRAGMENTED-DATA');
  // 三片 IP 载荷边界 16：TCP 数据（偏移 20..36）落在第 2、3 片（包 #3/#4）
  eq('A7 区间定位到承载数据的分片原始包号', r.commands[0].packets, [3, 4]);
}

/* ---- A8 缺尾片：失败 --------------------------------------------- */
{
  const data = encodeCommands(['NEEDS-MORE-FRAGS']);
  const full = tcpPacket({ seq: S(0), flags: 0x18, payload: data });
  const frags = fragmentedTcpFrames(full, { id: 88, mtuPayload: 16 });
  const pb = new PcapBuilder();
  pb.add(ipv4Frame({ id: 1, payload: tcpPacket({ seq: ISN_DEFAULT, flags: 0x02 }) }));
  pb.add(frags[0]); // MF=1，尾片缺失
  expectFail('A8 缺尾片拒绝', () => reviewPcap(pb.base64(), FLOW), 'missing-fragment');
}

/* ---- A9 分片空洞：失败 ------------------------------------------- */
{
  const data = encodeCommands(['HOLE-IN-FRAGMENTS-XX']); // 23B payload + 20 tcp = 43
  const full = tcpPacket({ seq: S(0), flags: 0x18, payload: data });
  const pb = new PcapBuilder();
  pb.add(ipv4Frame({ id: 1, payload: tcpPacket({ seq: ISN_DEFAULT, flags: 0x02 }) }));
  // 首片 IP 偏移 0，长度 8，MF=1；直接跳到偏移 24 的尾片
  pb.add(ipv4Frame({ id: 2, flagsFrag: 0x2000 | 0,
    payload: full.subarray(0, 8) }));
  pb.add(ipv4Frame({ id: 3, flagsFrag: 24 / 8,
    payload: full.subarray(24) }));
  expectFail('A9 分片空洞拒绝', () => reviewPcap(pb.base64(), FLOW), 'missing-fragment');
}

/* ---- A10 分片交叠：失败 ------------------------------------------ */
{
  const data = encodeCommands(['OVERLAP-FRAGMENT']);
  const full = tcpPacket({ seq: S(0), flags: 0x18, payload: data });
  const pb = new PcapBuilder();
  pb.add(ipv4Frame({ id: 1, payload: tcpPacket({ seq: ISN_DEFAULT, flags: 0x02 }) }));
  pb.add(ipv4Frame({ id: 2, flagsFrag: 0x2000,
    payload: full.subarray(0, 24) }));
  pb.add(ipv4Frame({ id: 2, flagsFrag: 16 / 8,
    payload: full.subarray(16) })); // 与首片 [16,24) 交叠（同一 id=2）
  expectFail('A10 分片交叠拒绝', () => reviewPcap(pb.base64(), FLOW), 'fragment-overlap');
}

/* ---- A11 IPv4 头校验和错误：失败并指向校验字段 ------------------- */
{
  const pb = new PcapBuilder();
  pb.add(ipv4Frame({ id: 1, payload: tcpPacket({ seq: 1, flags: 0x02 }),
    badChecksum: true }));
  const err = expectFail('A11 坏 IPv4 校验和拒绝', () => reviewPcap(pb.base64(), FLOW),
    'bad-ipv4-checksum');
  eq('A11 定位包号', err.loc.packet, 1);
  eq('A11 定位校验和字段偏移（14+10）', err.loc.offset, 24);
}

/* ---- A12 PCAP 截断：失败 ----------------------------------------- */
{
  const pb = new PcapBuilder();
  pb.add(ipv4Frame({ id: 1, payload: tcpPacket({ seq: 1, flags: 0x02 }) }));
  const raw = Buffer.from(pb.build());
  // 追加一个声明 100 字节载荷但其后无数据的记录头（Base64 仍然完整合法）
  const rh = Buffer.alloc(16);
  rh.writeUInt32LE(100, 8);
  rh.writeUInt32LE(100, 12);
  const cut = Buffer.concat([raw, rh]).toString('base64');
  expectFail('A12 截断包拒绝', () => reviewPcap(cut, FLOW), 'truncated-packet');
}

/* ---- A13 缺失起始 SYN：失败 -------------------------------------- */
{
  const data = encodeCommands(['NO-SYN-HERE']);
  const pb = new PcapBuilder();
  pb.add(ipv4Frame({ id: 9, payload: tcpPacket({ seq: S(0), flags: 0x18, payload: data }) }));
  pb.add(ipv4Frame({ id: 10, payload: tcpPacket({ seq: S(data.length), flags: 0x11 }) }));
  expectFail('A13 无 SYN 拒绝', () => reviewPcap(pb.base64(), FLOW), 'missing-syn');
}

/* ---- A14 流内空洞：失败并定位缺口序号 ---------------------------- */
{
  const data = encodeCommands(['GAP-IN-THE-STREAM']);
  const err = expectFail('A14 流内空洞拒绝', () =>
    reviewPcap(buildPcap(withFin([
      { seq: S(0), data: data.subarray(0, 6) },
      { seq: S(10), data: data.subarray(10) },
    ])), FLOW), 'stream-gap');
  ok('A14 区间描述含缺口', /缺失序号/.test(err.loc.range), err.loc.range);
}

/* ---- A15 缺失 FIN：失败 ------------------------------------------ */
{
  const data = encodeCommands(['NEVER-CLOSED']);
  expectFail('A15 无 FIN 拒绝', () =>
    reviewPcap(buildPcap([{ seq: S(0), data }]), FLOW), 'missing-fin');
}

/* ---- A16 FIN 之后到达的数据：拒绝拼入 ---------------------------- */
{
  const data = encodeCommands(['AFTER-FIN!']);
  expectFail('A16 FIN 后数据拒绝', () =>
    reviewPcap(buildPcap([
      { seq: S(0), data: data.subarray(0, 4) },
      { seq: S(4), flags: 0x11, data: new Uint8Array(0) },
      { seq: S(4), data: data.subarray(4) },
    ]), FLOW), 'data-after-fin');
}

/* ---- A17 长度前缀越界：失败 -------------------------------------- */
{
  const data = new Uint8Array([0x01, 0x00, 0x41]); // 声称 256，实际 1 字节
  expectFail('A17 长度前缀超流末尾拒绝', () =>
    reviewPcap(buildPcap(withFin([{ seq: S(0), data }])), FLOW), 'length-overrun');
}

/* ---- A18 尾随残字节：失败 ---------------------------------------- */
{
  const good = encodeCommands(['TRAIL']);
  const data = new Uint8Array(good.length + 1);
  data.set(good, 0); data[good.length] = 0x58;
  expectFail('A18 尾随 1 残字节拒绝', () =>
    reviewPcap(buildPcap(withFin([{ seq: S(0), data }])), FLOW), 'trailing-bytes');
}

/* ---- A19 非可打印 ASCII：失败 ------------------------------------ */
{
  const data = encodeCommands(['BAD\x01CHAR']);
  expectFail('A19 非 ASCII 字节拒绝', () =>
    reviewPcap(buildPcap(withFin([{ seq: S(0), data }])), FLOW), 'non-ascii');
}

/* ---- A20 空载荷指令与空格：合法 ---------------------------------- */
{
  const data = encodeCommands(['', 'SPACE LOAD']);
  const r = reviewPcap(buildPcap(withFin([{ seq: S(0), data }])), FLOW);
  eq('A20 空指令 + 含空格指令', r.commands.map((c) => c.text), ['', 'SPACE LOAD']);
  eq('A20 空指令长度前缀', r.commands[0].lengthPrefix, 0);
}

/* ---- A21 非 Ethernet II / 非 IPv4：拒绝 -------------------------- */
{
  const mk = (ethertype) => {
    const f = ipv4Frame({ payload: tcpPacket({ seq: 1, flags: 0x02 }) });
    f[12] = (ethertype >> 8) & 0xff; f[13] = ethertype & 0xff;
    return f;
  };
  let pb = new PcapBuilder(); pb.add(mk(0x0806)); // ARP
  expectFail('A21a ARP EtherType 拒绝', () => reviewPcap(pb.base64(), FLOW), 'not-ipv4');
  pb = new PcapBuilder(); pb.add(mk(0x8100)); // 802.1Q VLAN
  expectFail('A21b VLAN 标签拒绝', () => reviewPcap(pb.base64(), FLOW), 'not-ipv4');
  pb = new PcapBuilder(); pb.add(mk(0x0064)); // 802.3 长度字段
  expectFail('A21c 802.3 帧拒绝', () => reviewPcap(pb.base64(), FLOW), 'not-ethernet-ii');
}

/* ---- A22 五元组方向不匹配：无段可用 ------------------------------ */
{
  const b64 = buildPcap(withFin([{ seq: S(0), data: encodeCommands(['X'] ) }]));
  expectFail('A22 反向端口无段', () => reviewPcap(b64,
    { ...FLOW, srcPort: FLOW.dstPort, dstPort: FLOW.srcPort }), null);
  expectFail('A22b 地址非法', () => reviewPcap(b64, { ...FLOW, srcIp: '999.1.1.1' }), null);
}

/* ---- A23 Base64 非法字符 / 超 256 KiB ---------------------------- */
{
  expectFail('A23a 非法 Base64 字符', () =>
    reviewPcap('@@@@' , FLOW), null);
  const big = 'A'.repeat(_internals.MAX_PASTE_BYTES + 1);
  expectFail('A23b 超过 256 KiB 拒绝', () => reviewPcap(big, FLOW), null);
  expectFail('A23c 空内容拒绝', () => reviewPcap('   \n ', FLOW), null);
}

/* ---- A24 校验和工具本身 ------------------------------------------ */
{
  const good = ipv4Frame({ id: 1, payload: tcpPacket({ seq: 1, flags: 0x02 }) });
  // IPv4 头在帧偏移 14，取 20 字节
  const hdr = good.subarray(14, 34);
  eq('A24 正确头校验和为 0', _internals.ipv4HeaderChecksum(hdr, 20), 0);
  const bad = hdr.slice(); bad[10] ^= 0xff;
  ok('A24 损坏头校验和非 0', _internals.ipv4HeaderChecksum(bad, 20) !== 0);
}

/* ================================================================ */
console.log('\n[B] 页面构建检查');

const htmlPath = resolve(ROOT, 'public/index.html');
const enginePath = resolve(ROOT, 'public/pcap-engine.mjs');
ok('B1 index.html 存在', existsSync(htmlPath));
ok('B2 pcap-engine.mjs 存在', existsSync(enginePath));
const html = readFileSync(htmlPath, 'utf8');
ok('B3 引入引擎 ESM', /<script type="module">\s*import[^]*reviewPcap/.test(html));
for (const needle of ['pcap', 'srcIp', 'dstIp', 'srcPort', 'dstPort', '发起复核', '清空草稿']) {
  ok(`B4 页面包含 ${needle}`, html.includes(needle));
}
for (const needle of ['首个原始包号', '帧内偏移', '冲突', '长度前缀', '包号']) {
  ok(`B5 结果/错误展示含 ${needle}`, html.includes(needle));
}
ok('B6 清空逻辑会清掉旧结论', /function clearAll[\s\S]*verdict/.test(html) ||
  /清空草稿[\s\S]*clearAll/.test(html));

/* ================================================================ */
console.log('\n[C] HTTP 冒烟');

function freePort() {
  return new Promise((res, rej) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const p = srv.address().port;
      srv.close(() => res(p));
    });
    srv.on('error', rej);
  });
}

async function httpGet(port, path) {
  const res = await fetch(`http://127.0.0.1:${port}${path}`);
  const body = await res.text();
  return { status: res.status, body, headers: res.headers };
}

async function smoke() {
  // 确保样例存在（verify 容器内重新生成，避免漏提交）
  execFileSync(process.execPath, [resolve(__dirname, 'generate-sample.mjs')], { stdio: 'inherit' });

  const port = await freePort();
  const child = spawn(process.execPath, [resolve(ROOT, 'server.mjs')], {
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (d) => process.stdout.write(`[server] ${d}`));
  child.stderr.on('data', (d) => process.stderr.write(`[server] ${d}`));

  const waitFor = async (ms) => new Promise((r) => setTimeout(r, ms));
  let up = false;
  for (let i = 0; i < 50; i++) {
    try { const r = await httpGet(port, '/healthz'); if (r.status === 200) { up = true; break; } }
    catch { await waitFor(100); }
  }
  ok('C1 服务可启动', up);

  if (up) {
    const h = await httpGet(port, '/healthz');
    ok('C2 /healthz 200', h.status === 200);
    try { const j = JSON.parse(h.body); ok('C3 /healthz 返回 status ok', j.status === 'ok'); }
    catch { ok('C3 /healthz JSON', false, h.body); }

    const idx = await httpGet(port, '/');
    ok('C4 / 200 且为 HTML', idx.status === 200 &&
      idx.headers.get('content-type').includes('text/html'));
    ok('C5 页面含标题与复核按钮', idx.body.includes('TCP 指令流复核') &&
      idx.body.includes('发起复核'));

    const eng = await httpGet(port, '/pcap-engine.mjs');
    ok('C6 引擎脚本可下载', eng.status === 200 &&
      eng.headers.get('content-type').includes('javascript'));
    ok('C7 引擎脚本含导出', eng.body.includes('export function reviewPcap'));

    const sample = await httpGet(port, '/samples/avionics-capture.b64');
    ok('C8 样例文件经 HTTP 可取', sample.status === 200 && sample.body.length > 0);

    // 端到端：HTTP 取回的样例必须能被同一份引擎复核通过
    try {
      const r = reviewPcap(sample.body, FLOW);
      ok('C9 HTTP 样例经引擎复核成功', r.ok && r.commands.length === 3);
    } catch (e) {
      ok('C9 HTTP 样例经引擎复核成功', false, e.message);
    }

    const nf = await httpGet(port, '/../server.mjs');
    ok('C10 路径逃逸被拦截（403/404）', nf.status === 403 || nf.status === 404);
  }

  child.kill('SIGTERM');
  await new Promise((r) => child.on('exit', r));
}

await smoke();

/* ================================================================ */
console.log(`\n${'=' .repeat(60)}`);
console.log(`通过 ${passed} 项；失败 ${failures.length} 项`);
if (failures.length) {
  console.log('\n失败项：');
  for (const f of failures) console.log('  - ' + f);
  process.exit(1);
}
console.log('verify 全部通过。');
process.exit(0);
