import { analyze, AnalysisError, LIMITS } from '/lib/analyze.js';

const $ = (id) => document.getElementById(id);
const pcapEl = $('pcap');
const meter = $('size-meter');
const resultEl = $('result');
const btnVerify = $('btn-verify');
const btnClear = $('btn-clear');

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function updateMeter() {
  const len = pcapEl.value.length;
  meter.textContent = `${len} / ${LIMITS.MAX_BASE64_BYTES} 字节`;
  meter.classList.toggle('over', len > LIMITS.MAX_BASE64_BYTES);
}

function clearConclusion() {
  // 任何新的复核开始前，先彻底清除上一条结论（绝不让旧结论与新错误并存）
  resultEl.className = 'card hidden';
  resultEl.textContent = '';
}

function renderError(err) {
  const e = err instanceof AnalysisError ? err.toJSON() : {
    code: 'UNKNOWN',
    message: String(err && err.message ? err.message : err),
    packet: null, packet2: null, offset: null, range: null,
  };
  const loc = [];
  loc.push(`定位首个原始包号 : ${e.packet ?? '—'}`);
  if (e.packet2 != null) loc.push(`冲突对端包号     : ${e.packet2}`);
  if (e.offset != null) loc.push(`字节偏移         : ${e.offset}`);
  if (e.range) loc.push(`冲突区间 [起,止) : [${e.range[0]}, ${e.range[1]})  长度 ${e.range[1] - e.range[0]}`);
  if (e.fragmentPackets) loc.push(`该组分片已到包号 : ${e.fragmentPackets.join(', ')}`);
  resultEl.innerHTML = `
    <div class="banner bad">
      <div><span class="code">${esc(e.code)}</span>复核不通过——已拒绝输出指令流，旧结论已清除。</div>
      <p class="meta">${esc(e.message)}</p>
      <div class="locate">${esc(loc.join('\n'))}</div>
    </div>`;
  resultEl.className = 'card';
}

function renderOk(r) {
  const rows = r.commands.map((c) => `
    <tr>
      <td class="mono">${c.index + 1}</td>
      <td class="mono cmd-text">${esc(c.text)}</td>
      <td class="mono">${c.length}</td>
      <td class="mono">[${c.byteRange[0]}, ${c.byteRange[1]})</td>
      <td class="mono">[${c.payloadRange[0]}, ${c.payloadRange[1]})</td>
      <td class="mono pkt-list">${c.packets.map((p) => `#${p}`).join(', ')}</td>
    </tr>`).join('');
  resultEl.innerHTML = `
    <div class="banner ok">
      <div>✓ 复核通过：已按序重建 ${r.commands.length} 条长度前缀 ASCII 指令（FIN 前连续字节，无空洞、无冲突）</div>
      <p class="meta">
        五元组 ${esc(r.tuple.srcIp)}:${r.tuple.srcPort} → ${esc(r.tuple.dstIp)}:${r.tuple.dstPort} ·
        ISN 0x${(r.isn >>> 0).toString(16).padStart(8, '0')}（SYN 包 #${r.synPacket}）·
        FIN 包 #${r.finPacket} · 有效流 ${r.streamLength} 字节 ·
        捕获共 ${r.packetCount} 包，相关重组 IP 数据报 ${r.datagramCount} 个
      </p>
    </div>
    <table>
      <thead>
        <tr>
          <th>#</th><th>重建指令（ASCII）</th><th>载荷长度</th>
          <th class="mono">流内字节区间[起,止)<br><span style="font-weight:400">含 2 字节长度前缀</span></th>
          <th class="mono">载荷区间[起,止)</th>
          <th>对应原始包号</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
  resultEl.className = 'card';
}

function runVerify() {
  clearConclusion();
  const input = {
    srcIp: $('srcIp').value,
    srcPort: $('srcPort').value,
    dstIp: $('dstIp').value,
    dstPort: $('dstPort').value,
    pcapBase64: pcapEl.value,
  };
  try {
    if (pcapEl.value.length > LIMITS.MAX_BASE64_BYTES) {
      // 与服务端一致的硬性上限，超限不得发起
      throw new AnalysisError('TOO_LARGE',
        `Base64 输入 ${pcapEl.value.length} 字节，超过 ${LIMITS.MAX_BASE64_BYTES} 字节（256 KiB）上限`,
        { extra: { size: pcapEl.value.length, limit: LIMITS.MAX_BASE64_BYTES } });
    }
    const result = analyze(input);
    renderOk(result);
  } catch (err) {
    renderError(err);
  }
}

btnVerify.addEventListener('click', runVerify);
btnClear.addEventListener('click', () => {
  pcapEl.value = '';
  clearConclusion();
  updateMeter();
  pcapEl.focus();
});
pcapEl.addEventListener('input', updateMeter);

// 载入本题捕获样例（经 HTTP 拉取 manifest 与 base64，并回填五元组）
async function loadSample(kind) {
  clearConclusion();
  try {
    const [m, b] = await Promise.all([
      fetch('/samples/manifest.json').then((r) => r.json()),
      fetch(`/samples/${kind === 'good' ? 'good' : 'conflict'}.pcap.b64`).then((r) => r.text()),
    ]);
    $('srcIp').value = m.tuple.srcIp;
    $('srcPort').value = m.tuple.srcPort;
    $('dstIp').value = m.tuple.dstIp;
    $('dstPort').value = m.tuple.dstPort;
    pcapEl.value = b;
    updateMeter();
  } catch (e) {
    renderError(new AnalysisError('SAMPLE_LOAD', `样例加载失败：${e.message}`));
  }
}
document.getElementById('btn-sample-good').addEventListener('click', () => loadSample('good'));
document.getElementById('btn-sample-conflict').addEventListener('click', () => loadSample('conflict'));

updateMeter();
