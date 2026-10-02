# 航电地面站 · 断续链路 TCP 指令流复核

审查员把断续链路捕获（**Base64 classic PCAP，粘贴文本 ≤ 256 KiB**）粘贴进页面，
填写**受检 TCP 五元组**后发起复核；页面按序重建 **两字节大端长度前缀 + ASCII 载荷**
的指令，并给出每条指令对应的**原始包号、流字节区间、TCP 序号区间与帧偏移**。

复核纯在浏览器本地完成（零依赖 ESM），服务端只提供静态页面与健康响应。

## 判定规则（全部在 `public/pcap-engine.mjs`）

1. **格式白名单**：classic PCAP（libpcap，拒绝 pcapng）；链路层仅 Ethernet II
   （拒绝 802.3 长度帧、VLAN 标签与其他 EtherType），网络层仅 IPv4，传输层仅 TCP；
   抓包截断（`incl_len < orig_len`）、记录截断一律拒绝。
2. **IPv4 头校验和**：逐包反码求和核对，不为 0 即失败，定位到帧偏移 24（校验字段）。
3. **IP 分片重组**：按 `<源地址, 目的地址, 协议, 标识>` 归组，MF/片偏移判首尾；
   缺尾片、空洞、任何交叠都失败。重组后逐字节保留属主（来自哪一个原始分片、帧偏移多少）。
4. **TCP 五元组带方向**挑段；以 **SYN 的 ISN** 锚定起始序号：
   - 乱序段按序号重排；
   - 32 位序号回绕：以当前水位就近解绕（ISN 邻近 `0xFFFFFFFF` 的用例见测试 A6 与样例）；
   - 覆盖同一序号的段：字节完全相同视为重传（接受、归属首见包），
     **只要有一个字节不同即整批复核失败**，给出首个原始包号、帧偏移与冲突区间，
     绝不择一继续；
   - 缺失起始 SYN、流内空洞、FIN 后数据同样失败；
   - 有效流严格以 **FIN 前的连续字节**为准（无 FIN 不出结论）。
5. **指令切分**：两字节大端长度必须**恰好**覆盖完整可打印 ASCII（`0x20..0x7e`）载荷；
   长度越界、非 ASCII、流尾残字节（1 字节也拒绝）均失败。

任何失败都会先**作废旧结论**，再展示首个原始包号、偏移与冲突/缺失区间。

## 运行

```bash
# 可配置宿主端口（默认 8080）
HOST_PORT=8080 docker compose up --build web
# 打开 http://localhost:8080/

# 一次性复核服务：重组规则测试 + 页面构建检查 + HTTP 冒烟，结束即退出（0/1）
docker compose run --rm verify
```

无 Docker 时（Node ≥ 20）：

```bash
npm start                 # PORT=8080 node server.mjs
npm run verify            # 80 项：重组规则 54 + 页面构建 16 + HTTP 冒烟 10
node verify/generate-sample.mjs   # （重新）生成本题捕获样例
```

健康检查：`GET /healthz` → `200 {"status":"ok",...}`。

页面右上角 **“填入本题样例”** 会加载
`public/samples/avionics-capture.b64` 并填好五元组
（`10.0.0.10:40123 → 10.0.0.20:5010/TCP`）。样例刻意包含：

- ISN=`0xFFFFFFFA`，数据跨越 32 位回绕点；
- 数据段乱序到达；
- 首段被拆成两个 IPv4 分片且**分片本身乱序**；
- 首段一次内容完全相同的重传；
- FIN 终结，共 3 条指令。

## 目录

| 路径 | 说明 |
| --- | --- |
| `public/index.html` | 复核页面（粘贴、五元组、发起复核/清空草稿、结论与定位） |
| `public/pcap-engine.mjs` | 浏览器/Node 共用的解析重组引擎（零依赖 ESM） |
| `public/samples/avionics-capture.b64` | 本题捕获样例（可重新生成） |
| `server.mjs` | 静态服务 + `/healthz`，端口取 `PORT` |
| `verify/verify.mjs` | 一次性 verify：规则测试、页面构建、HTTP 冒烟 |
| `verify/pcap-builder.mjs` | 测试用 PCAP/分片构造器 |
| `verify/generate-sample.mjs` | 样例生成器 |
| `Dockerfile` / `docker-compose.yml` | web 服务与一次性 verify 服务 |
