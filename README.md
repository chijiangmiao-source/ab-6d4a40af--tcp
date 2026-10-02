# 断续链路 TCP 指令流复核（航电地面站）

审查员粘贴 **Base64 classic PCAP（≤ 256 KiB，Ethernet II 链路层）**、填写受检 **TCP 五元组**后发起复核。
页面在浏览器本地完成全链路重组，展示**按序重建的长度前缀 ASCII 指令**及每条指令对应的**原始包号与流内字节区间**；
任何可疑情形都**清空旧结论并定位首个原始包号、偏移与冲突区间，绝不二选一继续输出**。

## 复核规则（全部在 `lib/` 中实现，浏览器与 verify 共用同一份同构 ESM）

1. **Base64 classic**：只接受 `A-Za-z0-9+/` 与规范 `=` 填充（允许夹带空白）；拒绝 URL-safe 字符、错误填充、尾组携带非零置位位；硬上限 256 KiB。
2. **classic PCAP 容器**：两种字节序的微秒/纳秒魔数，拒绝 pcapng、截断记录与 `origLen > inclLen` 的抓包截断包。
3. **仅接受 Ethernet II / IPv4 / TCP**：拒绝 802.3 长度型帧；支持 802.1Q/QinQ 与以太网填充；识别 IP/TCP 选项（按 IHL/数据偏移取值）。
4. **先核对 IPv4 头校验和**：错误即作废该包，不得参与重组。
5. **IP 分片重组**：按 `(源, 目的, 协议, 标识)` 分组，乱序安放；缺末片、中间空洞、同偏移重叠字节不一致 → `MISSING_FRAGMENT` / `FRAGMENT_CONFLICT`。
6. **TCP 流重组（受检方向）**：
   - 必须有 **SYN**，以其序号确定 ISN，数据流自 ISN+1 开始；两个 SYN 序号不一致即拒绝；
   - 乱序段按 32 位序号安放，序号差按模 2³² 折算，正确处理**回绕**；
   - 重叠区间逐字节比较：相同 = 重传，接受；**不同 = 冲突，整体拒绝**，定位两个原始包号、流内偏移与冲突半开区间；
   - **FIN 前字节必须自 0 连续**，存在空洞（`STREAM_HOLE`）或缺 SYN/FIN 一律拒绝。
7. **指令解析**：`[2 字节大端长度 n][n 字节可见 ASCII 载荷]`；长度必须恰好覆盖完整载荷，非 ASCII、零长度、超长截断、**尾随残字节**（哪怕 1 字节）都拒绝。
8. 结论中每条指令给出：流内字节区间（含 2 字节前缀）、载荷区间、承载该指令的全部原始包号（跨 IP 分片/跨 TCP 段均可追溯）。

## 目录

```
lib/        同构核心（base64 / pcap / decode / ipdefrag / tcp / commands / analyze）
public/     静态页面（index.html、app.js、styles.css）与生成的 samples/
src/        Node 静态服务器（静态资源 + /healthz）
samples/    本题捕获样例生成器（good 与 conflict）
verify/     verify 服务：规则测试 + 页面构建检查 + HTTP 冒烟（一次性、退出码收尾）
```

## 本地运行（Node ≥ 18）

```bash
npm run gensamples          # 生成 public/samples/{good,conflict}.pcap.b64 与 manifest.json
npm start                   # 默认 8080，可用 PORT=xxxx 覆盖
# 打开 http://localhost:8080/，可点“载入通过样例 / 载入冲突样例”直接体验
npm run verify              # 80+ 项规则测试 + 页面构建 + 自启服务 HTTP 冒烟
```

## Compose

宿主端口可配置（默认 8080）：

```bash
HOST_PORT=9090 docker compose build
docker compose up app            # 静态页面 + 健康响应
docker compose run --rm verify   # 一次性复核服务：规则测试/页面构建/HTTP 冒烟，退出码结束
```

- `app`：对外提供静态页面与 `GET /healthz`（返回 `{"status":"ok"}`），带健康检查。
- `verify`：等待 `app` 健康后，经 Compose 网络访问 `http://app:8080` 做健康端点与本题 good/conflict 样例的 HTTP 冒烟；成功退出码 0，失败 1，`restart: "no"`。

## 错误码

`BAD_BASE64`、`TOO_LARGE`、`BAD_PCAP(_MAGIC)`、`TRUNCATED_CAPTURE`、`UNSUPPORTED_LINKTYPE`、
`TRUNCATED_FRAME`、`TRUNCATED_PACKET`、`NOT_IPV4`、`BAD_IP_HEADER`、`IP_CHECKSUM`、
`MISSING_FRAGMENT`、`FRAGMENT_CONFLICT`、`BAD_TCP_HEADER`、`NO_SYN`、`NO_FIN`、
`STREAM_HOLE`、`CONFLICT`、`TRUNCATED_COMMAND`、`TRAILING_BYTES`、`NON_ASCII`、
`INVALID_COMMAND`、`BAD_TUPLE`、`NO_MATCH`、`EMPTY_STREAM`。
