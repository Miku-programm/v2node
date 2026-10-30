# 探测日志（ProbeLog）

> [!CAUTION]
> **仅用于蜜罐 / 探测研究节点，不可以在承载机场常规业务的节点上开启。** ProbeLog 会记录连接来源、TLS/QUIC 指纹、SNI 和首包内容并上传到 ClickHouse，用在真实用户的节点上等于采集用户的连接元数据。本仓库的 xray 内核固定为 v26.7.28，详见仓库根目录 README。

记录节点收到的扫端口、连接和认证相关行为，批量写入 ClickHouse。数据用配套项目 [probe-dashboard](https://github.com/Miku-programm/probe-dashboard) 读取分析，v2node 本身不包含面板。

**这里记录的是“观察到了什么”，不对来源、意图下结论。** 来源国家、SYN 扫描、`auth=unknown`、高熵载荷、相同 JA3/JA4 或相同前缀哈希，单独都不能说明是 GFW 探测；某条异常连接和之后节点不可达之间也不能直接当成因果。单个节点只能看到自己这一侧，要确认链路丢包或伪造 RST，还需要客户端侧的记录或受控实验。

## 数据来源

| 来源 | 内容 |
|---|---|
| 抓包（仅 Linux，需 root 或 `CAP_NET_RAW`） | 打到未监听端口的 SYN；到监听端口的每个连接实例；可选的节点→客户端控制包与响应 |
| xray 日志 | access 的 accepted / rejected 记录；含 REALITY / fallback / invalid 等关键字的日志（只是线索，没有连接标识，不关联到具体连接） |
| 节点端口注册 | 区分节点端口（`node`）、其他监听端口（`listen`，如 SSH）和关闭端口（`closed`） |

## 观测模式（`Direction`）

| 值 | 抓什么 | 开销 |
|---|---|---|
| `inbound` | 只抓入站：所有端口的纯 SYN；监听端口的 FIN/RST 和带数据的包 | 最低。看不到节点方向，`close_by` 只能是 `client_*` 或 `none` |
| `control`（默认） | 另抓节点发给客户端的 SYN-ACK / FIN / RST | 很小（每个连接几个包） |
| `full` | 另抓节点发给客户端的数据包（每包截 1024 字节） | 与下行流量成正比，只建议在测试节点或短时间开启 |

所有模式都**不抓纯 ACK**。节点主动发起的连接（如 REALITY 回落到 target、用户代理流量）源端口是临时端口，不会被当成客户端连接的反方向。UDP 只抓入站。

## 事件类型（`kind`）

| kind | 说明 |
|---|---|
| `syn` | 打到未监听端口的 SYN，带 TTL / IPID / 窗口 / TCP 选项 / TSval |
| `tcp_flow` | 到监听端口的一个 TCP 连接实例，可能有多条记录（见下） |
| `udp_flow` | 到节点 UDP 端口或低于 32768 端口的一个 UDP 流 |
| `icmp` | 入站 ICMP / ICMPv6 |
| `xray_access` | xray access 记录（accepted 按 `AuthedSampleRate` 随机采样，rejected 全记） |
| `xray_log` | 含关键字的 xray 日志 |
| `stats` | 采集器每分钟的计数，包括各种丢弃和质量问题 |

## 连接实例与记录

- **连接身份**：完整五元组（协议、客户端 IP:端口、节点 IP:端口），IPv4-mapped 地址统一成 IPv4。同一来源端口访问多个本地端口或本地地址，是不同的连接。
- **`flow_id`**：每个连接实例一个随机 ID。同一五元组上 ISN 相同的 SYN 算重传（`syn_retrans`）；ISN 不同的 SYN 结束旧实例（`flow_end=superseded`）并开始新实例；连接关闭后再连也是新实例。
- **记录类型 `record_type`**：同一 `flow_id` 可以有多条记录，按 `revision` 取最大的一条作为当前结论。
  - `snapshot`：连接持续 60 秒时的阶段快照（`flow_end=open`），只输出一次
  - `final`：连接结束或被回收时的汇总
  - `correction`：`final` 之后认证结论（`auth` 或 `auth_assoc`）发生变化时输出的完整行（`flow_end=late_auth`）：迟到的 access 记录、后来才发现的多候选歧义、或之后才处理到的候选让原来的唯一匹配不再唯一。结论没有变化时不输出；已输出的行不会被就地修改
- **`event_id`** = `flow_id-revision`（其他事件为随机值），用于去重。
- 没看到 SYN 的 TCP 连接（记录器启动前建立的，或空闲回收后又有数据）只跟踪、不上报，数量见 `stats.midstream_flows`。这会漏掉 SYN 丢失的连接。

### `flow_end`（记录生成原因）

| 值 | 含义 |
|---|---|
| `closed` | 观察到了 FIN/RST，等待 2 秒（双向 FIN、RST，或 inbound 模式下的客户端 FIN）或 10 秒（只看到单向 FIN）后输出；具体方向见 `close_by` |
| `no_data_timeout` | 只有 SYN、30 秒没有任何方向的数据，采集器回收。不是观测到的服务端超时 |
| `idle_timeout` | TCP 15 分钟（UDP 30 秒）任一方向都没有可观察的包，采集器回收。`full` 模式的下行数据会推迟回收；`inbound` 只看入站、`control` 只看节点控制包，单向长下载在这两种模式下仍可能被回收，这是观察能力的限制，不是网络事件 |
| `superseded` | 同一五元组出现了新 ISN 的 SYN |
| `shutdown` | 记录器停止（进程退出或热重载） |
| `open` / `late_auth` | 快照 / 迟到修订 |

### `close_by`、`handshake`

- `close_by`：`client_fin` / `client_rst` / `server_fin` / `server_rst` / `both_fin` / `none`。只表示采集器看到了哪个方向的 FIN/RST，不能单凭方向确定实际发送主体（例如链路上注入的 RST）。FIN 也可能只关闭一个方向。
- `handshake`：按证据等级给出，**不是完整的 TCP 状态机**（纯 ACK 不抓，TFO 等情形没有单独建模）。
  - `syn_only`：只看到客户端 SYN
  - `synack`：看到节点 SYN-ACK（需要 control/full），但没有可接受的客户端 ACK
  - `established`：核对过的证据——看到 SYN-ACK 之后，客户端数据/FIN 段的 ACK 可接受：等于节点 ISN+1，或在 `full` 模式下不超过节点已发送的序列号范围
  - `inferred`：推定——SYN 之后有带 ACK 标志的客户端数据/FIN，但 ACK 无法核对（`inbound` 看不到 SYN-ACK；`control` 看不到节点数据，ACK 大于 ISN+1 时可能确认了这些数据）。数据到达不代表被节点协议栈接收
  - `unknown`：inbound 模式下证据不足
- `hs_flags`：`bad_ack`（看到 SYN-ACK 后客户端段的 ACK 不可接受：早于 ISN+1，或 `full` 模式下超出节点已发送范围）、`no_ack`（SYN 之后的客户端数据/FIN 没有 ACK 标志）。这两种段都不算握手证据；之后若出现可接受的 ACK 仍会得到 `established`，标记保留。
- `flow_ms` = 最后一个入站包时间 − 首个入站包时间；`flow_pkts` / `flow_bytes` 只统计入站数据包。都不包含回收前的等待时间。回收计时（`idle_timeout`）另外按任一方向的最后一个可观察包计算，与 `flow_ms` 不同。

## 载荷字段

| 字段 | 含义 |
|---|---|
| `payload_len` / `payload_cap_len` / `payload_truncated` | 首个**到达**的数据段的原始长度 / 实际捕获长度 / 是否被截断 |
| `payload_head` / `payload_hash` / `entropy` / `printable` | 只基于首段实际捕获的字节。不是完整应用消息；同样的字节流分段不同时哈希也不同 |
| `prefix_len` / `prefix_hash` | 固定策略的客户端字节流前缀：按 TCP 序列号重组后的**连续**字节，从流的第 0 字节开始，最多 4096 字节，及其 sha256 前 8 字节。覆盖范围只由 `prefix_stop` 决定，与 TCP 如何分段、ClientHello 后面的数据是否同段到达无关。比较时必须连同 `prefix_len`；短前缀（例如只有几个字节）区分度很低，应按长度分层看，不要和长前缀的相等当成同样的证据。相同只说明候选匹配，不能证明来源身份或重放因果 |
| `prefix_stop` | 前缀采集结束的条件：`bytes`（前缀满 4096 字节且 TLS 判别已有结论，或重组缓存满 16 KiB）、`window`（首个数据段之后 2 秒，按包时间）、`flow_end`（窗口内连接就结束了）、`snapshot`（窗口内到了 60 秒快照）、`overflow`（乱序暂存达到上限）。TLS 判别结束（例如首字节就能判断“不是 ClientHello”）**不会**结束前缀采集。不同 `prefix_stop` 的前缀不保证覆盖同样的范围 |
| `reasm_flags` | `gap`（后面有数据但中间缺字节）、`conflict`（重叠段内容不一致）、`overflow`（乱序队列或前缀达到上限）、`truncated`（有段因捕获长度丢了尾部）、`retrans`（收到内容一致的重复数据）。**只描述 `prefix_stop` 之前的观察**：之后到达的客户端字节不再检查，空值不代表整条连接都没有重叠冲突。重叠采用“先到达的字节优先”：每个位置第一次收到的字节（无论当时是否已接上连续前缀）保留，之后的只用于比较。这是采集器的确定规则，不一定是节点协议栈实际采用的字节 |
| `tls_state` | `complete` / `not_client_hello` / `malformed` / `incomplete` / `conflict`。`malformed`：record 与 handshake 长度都齐了，但内部向量的声明长度与内容不符（越界、尾部多余、元素大小不对）或出现了其他记录；未知扩展按声明长度跳过，不算畸形。`incomplete`：前缀采集结束时仍没收齐（缺口、截断、超时、结束）。`conflict`：语法可以解析，但 ClientHello 所在字节范围内有内容不一致的重叠段，不输出指纹。**只有 `complete` 时 `tls_*`、`ja3`、`ja4` 才填写**；跨多个 TLS record 的 ClientHello 会拼起来解析。冲突只出现在 ClientHello 之后时仍是 `complete`，`reasm_flags` 保留 `conflict` |
| `first_data_ms` | SYN 到首个数据段的毫秒数 |
| `quic_initial` / `quic_sni_first` / `quic_initials` | 仅 `udp_flow`（v4 起）：解密 QUIC 客户端 Initial 的结果，见下节 |
| `out_pkts` / `out_bytes` / `first_resp_ms` / `resp_records` | 仅 `full` 模式：节点方向的数据包统计、SYN 到节点首个数据段的毫秒数、节点响应前 8 个 TLS record 的 `类型:长度` |

**截断**：入站带数据的包每包最多捕获 2048 字节（含 IP/TCP 头），`full` 模式的出站数据包 1024 字节。截断通过 IP 长度字段和内核报告的原始长度（`MSG_TRUNC`）检测，截断的段只放入实际捕获的字节，后续数据不会被拼到缺失位置。主机上看到的分段不一定等于线上的实际分段：GRO 会把多个入站段合并成大包（更容易被截断），出站在 TSO 分段前被捕获。

## QUIC 客户端 Initial（`udp_flow`）

QUIC Initial 包的密钥由公开的版本盐和客户端选的 Destination Connection ID 推导（RFC 9001 §5.2、RFC 9369），任何在路径上的观察者都能解密。GFW 自 2024 年 4 月起就是这样解密 Initial、按 SNI 封锁 QUIC 的（Zohaib et al., *Exposing and Circumventing SNI-based QUIC Censorship of the Great Firewall of China*, USENIX Security 2025）。采集器用同样的方法解析节点收到的客户端 Initial：

- 首个数据报以 QUIC 长包头开头的 UDP 流才解析；支持 v1 和 v2、同一数据报中合并的多个包、多个 CRYPTO 帧乱序。按 CRYPTO 偏移重组 ClientHello（重叠冲突时先到达的字节优先，`reasm_flags` 记录 CRYPTO 流的质量标记）
- 解析在 ClientHello 有结论、首个数据报 2 秒后、解析满 8 个数据报或流结束时停止
- ClientHello 写入 `tls_state` / `tls_sni` / `tls_alpn` / `ja3` / `ja4`（JA4 以 `q` 开头）等字段，规则与 TCP 相同：只有 `complete` 才填写指纹
- `quic_initial`：`ok`（至少一个 Initial 解密成功）、`unsupported_version`（不是 v1/v2，无法推导密钥）、`decrypt_failed`（AEAD 校验失败）、`truncated`（捕获截断）、`malformed`（包头或帧不合法）、`no_initial`（有长包头但没有客户端 Initial）
- `quic_sni_first`：SNI 主机名的字节有多少落在**第一个 UDP 数据报**的 CRYPTO 帧里——`full` / `partial` / `none` / `no_sni`。论文观察到 GFW 不跨数据报重组，`full` 是 GFW 能读到 SNI 的情形；`partial` / `none` 对应客户端做了 SNI 切片（Firefox 137+、quic-go v0.52+、sing-box / Xray / Hysteria 的新版本）或 ClientHello 本身跨数据报
- `quic_initials`：含有可解密客户端 Initial 的数据报数

与 GFW 规则相关的另外两个量可以直接从已有列算：论文中 GFW 只检查**源端口 > 目的端口**的包（`src_port > dst_port`），并按（客户端 IP、节点 IP、目的端口）封锁约 180 秒，期间只丢客户端→节点方向。所以在节点上，被封的连接表现为：客户端发来 Initial 后不再有入站包（`flow_pkts` 接近 `quic_initials`），同一客户端 IP 到同一端口约 3 分钟没有新的流。查询示例见 `queries.sql` 第 8 条。

这些只是**候选**：节点只能看到“包没到”，区分不了 GFW 封锁、链路丢包、客户端放弃或伪造源地址触发的封锁（论文第 6 节：从境内伪造 Initial 仍能让 GFW 封锁两个无关主机之间的 UDP）。确认需要境内对照测量。UDP 只抓入站，看不到节点的响应。

## 认证字段

| 字段 | 值 |
|---|---|
| `auth` | `accepted` / `rejected`：关联到的 xray access 记录的状态（xray 实现中的 access 结果，不等于 REALITY 密码学握手成败）；`unknown`：没有关联到 access 记录——正常浏览器访问、健康检查、未完成的握手、日志缺失都会落在这里，**不等于认证失败，更不等于主动探测**；`not_applicable`：非节点端口（如 SSH） |
| `auth_assoc` | `matched`（唯一匹配）/ `unmatched` / `ambiguous`（同一来源 ip:port 有多个候选连接，没有传播认证结果）/ `not_applicable` |

xray access 记录只带来源地址，不带入站目标（`m.To` 是业务目标，不是节点入站地址），所以按“来源 ip:port + 时间窗”在候选连接里匹配。结论不取决于日志与抓包谁先被处理：

- **候选**：同一来源 ip:port、节点端口、首次观察时间不晚于日志时间 + 2 秒、且没有在日志时间 2 秒之前就已结束的连接
- **候选窗口**：日志处理后先不绑定，等到日志时间 + 3 秒（2 秒候选范围 + 1 秒处理先后差）再看候选集合：唯一 → `matched`；多个 → `ambiguous`；还没有候选 → 继续等，最多 10 秒（`stats.pending_logs_expired` 为一直没等到的数量）。已经有多个候选时立即标记 `ambiguous`（再出现候选也不会变成唯一）
- 窗口内观察到关闭的连接会推迟输出 `final`（最多 3 秒），让 `final` 直接带上结论，减少 `correction`
- 已决定的日志保留 30 秒：之后才处理到的候选（抓包处理落后）会把原来的 `matched` 撤回为 `ambiguous`，`auth` 回到 `unknown`，已输出的连接发 `correction`
- 同一来源端口的旧连接结束 2 秒后，日志不会再匹配旧连接，避免污染端口复用后的新连接
- 有多个候选时标记 `ambiguous`，不把结果传播给任何一个；被另一条日志唯一匹配过的连接保持 `matched`
- 这仍是基于时间窗的推定，不是连接级标识。根本的改善需要 xray 日志携带入站本地地址/端口或连接 ID

## 采样与限速

- `AuthedSampleRate`：已认证连接按 `flow_id` 稳定采样，同一连接的所有记录取舍一致；一个连接一旦输出过记录（例如快照时认证还是 `unknown`），之后的记录都会输出，不会只剩快照。
- `MaxEventsPerSec` / `MaxPerSourceSec`：按处理时间计算的每秒上限，只作用于每个连接的第一条记录和非连接事件；同一连接的后续记录不受限速，避免终态被丢掉。

## 数据质量统计（`kind=stats`）

`rate_dropped`、`sampled_out`、`sink_chan_dropped`、`sink_buffer_dropped`（各种主动丢弃）；`flow_table_full`；`midstream_flows`；`tls_incomplete`、`tls_malformed`、`tls_conflict`；`quic_initials`（解密成功并完成解析的 QUIC 流数）；`reasm_conflict`、`reasm_overflow`、`cap_truncated`；`assoc_unmatched`、`assoc_ambiguous`、`pending_logs_dropped`、`pending_logs_expired`、`late_corrections`；`kernel_packets`、`kernel_drops`（来自 `PACKET_STATISTICS`，取不到时为 `"unavailable"`，**不是 0**）；`sink_schema`（启动时表结构检查结果）。

## 配置

```json
"ProbeLog": {
  "Enable": true,
  "NodeName": "us-sjc-1",
  "Interface": "eth0",
  "Capture": true,
  "Direction": "control",
  "ExtraPorts": [22],
  "GeoTags": ["cn"],
  "MaxEventsPerSec": 2000,
  "MaxPerSourceSec": 200,
  "PayloadHeadBytes": 64,
  "AuthedSampleRate": 1,
  "XrayLogLevel": "info",
  "LocalFile": "",
  "ClickHouse": {
    "URL": "https://ch.example.com:8443",
    "Database": "v2node",
    "Table": "probe_events",
    "Username": "v2node_writer",
    "Password": "******",
    "BatchSize": 2000,
    "FlushInterval": 5,
    "BufferSize": 200000,
    "Timeout": 15
  }
}
```

- `Interface`：建议指定外网网卡。不指定时抓所有非回环网卡，有网桥/隧道时同一个包可能被看到两次。
- `XrayLogLevel`：采集 xray 日志的级别，REALITY 无效连接日志是 info 级；不影响屏幕和文件日志。
- `LocalFile`：同时写一份 JSONL 到本地文件。
- `BufferSize`：ClickHouse 不可用时内存中最多保留的事件数，超出丢最旧的批次。

## ClickHouse

- 新安装：`clickhouse-client --multiquery < probelog/schema.sql`
- 从 v1 升级：依次执行 `migrations/002_v2.sql`、`003_v3.sql`、`004_quic.sql`；从 v2 升级：执行 `003_v3.sql`、`004_quic.sql`；从 v3 升级：只执行 `004_quic.sql`。**先升级表、再升级节点**：节点不跳过未知字段，表结构落后时写入会直接失败，并在 `stats.sink_schema` 里列出缺少的列。
- 查询示例（取每个连接的最新记录、区分新旧语义等）：`probelog/queries.sql`
- 去重：上传失败重试会发送完全相同的批次，表开启了 `non_replicated_deduplication_window`；查询时仍建议按 `flow_id` 取最大 `revision`、按 `event_id` 去重。
- v2 行（`schema_version = 2`）与 v3 的差异，不要混在一起比较：非 TLS 前缀在首字节判断后就停止采集（长度取决于分段，没有 `prefix_stop`）；`tls_state=complete` 可能包含 ClientHello 内的重叠冲突和漏检的内部长度错误；`handshake=established` 只要有客户端数据或 FIN 就会给出（v3 中多为 `inferred`）；日志先到时会绑定第一个出现的连接，final 后的歧义没有 correction；`full` 模式下按入站包计时回收。旧行不会自动获得新语义保证。
- 旧数据：`schema_version < 2` 的行是 v1 语义（以来源 ip:port 为流键、按到达顺序拼接、`auth=none` 只表示没关联到 access 记录、`flow_end=fin/rst` 只是观察到入站 FIN/RST），不要和新行混在一起解释。

## 可比较样本的统一门槛

`queries.sql` 和面板使用同一套条件（新的比较查询也应沿用）：

- TLS 指纹：`schema_version >= 3 AND tls_state = 'complete'`。`conflict` / `malformed` / `incomplete` 不进入指纹统计
- 前缀：`schema_version >= 3 AND prefix_hash != '' AND reasm_flags NOT LIKE '%conflict%'`，按 `(prefix_len, prefix_hash)` 分组；需要时再按 `prefix_stop` 分层。`gap` / `truncated` 不破坏已采集的连续字节，只说明前缀比实际到达的数据短，因此不排除，但 `prefix_len` 会不同
- 握手：`handshake = 'established'` 才是核对过的证据，`inferred` 只是推定

## 分析面板（配套项目）

v2node 只负责采集和写入。查看和分析数据请配套使用 **[Miku-programm/probe-dashboard](https://github.com/Miku-programm/probe-dashboard)**，它按本目录 `schema.sql` 的表结构编写查询。修改表结构或字段含义时需要同步更新面板。也可以直接用 clickhouse-client 查询。
