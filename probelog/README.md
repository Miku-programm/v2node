# 探测日志（ProbeLog）

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
  - `correction`：`final` 之后迟到的 access 记录改变了认证结论时输出的完整行（`flow_end=late_auth`）
- **`event_id`** = `flow_id-revision`（其他事件为随机值），用于去重。
- 没看到 SYN 的 TCP 连接（记录器启动前建立的，或空闲回收后又有数据）只跟踪、不上报，数量见 `stats.midstream_flows`。这会漏掉 SYN 丢失的连接。

### `flow_end`（记录生成原因）

| 值 | 含义 |
|---|---|
| `closed` | 观察到了 FIN/RST，等待 2 秒（双向 FIN、RST，或 inbound 模式下的客户端 FIN）或 10 秒（只看到单向 FIN）后输出；具体方向见 `close_by` |
| `no_data_timeout` | 只有 SYN、30 秒没有数据，采集器回收。不是观测到的服务端超时 |
| `idle_timeout` | TCP 15 分钟（UDP 30 秒）没有可观察的包，采集器回收 |
| `superseded` | 同一五元组出现了新 ISN 的 SYN |
| `shutdown` | 记录器停止（进程退出或热重载） |
| `open` / `late_auth` | 快照 / 迟到修订 |

### `close_by`、`handshake`

- `close_by`：`client_fin` / `client_rst` / `server_fin` / `server_rst` / `both_fin` / `none`。只表示采集器看到了哪个方向的 FIN/RST，不能单凭方向确定实际发送主体（例如链路上注入的 RST）。FIN 也可能只关闭一个方向。
- `handshake`：`syn_only`（只看到客户端 SYN）、`synack`（看到节点 SYN-ACK，需要 control/full）、`established`（客户端 ACK 了节点 ISN，或客户端已发数据或 FIN）、`unknown`（inbound 模式下证据不足）。
- `flow_ms` = 最后一个入站包时间 − 首个入站包时间；`flow_pkts` / `flow_bytes` 只统计入站数据包。都不包含回收前的等待时间。

## 载荷字段

| 字段 | 含义 |
|---|---|
| `payload_len` / `payload_cap_len` / `payload_truncated` | 首个**到达**的数据段的原始长度 / 实际捕获长度 / 是否被截断 |
| `payload_head` / `payload_hash` / `entropy` / `printable` | 只基于首段实际捕获的字节。不是完整应用消息；同样的字节流分段不同时哈希也不同 |
| `prefix_len` / `prefix_hash` | 按 TCP 序列号重组后的**连续**客户端字节流前缀（最多 4096 字节）及其 sha256 前 8 字节。比较时必须连同 `prefix_len`。相同只说明候选匹配，不能证明来源身份或重放因果 |
| `reasm_flags` | `gap`（后面有数据但中间缺字节）、`conflict`（重叠段内容不一致，保留先到的字节——不一定是服务端协议栈实际采用的字节）、`overflow`（乱序队列或前缀达到上限）、`truncated`（有段因捕获长度丢了尾部）、`retrans`（收到内容一致的重复数据） |
| `tls_state` | `complete` / `not_client_hello` / `malformed` / `incomplete`（结束、超时 2 秒或到达上限时仍没收齐）。**只有 `complete` 时 `tls_*`、`ja3`、`ja4` 才填写**；跨多个 TLS record 的 ClientHello 会拼起来解析 |
| `first_data_ms` | SYN 到首个数据段的毫秒数 |
| `out_pkts` / `out_bytes` / `first_resp_ms` / `resp_records` | 仅 `full` 模式：节点方向的数据包统计、SYN 到节点首个数据段的毫秒数、节点响应前 8 个 TLS record 的 `类型:长度` |

**截断**：入站带数据的包每包最多捕获 2048 字节（含 IP/TCP 头），`full` 模式的出站数据包 1024 字节。截断通过 IP 长度字段和内核报告的原始长度（`MSG_TRUNC`）检测，截断的段只放入实际捕获的字节，后续数据不会被拼到缺失位置。主机上看到的分段不一定等于线上的实际分段：GRO 会把多个入站段合并成大包（更容易被截断），出站在 TSO 分段前被捕获。

## 认证字段

| 字段 | 值 |
|---|---|
| `auth` | `accepted` / `rejected`：关联到的 xray access 记录的状态（xray 实现中的 access 结果，不等于 REALITY 密码学握手成败）；`unknown`：没有关联到 access 记录——正常浏览器访问、健康检查、未完成的握手、日志缺失都会落在这里，**不等于认证失败，更不等于主动探测**；`not_applicable`：非节点端口（如 SSH） |
| `auth_assoc` | `matched`（唯一匹配）/ `unmatched` / `ambiguous`（同一来源 ip:port 有多个候选连接，没有传播认证结果）/ `not_applicable` |

xray access 记录只带来源地址，不带入站目标，所以按“来源 ip:port + 时间窗”在候选连接里匹配：

- 日志比抓包先到：日志最多保留 10 秒，等连接出现后应用（`stats.pending_logs_expired` 为一直没等到的数量）
- 连接已输出 `final` 后 2 秒内的迟到日志：输出 `correction`
- 同一来源端口的旧连接结束 2 秒后，日志不会再匹配旧连接，避免污染端口复用后的新连接
- 有多个候选时标记 `ambiguous`，不把结果传播给任何一个

## 采样与限速

- `AuthedSampleRate`：已认证连接按 `flow_id` 稳定采样，同一连接的所有记录取舍一致；一个连接一旦输出过记录（例如快照时认证还是 `unknown`），之后的记录都会输出，不会只剩快照。
- `MaxEventsPerSec` / `MaxPerSourceSec`：按处理时间计算的每秒上限，只作用于每个连接的第一条记录和非连接事件；同一连接的后续记录不受限速，避免终态被丢掉。

## 数据质量统计（`kind=stats`）

`rate_dropped`、`sampled_out`、`sink_chan_dropped`、`sink_buffer_dropped`（各种主动丢弃）；`flow_table_full`；`midstream_flows`；`tls_incomplete`、`tls_malformed`；`reasm_conflict`、`reasm_overflow`、`cap_truncated`；`assoc_unmatched`、`assoc_ambiguous`、`pending_logs_dropped`、`pending_logs_expired`、`late_corrections`；`kernel_packets`、`kernel_drops`（来自 `PACKET_STATISTICS`，取不到时为 `"unavailable"`，**不是 0**）；`sink_schema`（启动时表结构检查结果）。

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
- 从 v1 升级：`clickhouse-client --multiquery < probelog/migrations/002_v2.sql`。**先升级表、再升级节点**：新版不再跳过未知字段，表结构落后时写入会直接失败，并在 `stats.sink_schema` 里列出缺少的列（旧版会静默丢掉新字段）。
- 查询示例（取每个连接的最新记录、区分新旧语义等）：`probelog/queries.sql`
- 去重：上传失败重试会发送完全相同的批次，表开启了 `non_replicated_deduplication_window`；查询时仍建议按 `flow_id` 取最大 `revision`、按 `event_id` 去重。
- 旧数据：`schema_version < 2` 的行是 v1 语义（以来源 ip:port 为流键、按到达顺序拼接、`auth=none` 只表示没关联到 access 记录、`flow_end=fin/rst` 只是观察到入站 FIN/RST），不要和新行混在一起解释。

## 分析面板（配套项目）

v2node 只负责采集和写入。查看和分析数据请配套使用 **[Miku-programm/probe-dashboard](https://github.com/Miku-programm/probe-dashboard)**，它按本目录 `schema.sql` 的表结构编写查询。修改表结构或字段含义时需要同步更新面板。也可以直接用 clickhouse-client 查询。
