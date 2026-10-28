# ProbeLog 数据正确性修复：交付说明

- 对应交接文档：`v2node-probelog-claude-handoff.md`（审查基线 `e747e7c`）
- v2node 分支：`fix/probelog-accuracy`（基于 `e747e7c`，未提交、未推送）
- probe-dashboard：工作目录已修改（未提交、未推送）
- 本轮目标是让采集结果准确表达“观察到了什么”。**修复后不能识别 GFW**，也不能单凭任何一个字段把连接归为主动探测。

## 1. 问题重新核对

开始时 HEAD 就是 `e747e7c`，工作树除未跟踪的 `docs/` 外是干净的。逐项对照源码，交接文档列出的问题在这个版本中**全部存在**，没有已被修复的项：

| # | 问题 | 在 e747e7c 中的情况 | 本轮处理 |
|---|---|---|---|
| 1 | 流键只有 `(udp, 源 ip:port)` | 确认：`flowKey{udp, src}`；`markAuth` 同样只按来源查找 | 已修复 |
| 2 | 载荷按到达顺序拼接；`clientHelloNeed` 对 1–4 字节返回 -1 被当成结束 | 确认：`f.buf = append(...)`；`need < 0` 即 `finalizePayload` | 已修复 |
| 2b | 首段哈希被当作流内容；截断不可见 | 确认：`payload_hash` 来自首个捕获段；`snapPayload` 截断无标记 | 已修复（语义拆分 + 截断检测） |
| 3 | `auth=none` = 没关联到；日志先到、流先结束无补关联 | 确认：`markAuth` 找不到流直接忽略；`finish` 写 `none` | 已修复 |
| 4 | 只抓入站，无法区分关闭方向 | 确认（设计能力缺口，不是 bug） | 已增加 `control` / `full` 模式 |
| 5 | 60 秒 `open` 后不再输出终态 | 确认：`emitted=true` 后 FIN/回收都不再输出 | 已修复 |
| 待复核 | `emit()` 用事件时间限速 | 确认：`limit.allow(e.SrcIP, e.Time)`，延迟输出的汇总会落到历史秒窗口 | 已改为处理时间；连接后续记录不受限速 |
| 待复核 | 无 SYN 的 TCP 流不上报 | 确认 | 保留策略，增加 `midstream_flows` 计数与文档说明 |
| 实现约束 | 入队后修改 `*Event` | 当前实现没有发现这种用法（每条流只输出一次），但引入快照后会出现 | 每次输出前复制一份（`buildRecord`），测试验证快照未被后续修改 |

## 2. 采集器修改

改动全部在 `probelog/` 和 `conf/conf.go`（新增 `Direction`）。

### 2.1 连接身份与生命周期（`flow.go`）

- `flowKey{proto, client AddrPort, server AddrPort}`：完整五元组，统一“客户端→节点”方向，IPv4-mapped 地址规范化。
- 每个连接实例生成随机 `flow_id`。同一五元组上：ISN 相同的 SYN 计为 `syn_retrans`；ISN 不同的 SYN 以 `flow_end=superseded` 结束旧实例并开始新实例；关闭后再连是新实例。
- 出站包（节点→客户端）反转后查同一个连接，方向分别计数，不会重复计数。节点主动发起的连接（REALITY 回落 target 等）源端口是临时端口，被 BPF 排除，不会被并入客户端连接。

### 2.2 有界重组、TLS 完整性、截断（`reasm.go`、`tls.go`、`parse.go`、`bpf.go`、`capture_linux.go`）

- `reassembler`：按序列号（int32 差值处理回绕）重组从 ISN+1 开始的连续前缀；处理乱序、重传、相同内容重叠、内容冲突（保留先到字节并标 `conflict`，文档说明不一定是服务端实际采用的字节）、缺口。上限：客户端前缀 16 KB、乱序 64 段 / 64 KB，超出标 `overflow`；首段到达后最多等 2 秒。
- `classifyClientHello` 返回 `need_more / not_client_hello / malformed / complete`，结束、超时或到上限时 `need_more` 转为 `incomplete`。跨多个 handshake record 拼接后解析；ClientHello 中间出现其他 record、扩展区有残留字节时判为 `malformed`。**只有 `complete` 才写 `tls_*`、`ja3`、`ja4`**。
- 字段语义拆分：首个到达段 `payload_len`（原始长度）/ `payload_cap_len` / `payload_truncated` / `payload_hash`；重组后前缀 `prefix_len` + `prefix_hash`（最多 4096 字节，sha256 前 8 字节）；`reasm_flags`。
- 截断检测：用 IP 长度字段，IP 长度为 0 时用 `recvfrom(MSG_TRUNC)` 返回的原始长度。截断段只放入实际捕获的字节，缺失部分留作缺口，后续数据不会拼到缺口位置。README 说明了 GRO/TSO 对分段的影响。

### 2.3 认证关联（`flow.go` `onAccess` / `applyAuth`，`event.go`）

- 字段分开：`auth`（`accepted` / `rejected` / `unknown` / `not_applicable`）与 `auth_assoc`（`matched` / `unmatched` / `ambiguous` / `not_applicable`）。不新增“探测分类”字段——采集器不做分类。
- 已核对 xray 分支（`gunzi-666/Xray-core`）：VLESS 非 mux 请求在 `proxy/vless/inbound/inbound.go` 记录 `AccessAccepted`（From = 连接远端地址），被拒绝时在同文件记录 `AccessRejected`；mux 在 `common/mux/server.go` 记录。这是 xray 的 access 状态，README 明确不等于 REALITY 握手成败。
- 关联按“来源 ip:port + 时间窗”在候选连接中进行：日志先到时最多保留 10 秒等连接出现；连接 `final` 后 2 秒内的迟到日志输出 `correction`；旧连接结束 2 秒后不再作为候选，避免污染端口复用的新连接；多个候选时标 `ambiguous`，不传播结果。
- 非节点端口（如 SSH）为 `not_applicable`。

### 2.4 双向观测（`bpf.go`、`capture_linux.go`、`flow.go`）

- `Direction`：`inbound`（旧行为）、`control`（默认，另抓节点发出的 SYN-ACK/FIN/RST）、`full`（另抓节点发出的数据包，截 1024 字节）。
- 新字段：`close_by`、`handshake`、`obs_mode`；`full` 模式另有 `out_pkts`、`out_bytes`、`first_resp_ms`、`resp_records`（节点响应前 8 个 TLS record 的 `类型:长度`，同样经过重组）。
- 不抓纯 ACK。`handshake=established` 的依据是客户端 ACK 了节点 ISN（需 control/full），或客户端已发数据或 FIN；README 写明了依据。

### 2.5 快照、终态、修订（`flow.go`、`recorder.go`）

- `record_type` = `snapshot`（60 秒，一次）/ `final` / `correction`，`revision` 单调递增，`event_id = flow_id-revision`。
- `flow_end` 改为记录生成原因：`closed`、`no_data_timeout`、`idle_timeout`、`superseded`、`shutdown`、`open`、`late_auth`；空闲回收和进程退出不会伪装成 FIN/RST（方向看 `close_by`）。
- 采样按 `flow_id` 稳定：一开始就已认证的连接整条取舍一致；一旦输出过记录，后续记录都输出。

### 2.6 其他

- `emit` 加 `schema_version=2`、`event_id`、`emitted_at`；限速改用处理时间。
- sink 去掉 `input_format_skip_unknown_fields`：表结构落后时写入会明确失败；启动时查询 `system.columns` 核对列，结果放进 `stats.sink_schema`。
- 新增 stats：`flow_table_full`、`midstream_flows`、`tls_incomplete`、`tls_malformed`、`reasm_conflict`、`reasm_overflow`、`cap_truncated`、`assoc_unmatched`、`assoc_ambiguous`、`pending_logs_dropped`、`pending_logs_expired`、`late_corrections`、`kernel_packets` / `kernel_drops`（`PACKET_STATISTICS`，取不到时为 `"unavailable"` 而不是 0）。

## 3. ClickHouse

| 文件 | 内容 |
|---|---|
| `probelog/schema.sql` | 新安装建表（v2），加 `non_replicated_deduplication_window` 让重试的相同批次去重 |
| `probelog/migrations/002_v2.sql` | v1 → v2：`ADD COLUMN IF NOT EXISTS` 补齐新列、加索引、改设置；可重复执行。附旧行语义说明 |
| `probelog/queries.sql` | 示例：`flows_latest` 视图（按 `flow_id` 取最大 `revision`；v1 旧行用自身五元组+时间作键，不会被归并到同一个空 ID）、新旧语义区分、未关联认证连接、完整指纹比较、相同前缀候选、关闭方向、数据质量 |

旧行识别：`schema_version < 2`。v1 的 `auth=none`、`flow_end=fin/rst`、v1 指纹的语义都在迁移文件和 README 中说明，查询中不要和 v2 行混在一起解释。

**部署顺序：先执行迁移，再升级节点。**

## 4. probe-dashboard 兼容

已修改（未提交、未推送）：

- 所有连接统计先经过 `{F}` 去重子查询（每个 `flow_id` 取最大 `revision`）再计数；`overview`、`timeline`、`ports`、`geo` 拆成原始事件与连接两部分，避免快照重复计数。
- “未认证”改称“未关联认证”：`auth NOT IN ('accepted', 'not_applicable')`；探测相关页只看节点端口。
- SNI / JA4 只用 `tls_state = complete`（v1 旧行保留）。
- “重放检测”改为“相同客户端前缀”：v2 用 `prefix_len:prefix_hash` 并排除 `conflict`，v1 退回首段哈希；文案说明只是候选匹配。
- 明细与 IP 查询页新增 `flow_id`、`record_type`、`revision`、`auth_assoc`、`tls_state`、`prefix_len`、`reasm_flags`、`close_by`、`handshake`、`first_resp_ms`、`resp_records`、`obs_mode` 等列；采集状态页显示所有新质量计数和 `sink_schema`。
- README 增加版本对应说明：需要 v2 表，旧表先迁移。

## 5. 验证

| 命令 / 方式 | 结果 |
|---|---|
| `GOEXPERIMENT=jsonv2 go test ./probelog/`（Windows） | **通过** |
| `GOEXPERIMENT=jsonv2 CGO_ENABLED=1 go test -race ./probelog/`（Windows） | **通过** |
| `GOOS=linux go vet ./probelog/ ./conf/ ./core/ ./cmd/`、`GOOS=linux go build .` | **通过** |
| 真实内核抓包（WSL2 Ubuntu，root，`TestCaptureLive`，默认 `control` 模式） | **通过**：关闭端口 SYN；带 SNI 的 ClientHello → `tls_state=complete`、JA4；随机 221 字节 → `not_client_hello`；连上不发数据；三条连接都观察到节点 FIN（`close_by=both_fin`）和 `handshake=established` |
| probe-dashboard `go test .`、`go vet .`、`node --check static/app.js` | **通过** |
| Linux 上运行全部单元测试（交叉编译的测试二进制在 WSL2 Ubuntu 中执行） | **通过**：22 个测试全部 PASS |
| WSL 原生 `go test ./probelog/`（Go 1.27.1 linux/amd64） | **通过** |
| WSL 原生 `CGO_ENABLED=1 go test -race ./probelog/` | **通过** |
| `full` 模式真实抓包（WSL2，root，测试监听器回写 TLS record 形状的响应） | **通过**：`resp_records=22:4,20:1,23:3`、`out_pkts=1`、`out_bytes=23`、`first_resp_ms` 有值；一条 `close_by=both_fin`，一条 `client_rst` |
| 真实 ClickHouse 26.11（WSL 内独立测试实例，只监听 127.0.0.1）：新安装 `schema.sql` | **通过**：71 列；按 sink 同样的方式插入（gzip、JSONEachRow）成功；**同一批重复插入被去重**（行数不变）；sink 的表结构检查查询返回 71 列 |
| 真实 ClickHouse：v1 旧表 → `migrations/002_v2.sql` | **通过**：迁移连续执行两次都成功；迁移后 71 列；v1 旧行 `schema_version=0`，与新行并存 |
| 真实 ClickHouse：`queries.sql` 全部语句 | **通过**（两种表上都执行过）。`flows_latest` 每个连接一行：snapshot+final 只保留 final，correction 覆盖 final，v1 旧行各自一行 |
| probe-dashboard 18 个命名查询 + 自定义 SQL，连真实 ClickHouse | **全部通过**。抽查：未关联认证 4（被 correction 改成 accepted 的那条已排除）、已认证 1、歧义 1、中国来源只计 1 次（快照没有重复计数） |
| 面板 UI（真实 ClickHouse 数据） | **通过**：11 个标签页没有报错，自定义 SQL 可执行 |

**真实 ClickHouse 测试发现并修复了一个缺陷**：新版 ClickHouse 默认开启 `input_format_skip_unknown_fields`。sink 只是“不传这个参数”时，v2 事件写进 v1 旧表仍然返回 200，新字段被静默丢弃。现在 sink 显式传 `input_format_skip_unknown_fields=0`，复测时旧表正确返回 400（`Unknown field found ... schema_version`）；`TestClickHouseSink` 也改为检查这个参数必须是 0。

新增的回归测试（`probelog/probelog_test.go`、`sink_test.go`）覆盖交接文档要求的场景：

| 场景 | 测试 |
|---|---|
| 同源端口访问多个本地端口 / 本地 IP，不串流不串认证 | `TestFlowIdentitySeparation`、`TestUDPFlowSeparation` |
| SYN 重传与同五元组新连接 | `TestSynRetransVsNewConnection` |
| 正常分段、重传、乱序、相同重叠、冲突、缺口、序列号回绕、上限 | `TestReassembler`、`TestClientHelloReassemblyVariants` |
| TLS 首段 1–4 字节、跨 records、畸形 | `TestClassifyClientHello`、`TestClientHelloReassemblyVariants`（`tiny`） |
| 捕获截断、缺口不生成指纹 | `TestParsePacketAndTruncation`、`TestIncompleteClientHelloHasNoFingerprint` |
| 节点 / 客户端各自 FIN/RST、双向 FIN、仅 SYN、超时回收 | `TestCloseDirection` |
| full 模式响应 | `TestFullModeResponse` |
| 60 秒后结束、快照不被修改 | `TestSnapshotThenFinal` |
| 先日志后流、先流后日志、final 后迟到、端口复用、多候选、SSH | `TestAuthCorrelation`、`TestFlowIdentitySeparation` |
| 采样稳定 | `TestStableSampling` |
| 中途接上的流、关闭端口 SYN | `TestClosedPortSynAndMidstream` |
| 表结构 / 迁移覆盖所有列、旧表缺列被检测、不跳过未知字段 | `TestEventColumnsMatchSchema`、`TestMigrationCoversNewColumns`、`TestSinkSchemaCheckMissing`、`TestClickHouseSink` |

测试辅助 `buildTCP4` 现在带真实的 seq/ack，旧 fixture 已全部改写，没有放宽序列号校验。

## 6. 未解决的限制

1. **没有客户端侧可达性测试**：节点只看到自己这一侧，`close_by=client_rst` 不能说明 RST 是谁发的（可能是链路注入），也不能据此判断封锁。
2. **来源归因没有做**：`src_geo` 只是 geoip 标签；相同前缀、相同指纹只是候选匹配。
3. **单节点观测不能证明封锁因果**：异常连接和之后不可达之间的关系需要受控实验。
4. **xray access 记录没有入站目标地址**：同一来源端口同时连多个节点端口时只能标 `ambiguous`。要彻底解决，需要修改 xray 分支，让 access 记录带上本地地址。
5. **不抓纯 ACK**：`control` 模式下，客户端只建连不发数据、也不发 FIN 时，只能判断到 `synack`。
6. **`full` 模式开销与下行流量成正比**，AF_PACKET 在出站 TSO 分段前捕获，响应前缀可能因截断而不完整（有 `resp_reasm_flags` 标记）。
7. **重叠冲突按“先到优先”处理**，不一定是目标系统协议栈的行为。
8. **没指定 `Interface` 时**，有网桥或隧道的主机可能重复看到同一个包。
9. SQL 只在 ClickHouse 26.11 单机上验证过，测试数据是少量合成行加实测行；没有在副本表、生产数据量下测试性能。