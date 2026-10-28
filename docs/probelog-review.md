# v2node 探测日志功能：变更说明（供代码审核）

本次交付是**两个互相独立的部分**：

| 部分 | 位置 | 职责 |
|---|---|---|
| v2node 采集（`probelog` 包） | 仓库 `Miku-programm/v2node`，分支 `feat/probe-telemetry`，基于 `d31ebd1` | 在节点上采集扫描/探测/连接行为，写入 ClickHouse。**不包含任何面板代码** |
| probe-dashboard | 独立项目（自己的 `go.mod`，模块名 `github.com/Miku-programm/probe-dashboard`），不在 v2node 仓库里 | 只读取 ClickHouse 的 `probe_events` 表展示数据，不依赖 v2node 的任何代码，只用 Go 标准库 |

两者之间唯一的约定是 ClickHouse 表结构（`v2node/probelog/schema.sql`）。

- v2node 部分规模：22 个文件，改动原有文件 5 个（共 +83 行），其余为新增
- 语言 / 版本：Go 1.27.1，v2node 构建需要 `GOEXPERIMENT=jsonv2`（沿用原项目）
- 说明：第一次提交 `af31669` 曾把面板做成 `v2node dashboard` 子命令；按要求已从 v2node 中移除，改为独立项目

---

## 1. 目标

节点被怀疑遭到主动探测。需要在节点后端里：

1. 记录节点收到的**扫端口、主动探测、连接行为**的全部细节；
2. 把记录**上传到远端 ClickHouse**；
3. 提供一个**前端分析面板**。

## 2. 总体设计

```
                 ┌──────────────── v2node server（每个节点）────────────────┐
 入站数据包 ──►  │ AF_PACKET + BPF ──► parsePacket ──► flowTable ──┐         │
                 │                                                ├─► emit ─► 限速/采样 ─► sink ─► ClickHouse (HTTP, gzip, JSONEachRow)
 xray 日志   ──► │ teeHandler（包住原 log handler）──► onXrayMessage ┘   │                   └► 可选本地 JSONL 文件
                 │        └─ accepted/rejected ──► flowTable.markAuth（给流打认证标签）
 节点增删    ──► │ core.AddNode/DelNode ──► RegisterNode/UnregisterNode（端口注册表）
                 └──────────────────────────────────────────────────────────┘

 probe-dashboard（独立项目、独立进程）：浏览器 ──► /api/q/{命名查询} ──► 服务端带只读账号转发 ──► ClickHouse
```

三类数据来源：

| 来源 | 得到什么 | 实现 |
|---|---|---|
| 抓包（仅 Linux，需 root / CAP_NET_RAW） | SYN 扫描、每条到监听端口的 TCP/UDP 流的 IP/TCP 指纹、首包特征、TLS ClientHello、ICMP | `probelog/capture_linux.go`、`bpf.go`、`parse.go`、`tls.go`、`flow.go` |
| xray 日志 | access 的 accepted/rejected（带来源 ip:port、用户、目标、原因）、REALITY/fallback 等关键字日志 | `probelog/xraylog.go` |
| 节点端口注册 | 区分“节点端口 / 其他监听端口 / 关闭端口” | `probelog/ports.go` + `core/node.go` |

**判定“探测”的核心思路**：REALITY 鉴权失败时连接被转发到目标站，xray 不会产生 accepted 记录，而 REALITY 的“invalid connection”日志又不带来源地址。因此用抓包看到的“从 SYN 开始、xray 从未 accepted 的 TCP 流”（`kind=tcp_flow AND auth!='accepted' AND tcp_flags 含 S`）作为未认证流 / 探测候选。

### 事件类型（ClickHouse `kind` 列）

| kind | 含义 |
|---|---|
| `syn` | SYN 打到未监听端口（扫端口），只记指纹，不建流 |
| `tcp_flow` | 到节点端口或其他监听端口（如 SSH）的一条 TCP 流，结束时（或 60 秒后）输出一条汇总 |
| `udp_flow` | 到节点 UDP 端口或低于 32768 端口的 UDP 流 |
| `icmp` | 入站 ICMP / ICMPv6 |
| `xray_access` | xray access 记录（accepted 按采样率记录，rejected 全记） |
| `xray_log` | 含关键字的 xray 日志 |
| `stats` | 采集器自身每分钟的计数 |

---

## 3. 对原有文件的改动（逐处）

### 3.1 `conf/conf.go`（+50 / −3）

- **L14–47**：`Conf` 增加字段 `ProbeLogConfig ProbeLogConfig \`mapstructure:"ProbeLog"\``；新增类型 `ProbeLogConfig` 和 `ClickHouseConfig`。
- **L70–86**（`New()` 内）：给 `ProbeLog` 设默认值：`Capture=true`、`GeoTags=["cn"]`、`MaxEventsPerSec=2000`、`MaxPerSourceSec=200`、`PayloadHeadBytes=64`、`AuthedSampleRate=1`、`XrayLogLevel="info"`、ClickHouse `Database=v2node`、`Table=probe_events`、`BatchSize=2000`、`FlushInterval=5`、`BufferSize=200000`、`Timeout=15`。
- `Enable` 默认 `false`：不加配置时行为与原来完全一致。
- 说明：viper `Unmarshal` 到已有结构体时，未出现的键保留默认值。

### 3.2 `cmd/server.go`（+10）

- **L18**：import `probelog`。
- **L82–86**（`serverHandle` 中，`limiter.Init()` 之前）：`probelog.Start(&c.ProbeLogConfig)`，失败只打日志不退出；`defer probelog.Stop()`。
- **L136**（收到 SIGINT/SIGTERM 后、`os.Exit(0)` 之前）：`probelog.Stop()`，因为 `os.Exit` 不执行 defer，这里显式把缓冲的事件发出去。
- **L167–169**（`reload()` 中加载新配置之后、建新节点和新 core 之前）：`probelog.Start(&newConf.ProbeLogConfig)`。`Start` 内部会先停掉旧实例，所以热重载时记录器按新配置重建。

### 3.3 `core/core.go`（+2）

- **L11**：import `probelog`。
- **L65**（`Start()` 中 `v.Server.Start()` 成功之后）：`probelog.HookXrayLog(v.Server)`。必须在 xray 实例创建后调用，因为 xray 的 `app/log` 在 `New` 时会注册自己的 handler；每次热重载会新建实例，所以每次 `Start` 都重新挂接。

### 3.4 `core/node.go`（+16）

- **L7**：import `probelog`。
- **L19–32**（`AddNode` 成功添加 inbound 之后）：把 `info.Security` 映射为 `none/tls/reality`，调用 `probelog.RegisterNode(NodePort{Tag, Type, Security, UDP: type 为 hysteria2 或 tuic, Port: ServerPort})`。
- **L37**（`DelNode` 开头）：`probelog.UnregisterNode(tag)`。
- 注册表是包级全局变量，和记录器生命周期无关，记录器未启用时只是维护一个小 map。

### 3.5 `go.mod`（+1 / −1）

- `golang.org/x/net v0.59.0` 从 indirect 改为直接依赖（用 `golang.org/x/net/bpf` 汇编 BPF）。没有引入新模块，版本不变。

---

## 4. 新增文件

### 4.1 `probelog/` 包

| 文件 | 行数 | 作用 / 关键位置 |
|---|---|---|
| `event.go` | 83 | `Event` 结构（L31），json tag 即 ClickHouse 列名，绝大多数字段 `omitempty`；`FirstDataMs` 用 `*int32` 以区分“0 毫秒”和“未知”（表里默认 -1） |
| `recorder.go` | 196 | 生命周期与公共处理。`Start` L48 / `Stop` L86 / `stopLocked` L92（停止顺序：置空全局指针 → 关抓包 → 关流表并输出剩余流 → 等统计协程 → 关 sink 最后一次上传）。`emit` L111（限速、补时间戳/节点名/地区标签、交给 sink）。`sampleAuthed` L129。`statsLoop` L141（每分钟一条 `stats`）。`rateLimiter` L169（每秒窗口，全局上限 + 单来源上限） |
| `sink.go` | 273 | 上传。`batchLoop` L125 攒批（条数或时间触发）→ 写本地文件 → `enqueue` L176 进内存待发队列（超过 `BufferSize` 丢最旧批次）。`sendLoop` L193 独立协程发送，失败指数退避 1s→60s。`post` L248：`POST {URL}/?query=INSERT INTO \`db\`.\`table\` FORMAT JSONEachRow&date_time_input_format=best_effort&input_format_skip_unknown_fields=1`，gzip 请求体，`X-ClickHouse-User/Key` 头认证。入口通道满时直接丢弃并计数（不阻塞抓包和 xray） |
| `ports.go` | 116 | 节点端口注册表（L21）；`readListenPorts` L81 读 `/proc/net/tcp{,6}` 的 LISTEN 和 `/proc/net/udp{,6}` 绑定在通配地址上的端口 |
| `geo.go` | 67 | 用 xray 自带的 `geodata.IPReg` + geoip.dat 给来源 IP 打 `GeoTags` 中的国家标签，未命中为 `other`；带简单缓存（超过 10 万条清空） |
| `xraylog.go` | 154 | `teeHandler`（L29）：先调用原 handler，再复制给记录器。`Severity()`（L45）返回原级别与采集级别中**更详细**的一个——否则 xray 在生成 Info 日志前就会过滤掉 REALITY 的 Info 日志；原 handler 内部仍按原级别过滤，屏幕和文件日志不变。`HookXrayLog` L56 通过 `server.GetFeature((*applog.Instance)(nil))` 取原 handler。`onAccess` L104：解析来源地址、调用 `flows.markAuth`、按采样率输出 `xray_access`。`parseXrayAddr` L130 兼容 `net.Addr` 和 `tcp:1.2.3.4:5` 两种格式，IPv4-mapped 地址转成 IPv4 |
| `parse.go` | 262 | `parsePacket` L59：解析 IPv4（丢弃分片）/ IPv6（跳过 0/43/60 扩展头）、TCP/UDP/ICMP。`parseTCPOptions` L153 生成 p0f 风格选项串（如 `M1460,S,T,N,W7`），同时取 MSS、TSval、TSecr。`fillPayloadFeatures` L230：首包长度、前 N 字节 hex、sha256 前 8 字节、香农熵、可打印字符比例。`quicVersion` L261 |
| `tls.go` | 288 | `clientHelloNeed` L36（判断需要多少字节才能读完 ClientHello）；`parseClientHello` L48（会把多个 TLS 记录体拼起来；解析 SNI、ALPN、supported_groups、ec_point_formats、signature_algorithms、supported_versions）；`ja3` L165；`ja4` L198（TCP 版 JA4：`t{版本}{d/i}{密码套件数}{扩展数}{ALPN 首尾字符}_{排序后套件 sha256 前 12}_{排序后扩展（去 SNI/ALPN）+签名算法 sha256 前 12}`，去除 GREASE）；`reader` L254 出错后返回零值的字节读取器 |
| `flow.go` | 373 | 流表。key 为 `(是否 UDP, 源 ip:port)`。`handleTCP` L162：关闭端口的纯 SYN 直接输出 `syn` 事件不建流；监听端口上建流，记 SYN 指纹和重传次数；数据包累积到能完整解析 ClientHello（最多 16KB / 8 个分段 / 2 秒）后 `finalizePayload` L260；收到 FIN/RST 时 `finish` L281 输出 `tcp_flow`。`handleUDP` L237 首包即算特征。`markAuth` L306。`sweep` L338 每 5 秒：UDP 空闲 30 秒结束；TCP 只有 SYN 没数据 30 秒结束（`no_data`）、空闲 15 分钟结束、存活超过 60 秒先输出一次（`open`）。**没看到 SYN 的 TCP 流（中途接上的长连接）只跟踪不上报**，避免加密流中段被误判为探测。上限 20 万条流 |
| `bpf.go` | 174 | 带标签的 BPF 小汇编器（条件跳转只跨一条，远跳用 32 位偏移的 `ja`，避免 8 位偏移溢出）。`buildFilter` L70 生成过滤器：只收 `PACKET_HOST`；IPv4/IPv6；所有端口的纯 SYN（截 160 字节）；监听端口的 FIN/RST 和有负载的包（截 2048 字节，纯 ACK 在内核中丢弃）；节点 UDP 端口及低于 32768 的 UDP；ICMP（截 96 字节）。端口最多 250 个 |
| `capture_linux.go` | 213 | `newCapturer` L41：以协议 0 创建 `AF_PACKET/SOCK_DGRAM`（此时不收包）→ 挂过滤器 → 设 8MB 接收缓冲和 500ms 读超时 → 以 `ETH_P_ALL` bind。`watchedPorts` L97 = 节点 TCP 端口 ∪ 本机 TCP 监听端口 ∪ ExtraPorts（节点端口排前，防止超过 250 个时被截掉）。`watchLoop` L161 每 5 秒检查端口变化并重挂过滤器。`readLoop` L183 跳过回环网卡和回环源地址 |
| `capture_other.go` | 13 | 非 Linux 的空实现，返回错误后只记录 xray 事件 |
| `schema.sql` | 79 | 建库建表：`MergeTree`，`PARTITION BY toYYYYMMDD(ts)`，`ORDER BY (kind, node, ts)`，`TTL 30 天`，`src_ip`、`payload_hash` 加 bloom_filter 索引；末尾有写入账号（仅 INSERT）和只读账号（readonly=2）示例 |
| `README.md` | 87 | 使用与配置说明 |
| `probelog_test.go` / `sink_test.go` / `capture_live_test.go` | — | 测试，见第 6 节 |

### 4.2 独立项目 probe-dashboard（不在 v2node 仓库中）

只依赖 Go 标准库，`package main`，单个二进制。

| 文件 | 作用 / 关键位置 |
|---|---|
| `main.go` | 用标准库 `flag` 解析参数：`-listen`（默认 127.0.0.1:8088）、`-ch-url`、`-ch-db`、`-ch-table`、`-ch-user`、`-ch-password`（或环境变量 `CH_PASSWORD`）、`-auth-user`、`-auth-password`（或 `DASH_PASSWORD`）、`-raw-sql` |
| `server.go` | `New` 校验库名表名只含 `[A-Za-z0-9_]`；`Run` 用 `go:embed` 提供静态文件；`auth` 可选 Basic Auth（常量时间比较）；`handleNamed` 只执行 `queries.go` 中的命名查询，用户输入（hours、node、limit、ip）全部作为 ClickHouse 查询参数 `param_*` 传入，不拼接进 SQL；`handleRaw` 仅在 `-raw-sql` 时可用，附加 `readonly=2`、`max_result_rows=10000`；`query` 统一加 `max_execution_time=30`，ClickHouse 账号只在服务端使用 |
| `queries.go` | 19 个命名查询：nodes、overview、timeline、probes、probe_sources、scanners、replays、fp_probe、fp_scan、payload_len、reaction（`ASOF LEFT JOIN` 求每条探测距同节点同端口上一次已认证连接的时间）、sni、ports、geo、udp、xray、ip、stats |
| `static/` | `index.html` + `style.css` + `app.js`（原生 JS，ECharts 5.5.1 来自 jsdelivr CDN）。KPI 卡片、时间线（扫描 SYN 放右轴），11 个标签页：探测流量、扫端口、重放检测、指纹聚类、长度与时机、SNI/端口/地区、UDP、Xray 日志、IP 查询、SQL、采集状态。表格可排序，点击 IP 跳转到 IP 查询。时间范围和当前标签存 localStorage |
| `server_test.go` | 命名查询转发、Basic Auth、查询参数齐全、静态文件已嵌入 |
| `README.md` | 构建、运行、参数说明 |

---

## 5. 配置示例

```json
"ProbeLog": {
  "Enable": true,
  "NodeName": "us-sjc-1",
  "Capture": true,
  "ExtraPorts": [22],
  "GeoTags": ["cn"],
  "AuthedSampleRate": 1,
  "ClickHouse": {
    "URL": "https://ch.example.com:8443",
    "Username": "v2node_writer",
    "Password": "******"
  }
}
```

---

## 6. 测试情况

| 测试 | 结果 | 说明 |
|---|---|---|
| v2node：`go test ./probelog/`（Windows） | 通过 | ClickHouse 返回 503 一次后重试成功、请求头和 INSERT 语句正确、空字段被省略；ClientHello 解析（用 `crypto/tls` 生成真实 ClientHello）与 JA3/JA4 格式；IPv4 TCP 解析与选项串；300 个端口时 BPF 能汇编；流表端到端（关闭端口 SYN、未认证探测流、accepted 打标、xray 日志） |
| probe-dashboard：`go test .` | 通过 | 命名查询转发、Basic Auth、所有查询参数都有提供、静态文件已嵌入 |
| 两个项目的 `go vet`、`GOOS=linux` 交叉编译 | 通过 | 移除面板后 v2node 重新编译通过 |
| 真实内核抓包（WSL2 Ubuntu，root） | 通过 | 从 Windows 主机向 WSL 发流量，正确记录：3 个关闭端口的 SYN（含重传）；带 SNI `www.microsoft.com` 的 ClientHello（解析出 TLS 1.3、JA4、Session ID 32）；随机 221 字节探测（熵 7.04）；连上不发数据；UDP QUIC 长包头（版本 0x1） |
| 面板 UI | 通过（模拟数据） | 用模拟 ClickHouse HTTP 服务返回合成数据，11 个标签页都无报错并能渲染表格和图表 |
| **真实 ClickHouse** | **未测试** | 下载 ClickHouse 被环境策略拦截。`schema.sql` 和 19 个查询的 SQL **从未在真实 ClickHouse 上执行过**，需要重点检查语法和函数用法 |
| 真实节点（带 panel、真实 VLESS-REALITY 流量） | 未测试 | |

---

## 7. 已知限制与风险

1. **只看得到入站方向**：没有抓服务器的回包，`flow_bytes` / `flow_pkts` 只是客户端→服务器方向；无法直接知道服务器是否回应、回应了什么。
2. **REALITY 回落无法直接观测**：REALITY 鉴权失败转发到目标站的过程在 xray 内部，日志没有来源地址，只能靠“未认证流”间接判断。
3. **认证打标依赖 xray access 记录的来源端口**：VLESS 非 mux 请求在 `proxy/vless/inbound/inbound.go` 记录 accepted（From 为连接远端地址）；mux 请求由 `common/mux/server.go` 记录。如果某种入站不产生 access 记录，或者经过 PROXY protocol / CDN，流会被错误地标成 `auth=none`。
4. **为抓 REALITY 的 Info 日志，xray 的有效日志级别被调到至少 info**（`XrayLogLevel` 可改）：会多生成 Info 级日志对象（不会多输出），有一些 CPU 开销。
5. **上行数据包会被复制到用户态**：监听端口上所有带负载的入站包都会进 Go 处理（最多 2048 字节/包）。上传量大的节点上有 CPU 开销；纯 ACK 已在内核中丢弃。
6. **长连接空闲判断**：因为只看上行包，以下载为主的连接可能 15 分钟没有入站数据而被当作空闲移出流表；之后再有数据会被当成中途接上的流（不上报）。
7. **关闭端口的 SYN 重传会产生多条 `syn` 事件**（实测 Windows 客户端每个端口 2 条），没有去重。
8. **本机回环地址上的监听端口也会被加入关注列表**（实测出现了 systemd-resolved 的 53 端口），无害但多余。
9. **UDP“监听端口”判断不精确**：出站 UDP 套接字也会绑定在通配地址上；目前只用于打 `port_state` 标签，BPF 只放行节点 UDP 端口和低于 32768 的端口。
10. **`clientHelloNeed` 假设 ClientHello 在第一个 TLS 记录内**；跨记录时会在 8 个分段 / 16KB / 2 秒后按已有数据解析。
11. **隐私**：`xray_access` 记录包含用户 email 和访问目标，会上传到 ClickHouse。
12. **面板（probe-dashboard）**：未设 `-auth-user` 时只打警告；`-raw-sql` 依赖 ClickHouse 账号本身只读（readonly=2 仍允许改会话设置）；前端依赖 jsdelivr CDN。
13. **重载时 `Stop` 会做最后一次上传**，ClickHouse 不可达时可能让重载阻塞最多 `Timeout`（默认 15 秒）。
14. 重新挂接 xray 日志时用的是 xray 的全局 `log.RegisterHandler`，与 v2node 其他代码无冲突，但如果以后有别的代码也替换这个全局 handler，会互相覆盖。

---

## 8. 希望审核重点关注的问题

1. **并发与生命周期**：`recorder.go` 的 `stopLocked` 停止顺序；`Stop` 之后仍可能持有旧 `*Recorder` 的 xray 回调调用 `emit`（目前会把事件推进已停止的 sink 通道然后丢失，不会 panic，是否可接受）；`flowTable` 的单把互斥锁在高包速下是否成为瓶颈。
2. **`sink.go`**：`flushPending` 用“队首批次数据首字节地址相同”来判断发送期间队首没被丢弃（约 L240），这个判断是否可靠；退避和关闭流程是否可能卡住。
3. **BPF 正确性**（`bpf.go` `buildFilter`）：IPv4 负载长度计算（总长 − IP 头 − TCP 头）、X 寄存器在各分支中的值、IPv6 只处理固定头后直接跟 TCP/UDP 的情况。
4. **`teeHandler.Severity()`** 调高 xray 有效日志级别的做法是否有副作用。
5. **`tls.go` 的 JA4 实现**是否符合 FoxIO 规范（ALPN 非字母数字时的处理、签名算法顺序、扩展计数是否包含 SNI/ALPN）。
6. **`schema.sql` 与 `queries.go` 的 ClickHouse SQL** 是否能在当前版本 ClickHouse 上正确执行（尤其 `ASOF LEFT JOIN` 未匹配时右表时间的默认值、`groupUniqArrayIf`、`topK(1)(x)[1]`、`toStartOfInterval` 对 `DateTime64` 的行为、`ORDER BY authed = 0 DESC`）。
7. **面板安全（probe-dashboard）**：命名查询参数化是否完整，`-raw-sql` 的限制是否足够，库名表名校验。
8. **性能**：大规模扫描（如每秒数万 SYN）时限速器、流表、sink 的表现。

---

## 9. 如何查看完整改动

v2node（在仓库里）：

```bash
git diff d31ebd1 feat/probe-telemetry
git diff d31ebd1 feat/probe-telemetry -- cmd/server.go conf/conf.go core/core.go core/node.go go.mod   # 只看原有文件
```

probe-dashboard 是独立目录，直接阅读其全部文件即可。
