# 探测日志（ProbeLog）

记录节点收到的扫端口、主动探测和连接行为，批量上传到 ClickHouse。数据用独立项目 probe-dashboard 读取分析，v2node 本身不包含面板。

## 采集内容

| kind | 来源 | 说明 |
|---|---|---|
| `syn` | 抓包 | 打到**未监听端口**的 SYN（扫端口），带 TTL / IPID / 窗口 / TCP 选项 / TSval 指纹 |
| `tcp_flow` | 抓包 + xray | 到节点端口或其他监听端口（如 SSH）的一条 TCP 流：SYN 指纹、SYN 重传、首包长度/熵/可打印比例/十六进制头/哈希、TLS ClientHello（SNI、ALPN、JA3、JA4、Session ID 长度）、SYN 到首包间隔、结束方式（fin/rst/no_data/idle/open）、xray 认证结果（none/accepted/rejected） |
| `udp_flow` | 抓包 | 到节点 UDP 端口（hysteria2/tuic）和低于 32768 的端口的 UDP 流，带首包特征和 QUIC 版本 |
| `icmp` | 抓包 | 入站 ICMP / ICMPv6 |
| `xray_access` | xray | access 日志的 accepted / rejected 记录（来源、用户、目标、拒绝原因） |
| `xray_log` | xray | 含 REALITY / fallback / invalid / handshake 等关键字的 xray 日志 |
| `stats` | 记录器 | 每分钟一条采集器自身计数（丢弃、上传积压、错误） |

`auth=none` 且从 SYN 开始的 `tcp_flow` 就是“未认证流”，主动探测会落在这一类：REALITY 鉴权失败会被转发到目标站，xray 不会产生 accepted 记录。

抓包只在 Linux 上可用，需要 root 或 `CAP_NET_RAW`。过滤在内核 BPF 里完成：所有端口只收纯 SYN；只有监听端口才收带数据的包和 FIN/RST；纯 ACK 不进用户态。不能抓包时（非 Linux、没有权限）只记录 xray 事件。

## 配置

在 `/etc/v2node/config.json` 中加入：

```json
{
  "Log": { "Level": "warning", "Output": "", "Access": "none" },
  "Nodes": [ ... ],
  "ProbeLog": {
    "Enable": true,
    "NodeName": "us-sjc-1",
    "Interface": "",
    "Capture": true,
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
}
```

| 字段 | 默认 | 说明 |
|---|---|---|
| `NodeName` | 主机名 | 事件里的 `node` 列 |
| `Interface` | 全部 | 只抓指定网卡，如 `eth0` |
| `ExtraPorts` | 无 | 额外关注的端口（TCP 监听端口会自动加入） |
| `GeoTags` | `["cn"]` | 用 geoip.dat 给来源打国家标签，未命中为 `other` |
| `MaxEventsPerSec` / `MaxPerSourceSec` | 2000 / 200 | 每秒总事件数和单个来源事件数上限，防止全端口扫描打满上传 |
| `AuthedSampleRate` | 1 | 已认证正常流的采样率，用户多时可调到 0.1 |
| `XrayLogLevel` | `info` | 采集 xray 日志的级别。REALITY 无效连接日志是 info 级；不影响屏幕/文件日志 |
| `LocalFile` | 空 | 同时写一份 JSONL 到本地文件 |
| `BufferSize` | 200000 | ClickHouse 不可用时内存中保留的最多事件数，超出丢最旧的 |

## ClickHouse

```bash
clickhouse-client --multiquery < probelog/schema.sql
```

`schema.sql` 末尾有写入账号（只 INSERT）和只读账号的示例。默认保留 30 天。

## 分析

v2node 只负责采集和写入。查看数据请使用独立的 `probe-dashboard` 项目，它只读取 ClickHouse 中的 `probe_events` 表；也可以直接用 clickhouse-client 查询。
