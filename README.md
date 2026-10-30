# v2node 蜜罐节点（ProbeLog）

用于搭建 **蜜罐 / 主动探测研究节点** 的 v2node 修改版：在 V2board 节点服务端的基础上加入 ProbeLog，记录节点收到的扫端口、主动探测和连接行为并写入 ClickHouse，配合 [probe-dashboard](https://github.com/Miku-programm/probe-dashboard) 分析 GFW 的主动探测与封锁行为。

> [!CAUTION]
> **本仓库仅用于搭建蜜罐 / 探测研究节点，不可以作为机场节点端运行常规业务。**
>
> - ProbeLog 会抓包、重组客户端字节流、解密 QUIC Initial、关联 xray access 日志，记录连接来源 IP、端口、TLS/QUIC 指纹、SNI 和首包内容等信息并上传 ClickHouse。用于承载真实用户流量就等于采集用户的连接元数据，不符合机场服务的隐私要求。
> - 本仓库面向研究，没有按生产机场节点的稳定性、性能要求设计与测试。
> - xray 内核固定为 v26.7.28（[wyx2685/xray-core@83ad74c](https://github.com/wyx2685/xray-core/commit/83ad74c46335)），是为了研究需要固定的旧版本，不会随上游的安全与稳定性修复更新，也不包含 gunzi-666/Xray-core 之后加入的 AnyTLS 连接泄漏修复和 PROXY protocol 下 sendThrough 修复。
> - 需要运行机场节点请使用上游 [wyx2685/v2node](https://github.com/wyx2685/v2node)。

## 组成

| 项目 | 作用 |
|---|---|
| [Miku-programm/v2node](https://github.com/Miku-programm/v2node)（本仓库） | 蜜罐节点：V2board 节点服务端 + ProbeLog 采集，写入 ClickHouse |
| [Miku-programm/probe-dashboard](https://github.com/Miku-programm/probe-dashboard) | 分析面板：只读取 ClickHouse 中的数据，表结构以 [probelog/schema.sql](probelog/schema.sql) 为准 |

节点需要对接 [修改版 V2board](https://github.com/wyx2685/v2board) 面板。

## ProbeLog

默认关闭，在配置里开启。可以记录：

- 打到未监听端口的 SYN（扫端口）
- 到监听端口的每个 TCP / UDP 连接实例：IP/TCP 指纹、首段载荷、按序列号重组的客户端前缀、TLS ClientHello（JA3 / JA4）、握手与关闭方向的观察证据
- QUIC 客户端 Initial 解密：SNI、JA4，以及 SNI 是否完整落在第一个 UDP 数据报里（对应 GFW 按 SNI 封锁 QUIC 的方式）
- 与 xray access 日志的关联（accepted / rejected / 未关联 / 歧义）

字段含义、观测模式、数据质量限制和 ClickHouse 建表 / 升级说明见 [probelog/README.md](probelog/README.md)。这些记录只描述“观察到了什么”，单独一条都不能证明来源是 GFW 或说明封锁因果。

## 构建

需要 Go 1.27.1。

```bash
git clone https://github.com/Miku-programm/v2node.git
cd v2node
GOEXPERIMENT=jsonv2 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o build_assets/v2node -trimpath -ldflags "-X 'github.com/wyx2685/v2node/cmd.version=$version' -s -w -buildid="
```

模块路径仍是上游的 `github.com/wyx2685/v2node`，不影响构建。抓包只支持 Linux，需要 root 或 `CAP_NET_RAW`。

## 部署

本仓库暂未发布预编译版本，请自行编译后部署：

1. 部署 ClickHouse，用 [probelog/schema.sql](probelog/schema.sql) 建表（已有旧表按 `probelog/migrations/` 中的脚本依次升级）。
2. 把编译好的 `v2node` 放到 `/usr/local/v2node/`，配置写在 `/etc/v2node/config.json`，并在其中开启 `ProbeLog`、填写 ClickHouse 写入账号（示例见 [probelog/README.md](probelog/README.md#配置)）。
3. 以 systemd 服务运行 `/usr/local/v2node/v2node server`。
4. 部署 [probe-dashboard](https://github.com/Miku-programm/probe-dashboard) 查看数据。

注意：`script/` 中的一键安装与管理脚本仍指向 gunzi-666/v2node 的发布版本，下载到的程序不包含 ProbeLog 和固定的 xray 版本，不要用它安装蜜罐节点。

## 致谢

本仓库 fork 自 [gunzi-666/v2node](https://github.com/gunzi-666/v2node)，其上游为 [wyx2685/v2node](https://github.com/wyx2685/v2node)；xray 内核来自 [wyx2685/xray-core](https://github.com/wyx2685/xray-core)（基于 [XTLS/Xray-core](https://github.com/XTLS/Xray-core)）。QUIC 部分参考了 Zohaib et al., *Exposing and Circumventing SNI-based QUIC Censorship of the Great Firewall of China*, USENIX Security 2025。

## Stars 增长记录

[![Stargazers over time](https://starchart.cc/Miku-programm/v2node.svg?variant=adaptive)](https://starchart.cc/Miku-programm/v2node)
