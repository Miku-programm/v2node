# v2node
A v2board backend base on moddified xray-core.
一个基于修改版xray内核的V2board节点服务端。

**注意： 本项目需要搭配[修改版V2board](https://github.com/wyx2685/v2board)**

## 软件安装

### 一键安装

```
wget -N https://raw.githubusercontent.com/gunzi-666/v2node/main/script/install.sh && bash install.sh
```

## 探测日志（ProbeLog）

可选功能，默认关闭。开启后记录节点收到的扫端口、主动探测和连接行为并写入 ClickHouse，说明见 [probelog/README.md](probelog/README.md)。

**分析面板是独立的配套项目，需与本项目配套使用：[Miku-programm/probe-dashboard](https://github.com/Miku-programm/probe-dashboard)**。它只读取本项目写入 ClickHouse 的数据，表结构以 [probelog/schema.sql](probelog/schema.sql) 为准。

## 构建
``` bash
GOEXPERIMENT=jsonv2 go build -v -o build_assets/v2node -trimpath -ldflags "-X 'github.com/wyx2685/v2node/cmd.version=$version' -s -w -buildid="
```

## Stars 增长记录

[![Stargazers over time](https://starchart.cc/wyx2685/v2node.svg?variant=adaptive)](https://starchart.cc/wyx2685/v2node)
