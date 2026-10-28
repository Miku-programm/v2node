-- v2node 探测日志 ClickHouse 表结构
-- 用法：clickhouse-client --multiquery < schema.sql

CREATE DATABASE IF NOT EXISTS v2node;

CREATE TABLE IF NOT EXISTS v2node.probe_events
(
    ts            DateTime64(3, 'UTC'),
    node          LowCardinality(String),
    kind          LowCardinality(String),   -- syn / tcp_flow / udp_flow / icmp / xray_access / xray_log / stats

    proto         LowCardinality(String),
    src_ip        String,
    src_port      UInt16,
    dst_ip        String,
    dst_port      UInt16,
    src_geo       LowCardinality(String),   -- GeoTags 中命中的国家，未命中为 other
    port_state    LowCardinality(String),   -- node / listen / closed
    node_tag      LowCardinality(String),
    node_type     LowCardinality(String),   -- 如 vless+reality

    -- IP / TCP 指纹（取自 SYN）
    ttl           UInt8,
    ip_id         UInt16,
    ip_df         UInt8,
    tcp_flags     LowCardinality(String),
    tcp_win       UInt16,
    tcp_opts      LowCardinality(String),   -- p0f 风格，如 M1460,S,T,N,W7
    mss           UInt16,
    ts_val        UInt32,
    ts_ecr        UInt32,
    syn_retrans   UInt16,

    -- 首个数据包
    payload_len   UInt32,
    payload_head  String,                   -- 前 N 字节 hex
    payload_hash  String,                   -- 首包 sha256 前 8 字节，用于发现重放
    entropy       Float32,
    printable     Float32,
    first_data_ms Int32 DEFAULT -1,         -- SYN 到首个数据包的毫秒数

    -- TLS ClientHello
    tls_ver       LowCardinality(String),
    tls_sni       String,
    tls_alpn      String,
    ja3           String,
    ja4           String,
    tls_sid_len   UInt8,
    tls_ch_len    UInt32,

    quic_ver      LowCardinality(String),
    icmp_type     UInt8,
    icmp_code     UInt8,

    -- 流汇总（字节/包数只统计客户端到服务器方向的数据包）
    flow_ms       UInt32,
    flow_pkts     UInt32,
    flow_bytes    UInt64,
    flow_end      LowCardinality(String),   -- fin / rst / no_data / idle / open / shutdown
    auth          LowCardinality(String),   -- none / accepted / rejected

    -- xray
    xray_status   LowCardinality(String),
    xray_email    String,
    xray_target   String,
    xray_reason   String,
    xray_detour   String,
    severity      LowCardinality(String),
    message       String,

    INDEX idx_src_ip src_ip TYPE bloom_filter GRANULARITY 4,
    INDEX idx_hash payload_hash TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (kind, node, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY;

-- 节点写入账号：只能 INSERT
-- CREATE USER v2node_writer IDENTIFIED WITH sha256_password BY '<写入密码>';
-- GRANT INSERT ON v2node.probe_events TO v2node_writer;

-- 面板查询账号：只读
-- CREATE USER v2node_reader IDENTIFIED WITH sha256_password BY '<只读密码>' SETTINGS readonly = 2;
-- GRANT SELECT ON v2node.probe_events TO v2node_reader;
