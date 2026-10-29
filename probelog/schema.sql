-- v2node 探测日志 ClickHouse 表结构（新安装，schema_version = 4）
-- 用法：clickhouse-client --multiquery < schema.sql
-- 已有表的升级按顺序执行 migrations/002_v2.sql（v1 表）、003_v3.sql、004_quic.sql（CREATE TABLE IF NOT EXISTS 不会升级已有表）
-- 字段含义见 README.md；查询示例见 queries.sql

CREATE DATABASE IF NOT EXISTS v2node;

CREATE TABLE IF NOT EXISTS v2node.probe_events
(
    ts  DateTime64(3, 'UTC'),                   -- 事件时间；流记录为连接首次观察时间
    schema_version  UInt16 DEFAULT 0,           -- 0/1 = v1 旧行；2 = v2；3 = v3；4 = 当前模型（语义差异见 README）
    event_id  String,                           -- 记录唯一标识；流记录为 flow_id-revision
    emitted_at  DateTime64(3, 'UTC') DEFAULT ts, -- 记录生成时间
    node  LowCardinality(String),
    kind  LowCardinality(String),               -- syn / tcp_flow / udp_flow / icmp / xray_access / xray_log / stats

    flow_id  String,                            -- 连接实例；v1 旧行为空
    record_type  LowCardinality(String),        -- snapshot / final / correction；v1 旧行为空
    revision  UInt32,                           -- 同一 flow_id 内单调递增，取最大者
    obs_mode  LowCardinality(String),           -- inbound / control / full

    proto  LowCardinality(String),
    src_ip  String,
    src_port  UInt16,
    dst_ip  String,
    dst_port  UInt16,
    src_geo  LowCardinality(String),
    port_state  LowCardinality(String),         -- node / listen / closed
    node_tag  LowCardinality(String),
    node_type  LowCardinality(String),

    ttl  UInt8,
    ip_id  UInt16,
    ip_df  UInt8,
    tcp_flags  LowCardinality(String),
    tcp_win  UInt16,
    tcp_opts  LowCardinality(String),
    mss  UInt16,
    ts_val  UInt32,
    ts_ecr  UInt32,
    syn_retrans  UInt16,

    payload_len  UInt32,                        -- 首个数据段原始长度
    payload_cap_len  UInt32,                    -- 首个数据段实际捕获长度
    payload_truncated  UInt8,
    payload_head  String,
    payload_hash  String,                       -- 首段捕获字节的哈希（不是流哈希）
    entropy  Float32,
    printable  Float32,
    first_data_ms  Int32 DEFAULT -1,

    prefix_len  UInt32,                         -- 重组后连续前缀长度（最多 4096）
    prefix_hash  String,                        -- sha256(前缀)[:8]，比较时连同 prefix_len
    reasm_flags  LowCardinality(String),        -- gap / conflict / overflow / truncated / retrans；只描述 prefix_stop 之前
    prefix_stop  LowCardinality(String),        -- v3：bytes / window / flow_end / snapshot / overflow

    tls_state  LowCardinality(String),          -- not_client_hello / malformed / complete / incomplete / conflict（v3）；v1 为空
    tls_ver  LowCardinality(String),
    tls_sni  String,
    tls_alpn  String,
    ja3  String,
    ja4  String,
    tls_sid_len  UInt8,
    tls_ch_len  UInt32,

    quic_ver  LowCardinality(String),
    quic_initial  LowCardinality(String),       -- v4，udp_flow：ok / unsupported_version / decrypt_failed / truncated / malformed / no_initial
    quic_sni_first  LowCardinality(String),     -- v4：full / partial / none / no_sni，SNI 字节落在第一个 UDP 数据报里的程度
    quic_initials  UInt8,                       -- v4：含可解密客户端 Initial 的数据报数
    icmp_type  UInt8,
    icmp_code  UInt8,

    flow_ms  UInt32,
    flow_pkts  UInt32,
    flow_bytes  UInt64,
    flow_end  LowCardinality(String),           -- v2：closed / no_data_timeout / idle_timeout / superseded / shutdown / open / late_auth
    close_by  LowCardinality(String),           -- client_fin / client_rst / server_fin / server_rst / both_fin / none
    handshake  LowCardinality(String),          -- syn_only / synack / established / inferred（v3）/ unknown
    hs_flags  LowCardinality(String),           -- v3：bad_ack / no_ack

    out_pkts  UInt32,
    out_bytes  UInt64,
    first_resp_ms  Int32 DEFAULT -1,
    resp_records  String,
    resp_reasm_flags  LowCardinality(String),

    auth  LowCardinality(String),               -- v2：accepted / rejected / unknown / not_applicable；v1：accepted / rejected / none
    auth_assoc  LowCardinality(String),         -- matched / unmatched / ambiguous / not_applicable

    xray_status  LowCardinality(String),
    xray_email  String,
    xray_target  String,
    xray_reason  String,
    xray_detour  String,
    severity  LowCardinality(String),
    message  String,

    INDEX idx_src_ip src_ip TYPE bloom_filter GRANULARITY 4,
    INDEX idx_hash payload_hash TYPE bloom_filter GRANULARITY 4,
    INDEX idx_prefix prefix_hash TYPE bloom_filter GRANULARITY 4,
    INDEX idx_flow flow_id TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (kind, node, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY
-- 上传失败重试时会发送完全相同的批次；开启去重窗口让重复批次被丢弃
SETTINGS non_replicated_deduplication_window = 1000;

-- 节点写入账号：INSERT；SHOW COLUMNS 用于节点启动时检查表结构（没有也能写入，只是 stats 里显示 unchecked）
-- CREATE USER v2node_writer IDENTIFIED WITH sha256_password BY '<写入密码>';
-- GRANT INSERT, SHOW COLUMNS ON v2node.probe_events TO v2node_writer;

-- 面板查询账号：只读
-- CREATE USER v2node_reader IDENTIFIED WITH sha256_password BY '<只读密码>' SETTINGS readonly = 2;
-- GRANT SELECT ON v2node.probe_events TO v2node_reader;
