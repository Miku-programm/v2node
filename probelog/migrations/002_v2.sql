-- 把 v1 表（af31669 ~ e747e7c 的 schema.sql）升级到 schema_version 2
-- 用法：clickhouse-client --multiquery < migrations/002_v2.sql
-- 先升级表、再升级节点：新版节点不再跳过未知字段，表结构落后时写入会失败（并在 stats 的 sink_schema 中报告）。
-- 所有语句都可以重复执行。旧行的新列取默认值，可用 schema_version < 2 识别。

ALTER TABLE v2node.probe_events
    ADD COLUMN IF NOT EXISTS schema_version UInt16 DEFAULT 0 AFTER ts,
    ADD COLUMN IF NOT EXISTS event_id String AFTER schema_version,
    ADD COLUMN IF NOT EXISTS emitted_at DateTime64(3, 'UTC') DEFAULT ts AFTER event_id,
    ADD COLUMN IF NOT EXISTS flow_id String AFTER kind,
    ADD COLUMN IF NOT EXISTS record_type LowCardinality(String) AFTER flow_id,
    ADD COLUMN IF NOT EXISTS revision UInt32 AFTER record_type,
    ADD COLUMN IF NOT EXISTS obs_mode LowCardinality(String) AFTER revision,
    ADD COLUMN IF NOT EXISTS payload_cap_len UInt32 AFTER payload_len,
    ADD COLUMN IF NOT EXISTS payload_truncated UInt8 AFTER payload_cap_len,
    ADD COLUMN IF NOT EXISTS prefix_len UInt32 AFTER first_data_ms,
    ADD COLUMN IF NOT EXISTS prefix_hash String AFTER prefix_len,
    ADD COLUMN IF NOT EXISTS reasm_flags LowCardinality(String) AFTER prefix_hash,
    ADD COLUMN IF NOT EXISTS tls_state LowCardinality(String) AFTER reasm_flags,
    ADD COLUMN IF NOT EXISTS close_by LowCardinality(String) AFTER flow_end,
    ADD COLUMN IF NOT EXISTS handshake LowCardinality(String) AFTER close_by,
    ADD COLUMN IF NOT EXISTS out_pkts UInt32 AFTER handshake,
    ADD COLUMN IF NOT EXISTS out_bytes UInt64 AFTER out_pkts,
    ADD COLUMN IF NOT EXISTS first_resp_ms Int32 DEFAULT -1 AFTER out_bytes,
    ADD COLUMN IF NOT EXISTS resp_records String AFTER first_resp_ms,
    ADD COLUMN IF NOT EXISTS resp_reasm_flags LowCardinality(String) AFTER resp_records,
    ADD COLUMN IF NOT EXISTS auth_assoc LowCardinality(String) AFTER auth;

ALTER TABLE v2node.probe_events ADD INDEX IF NOT EXISTS idx_prefix prefix_hash TYPE bloom_filter GRANULARITY 4;
ALTER TABLE v2node.probe_events ADD INDEX IF NOT EXISTS idx_flow flow_id TYPE bloom_filter GRANULARITY 4;

-- 重试上传的完全相同批次去重
ALTER TABLE v2node.probe_events MODIFY SETTING non_replicated_deduplication_window = 1000;

-- 迁移后检查：应返回 0 行缺失
-- SELECT name FROM system.columns WHERE database = 'v2node' AND table = 'probe_events' AND name = 'flow_id';

-- 旧行的语义（不要改写旧行）：
--   schema_version = 0      v1 行
--   v1 的 auth = 'none'     只表示“没有关联到 access 记录”，不等于认证失败，更不等于主动探测
--   v1 的 flow_end          fin / rst 只是“观察到入站 FIN/RST”，不是服务端关闭原因；open 只是 60 秒时的早期快照
--   v1 的 tls_* 指纹        按到达顺序拼接得到，没有重组和完整性校验
--   v1 的流                 以 (来源 ip:port) 为键，同一来源端口访问多个本地端口时可能被合并
