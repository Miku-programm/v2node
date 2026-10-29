-- 把 schema_version 3 的表升级到 4（QUIC 客户端 Initial 解析）
-- 用法：clickhouse-client --multiquery < migrations/004_quic.sql（更早的表先依次执行 002_v2.sql、003_v3.sql）
-- 先升级表、再升级节点：节点不跳过未知字段，表结构落后时写入会失败（并在 stats 的 sink_schema 中报告）。
-- 所有语句都可以重复执行。旧行的新列取默认值，可用 schema_version < 4 识别。

ALTER TABLE v2node.probe_events
    ADD COLUMN IF NOT EXISTS quic_initial LowCardinality(String) AFTER quic_ver,
    ADD COLUMN IF NOT EXISTS quic_sni_first LowCardinality(String) AFTER quic_initial,
    ADD COLUMN IF NOT EXISTS quic_initials UInt8 AFTER quic_sni_first;

-- 旧行的语义（不要改写旧行）：
--   schema_version < 4 的 udp_flow 没有解密 QUIC Initial，tls_* 字段为空；ja4 以 q 开头的行只来自 v4
