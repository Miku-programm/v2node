-- 把 schema_version 2 的表升级到 3
-- 用法：clickhouse-client --multiquery < migrations/003_v3.sql（v1 表先执行 002_v2.sql）
-- 先升级表、再升级节点：节点不跳过未知字段，表结构落后时写入会失败（并在 stats 的 sink_schema 中报告）。
-- 所有语句都可以重复执行。旧行的新列取默认值（空字符串），可用 schema_version < 3 识别。

ALTER TABLE v2node.probe_events
    ADD COLUMN IF NOT EXISTS prefix_stop LowCardinality(String) AFTER reasm_flags,
    ADD COLUMN IF NOT EXISTS hs_flags LowCardinality(String) AFTER handshake;

-- 旧行的语义（不要改写旧行）：
--   schema_version = 2 的 prefix_len / prefix_hash
--       非 TLS 字节流在首字节判断出“不是 ClientHello”时就停止采集，前缀长度取决于 TCP 分段；
--       不要与 v3 行的前缀直接比较
--   schema_version = 2 的 tls_state = complete
--       可能包含 ClientHello 范围内有重叠冲突的样本（reasm_flags 含 conflict），也可能漏检内部长度错误
--   schema_version = 2 的 handshake = established
--       只要 SYN 之后出现客户端数据或 FIN 就会给出，不代表 ACK 被核对过；v3 中这类情况是 inferred
--   schema_version = 2 的 auth_assoc
--       日志先于连接处理时会绑定到第一个出现的连接；final 之后才发现的 ambiguous 没有 correction
--   schema_version = 2 的 flow_end = idle_timeout
--       full 模式下只按入站包计时，持续有下行数据的连接也可能被回收
