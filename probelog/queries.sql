-- probe_events 查询示例（schema_version 3）
-- v2 版本的查询曾在 ClickHouse 26.11 上执行验证；v3 新增的条件（prefix_stop、hs_flags、tls_state=conflict）尚未在真实 ClickHouse 上执行。
-- 可比较样本的统一门槛见 README「可比较样本的统一门槛」，面板使用同样的条件。

-- 1. 每个连接实例只取一行：同一 flow_id 取 revision 最大的记录（final / correction 优先于 snapshot）。
--    v1 旧行没有 flow_id，用 event 自身的 (ts, src, dst) 组合作键，避免所有旧行被归并到同一个空 ID。
--    重复上传的完全相同批次由表设置 non_replicated_deduplication_window 去重。
CREATE VIEW IF NOT EXISTS v2node.flows_latest AS
SELECT *
FROM v2node.probe_events
WHERE kind IN ('tcp_flow', 'udp_flow')
ORDER BY revision DESC, emitted_at DESC
LIMIT 1 BY if(flow_id = '',
              concat('v1|', toString(ts), '|', src_ip, '|', toString(src_port), '|', dst_ip, '|', toString(dst_port)),
              flow_id);

-- 2. 区分新旧语义（v1 / v2 / v3 的字段含义不同，不要混在一起比较）
SELECT schema_version, kind, count() FROM v2node.probe_events GROUP BY schema_version, kind ORDER BY schema_version, kind;

-- 3. 到节点端口、从 SYN 开始、没有关联到 access 结果的连接（只用 v3 行）。
--    注意：auth = 'unknown' 只是“没有关联到 access 记录”，不等于认证失败，更不等于主动探测或 GFW。
SELECT ts, node, src_ip, dst_port, tls_state, tls_sni, ja4, prefix_len, prefix_hash, prefix_stop, reasm_flags,
       handshake, hs_flags, close_by, flow_end, first_data_ms, first_resp_ms, auth, auth_assoc
FROM v2node.flows_latest
WHERE schema_version >= 3 AND kind = 'tcp_flow' AND port_state = 'node'
  AND auth = 'unknown' AND auth_assoc = 'unmatched' AND position(tcp_flags, 'S') > 0
  AND ts > now() - INTERVAL 1 DAY
ORDER BY ts DESC
LIMIT 200;

-- 4. 只用完整、无冲突的 ClientHello 比较指纹（v3 中 ClientHello 范围内有重叠冲突的是 tls_state = 'conflict'，没有指纹）
SELECT ja4, tls_sni, count() AS flows, uniqExact(src_ip) AS ips, countIf(auth = 'accepted') AS accepted
FROM v2node.flows_latest
WHERE schema_version >= 3 AND tls_state = 'complete' AND ts > now() - INTERVAL 1 DAY
GROUP BY ja4, tls_sni
ORDER BY flows DESC
LIMIT 50;

-- 5. 相同客户端前缀出现在多个来源：候选匹配，不能证明来源身份或重放因果。
--    v2 行的前缀范围取决于 TCP 分段，不要与 v3 混合；短前缀区分度低，结果按 prefix_len 分层看。
SELECT prefix_len, prefix_hash, count() AS flows, uniqExact(src_ip) AS ips, groupUniqArray(prefix_stop) AS stops,
       argMin(src_ip, ts) AS first_src, argMin(auth, ts) AS first_auth, min(ts) AS first_seen, max(ts) AS last_seen
FROM v2node.flows_latest
WHERE schema_version >= 3 AND prefix_hash != '' AND reasm_flags NOT LIKE '%conflict%' AND ts > now() - INTERVAL 7 DAY
GROUP BY prefix_len, prefix_hash
HAVING ips > 1
ORDER BY flows DESC
LIMIT 50;

-- 6. 关闭方向分布（obs_mode = inbound 时看不到节点方向，close_by 只可能是 client_* 或 none）。
--    handshake = established 是核对过的证据，inferred 只是推定；hs_flags 中的 bad_ack / no_ack 是异常客户端段
SELECT obs_mode, close_by, flow_end, handshake, hs_flags, count()
FROM v2node.flows_latest
WHERE schema_version >= 3 AND kind = 'tcp_flow' AND ts > now() - INTERVAL 1 DAY
GROUP BY obs_mode, close_by, flow_end, handshake, hs_flags
ORDER BY count() DESC;

-- 7. 数据质量：最近一次各节点的采集统计（丢弃、截断、关联失败、内核丢包）
SELECT node, max(ts) AS last_seen, argMax(message, ts) AS stats
FROM v2node.probe_events
WHERE kind = 'stats' AND ts > now() - INTERVAL 1 HOUR
GROUP BY node;
