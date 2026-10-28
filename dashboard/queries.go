package dashboard

// 面板使用的命名查询。{T} 替换为表名，{W} 替换为公共时间/节点条件；
// 其余 {name:Type} 是 ClickHouse 的查询参数，由 HTTP 接口以 param_name 传入。
//
// "未认证流" = 到节点/监听端口、从 SYN 开始看到、xray 没有给出 accepted 的 TCP 流。
var queries = map[string]string{
	"nodes": `SELECT DISTINCT node FROM {T} WHERE ts > now() - INTERVAL 30 DAY ORDER BY node`,

	"overview": `SELECT
  count() AS events,
  uniqExactIf(src_ip, src_ip != '') AS sources,
  countIf(kind = 'syn') AS closed_syn,
  uniqExactIf(src_ip, kind = 'syn') AS scanners,
  countIf(kind = 'tcp_flow' AND auth != 'accepted' AND port_state = 'node') AS unauth_node_flows,
  uniqExactIf(src_ip, kind = 'tcp_flow' AND auth != 'accepted' AND port_state = 'node') AS unauth_sources,
  countIf(kind = 'tcp_flow' AND auth = 'accepted') AS authed_flows,
  countIf(kind = 'xray_access' AND xray_status = 'rejected') AS rejected,
  countIf(kind = 'xray_log' AND positionCaseInsensitive(message, 'reality') > 0) AS reality_logs,
  countIf(src_geo = 'cn' AND kind IN ('syn', 'tcp_flow', 'udp_flow') AND auth != 'accepted') AS cn_unauth,
  countIf(kind = 'udp_flow' AND port_state = 'closed') AS udp_closed
FROM {T} WHERE {W}`,

	"timeline": `SELECT
  toStartOfInterval(ts, toIntervalSecond({bucket:UInt32})) AS t,
  countIf(kind = 'syn') AS scan_syn,
  countIf(kind = 'tcp_flow' AND auth != 'accepted' AND port_state = 'node') AS unauth_node,
  countIf(kind = 'tcp_flow' AND auth != 'accepted' AND port_state = 'listen') AS unauth_other,
  countIf(kind = 'tcp_flow' AND auth = 'accepted') AS authed,
  countIf(kind = 'udp_flow') AS udp,
  countIf(kind = 'xray_access' AND xray_status = 'rejected') AS rejected,
  countIf(kind = 'icmp') AS icmp
FROM {T} WHERE {W}
GROUP BY t ORDER BY t`,

	"probes": `SELECT ts, node, src_ip, src_port, src_geo, dst_port, port_state, node_type,
  ttl, ip_id, tcp_win, tcp_opts, ts_val, syn_retrans, first_data_ms,
  payload_len, round(entropy, 2) AS entropy, round(printable, 2) AS printable, payload_head, payload_hash,
  tls_ver, tls_sni, tls_alpn, ja4, tls_sid_len, flow_ms, flow_pkts, flow_bytes, flow_end, auth
FROM {T}
WHERE {W} AND kind = 'tcp_flow' AND auth != 'accepted' AND port_state != 'closed' AND position(tcp_flags, 'S') > 0
ORDER BY ts DESC LIMIT {limit:UInt32}`,

	"probe_sources": `SELECT src_ip, any(src_geo) AS geo,
  countIf(auth != 'accepted') AS unauth, countIf(auth = 'accepted') AS authed,
  uniqExact(dst_port) AS ports, groupUniqArray(4)(node) AS nodes,
  groupUniqArrayIf(4)(tls_sni, tls_sni != '' AND auth != 'accepted') AS snis,
  groupUniqArrayIf(6)(payload_len, auth != 'accepted') AS lens,
  countIf(auth != 'accepted' AND payload_len = 0) AS no_data,
  min(ts) AS first_seen, max(ts) AS last_seen,
  topK(1)(ttl)[1] AS ttl, topK(1)(tcp_opts)[1] AS opts
FROM {T}
WHERE {W} AND kind = 'tcp_flow' AND port_state != 'closed' AND position(tcp_flags, 'S') > 0
GROUP BY src_ip HAVING unauth > 0
ORDER BY authed = 0 DESC, unauth DESC LIMIT {limit:UInt32}`,

	"scanners": `SELECT src_ip, any(src_geo) AS geo, count() AS syns, uniqExact(dst_port) AS ports,
  min(dst_port) AS min_port, max(dst_port) AS max_port, min(ts) AS first_seen, max(ts) AS last_seen,
  topK(1)(ttl)[1] AS ttl, topK(1)(tcp_win)[1] AS win, topK(1)(tcp_opts)[1] AS opts, groupUniqArray(4)(node) AS nodes
FROM {T} WHERE {W} AND kind = 'syn'
GROUP BY src_ip ORDER BY ports DESC, syns DESC LIMIT {limit:UInt32}`,

	"replays": `SELECT payload_hash, count() AS n, uniqExact(src_ip) AS ips, groupUniqArray(6)(src_ip) AS sample_ips,
  min(ts) AS first_seen, max(ts) AS last_seen, dateDiff('second', min(ts), max(ts)) AS span_s,
  any(payload_len) AS len, any(tls_sni) AS sni, any(dst_port) AS port,
  argMin(src_ip, ts) AS first_src, argMin(auth, ts) AS first_auth, countIf(auth = 'accepted') AS authed,
  groupUniqArray(4)(src_geo) AS geos
FROM {T}
WHERE {W} AND kind IN ('tcp_flow', 'udp_flow') AND payload_hash != ''
GROUP BY payload_hash HAVING ips > 1
ORDER BY n DESC LIMIT {limit:UInt32}`,

	"fp_probe": `SELECT ttl, tcp_win, tcp_opts, mss, ja4, count() AS n, uniqExact(src_ip) AS ips,
  groupUniqArray(5)(src_ip) AS sample_ips, countIf(src_geo = 'cn') AS cn,
  round(avg(payload_len), 1) AS avg_len, round(avg(first_data_ms), 1) AS avg_first_ms
FROM {T}
WHERE {W} AND kind = 'tcp_flow' AND auth != 'accepted' AND port_state != 'closed' AND position(tcp_flags, 'S') > 0
GROUP BY ttl, tcp_win, tcp_opts, mss, ja4
ORDER BY ips DESC, n DESC LIMIT {limit:UInt32}`,

	"fp_scan": `SELECT ttl, tcp_win, tcp_opts, mss, ip_df, count() AS n, uniqExact(src_ip) AS ips,
  uniqExact(dst_port) AS ports, groupUniqArray(5)(src_ip) AS sample_ips, countIf(src_geo = 'cn') AS cn
FROM {T} WHERE {W} AND kind = 'syn'
GROUP BY ttl, tcp_win, tcp_opts, mss, ip_df
ORDER BY ips DESC, n DESC LIMIT {limit:UInt32}`,

	"payload_len": `SELECT payload_len, count() AS n, uniqExact(src_ip) AS ips,
  round(avg(entropy), 2) AS entropy, countIf(tls_sni != '') AS tls
FROM {T}
WHERE {W} AND kind = 'tcp_flow' AND auth != 'accepted' AND port_state != 'closed' AND position(tcp_flags, 'S') > 0
GROUP BY payload_len ORDER BY payload_len`,

	"reaction": `SELECT
  multiIf(s < 0, '无用户连接', s < 1, '<1s', s < 10, '1-10s', s < 60, '10-60s', s < 600, '1-10m', s < 3600, '10-60m', s < 86400, '1-24h', '>24h') AS bucket,
  min(s) AS sort_key, count() AS n, uniqExact(src_ip) AS ips
FROM (
  SELECT p.src_ip AS src_ip,
    if(a.ts = toDateTime64(0, 3, 'UTC'), -1, dateDiff('millisecond', a.ts, p.ts) / 1000) AS s
  FROM (
    SELECT ts, node, dst_port, src_ip FROM {T}
    WHERE {W} AND kind = 'tcp_flow' AND auth != 'accepted' AND port_state = 'node' AND position(tcp_flags, 'S') > 0
  ) AS p
  ASOF LEFT JOIN (
    SELECT ts, node, dst_port FROM {T} WHERE {W} AND kind = 'tcp_flow' AND auth = 'accepted'
  ) AS a
  ON p.node = a.node AND p.dst_port = a.dst_port AND p.ts >= a.ts
)
GROUP BY bucket ORDER BY sort_key`,

	"sni": `SELECT tls_sni, countIf(auth = 'accepted') AS authed, countIf(auth != 'accepted') AS unauth,
  uniqExactIf(src_ip, auth != 'accepted') AS unauth_ips, groupUniqArray(3)(ja4) AS ja4s
FROM {T} WHERE {W} AND kind = 'tcp_flow' AND tls_sni != ''
GROUP BY tls_sni ORDER BY unauth DESC, authed DESC LIMIT {limit:UInt32}`,

	"ports": `SELECT dst_port, proto, any(port_state) AS state, any(node_type) AS node_type,
  countIf(kind = 'syn') AS syn, countIf(kind IN ('tcp_flow', 'udp_flow') AND auth != 'accepted') AS unauth,
  countIf(auth = 'accepted') AS authed, uniqExact(src_ip) AS ips
FROM {T} WHERE {W} AND kind IN ('syn', 'tcp_flow', 'udp_flow')
GROUP BY dst_port, proto ORDER BY syn + unauth DESC LIMIT {limit:UInt32}`,

	"geo": `SELECT if(src_geo = '', '未知', src_geo) AS geo,
  countIf(kind = 'syn') AS syn, countIf(kind = 'tcp_flow' AND auth != 'accepted') AS unauth,
  countIf(kind = 'tcp_flow' AND auth = 'accepted') AS authed, countIf(kind = 'udp_flow') AS udp,
  uniqExact(src_ip) AS ips
FROM {T} WHERE {W} AND src_ip != '' AND kind IN ('syn', 'tcp_flow', 'udp_flow', 'icmp')
GROUP BY geo ORDER BY ips DESC`,

	"udp": `SELECT ts, node, src_ip, src_port, src_geo, dst_port, port_state, node_type, ttl,
  payload_len, round(entropy, 2) AS entropy, payload_head, payload_hash, quic_ver, flow_ms, flow_pkts, flow_bytes, flow_end, auth
FROM {T} WHERE {W} AND kind = 'udp_flow' AND auth != 'accepted'
ORDER BY ts DESC LIMIT {limit:UInt32}`,

	"xray": `SELECT ts, node, kind, src_ip, src_port, src_geo, xray_status, xray_email, xray_target, xray_reason, severity, message
FROM {T}
WHERE {W} AND (kind = 'xray_log' OR (kind = 'xray_access' AND xray_status = 'rejected'))
ORDER BY ts DESC LIMIT {limit:UInt32}`,

	"ip": `SELECT ts, node, kind, proto, src_port, dst_port, port_state, auth, flow_end, flow_ms, flow_pkts,
  payload_len, round(entropy, 2) AS entropy, tls_sni, ja4, ttl, tcp_win, tcp_opts, ts_val, first_data_ms,
  payload_head, xray_status, xray_email, xray_target, xray_reason
FROM {T} WHERE {W} AND src_ip = {ip:String}
ORDER BY ts DESC LIMIT {limit:UInt32}`,

	"stats": `SELECT node, max(ts) AS last_seen, argMax(message, ts) AS stats
FROM {T} WHERE {W} AND kind = 'stats'
GROUP BY node ORDER BY node`,
}
