"use strict";

const $ = (s) => document.querySelector(s);
const state = { tab: "probes", ip: "", rawSQL: false, charts: {}, timer: null };

// ---------- 数据 ----------

async function q(name, extra = {}) {
  const p = new URLSearchParams({ hours: $("#hours").value, node: $("#node").value, ...extra });
  const res = await fetch(`api/q/${name}?${p}`);
  if (!res.ok) throw new Error(await res.text());
  return (await res.json()).data;
}

async function rawSQL(sql) {
  const res = await fetch("api/sql", { method: "POST", body: sql });
  if (!res.ok) throw new Error(await res.text());
  return await res.json();
}

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast.h);
  toast.h = setTimeout(() => (t.hidden = true), 6000);
}

// ---------- 格式化 ----------

const fmtNum = (v) => (v == null || v === "" ? "" : Number(v).toLocaleString());
function fmtTime(v) {
  if (!v) return "";
  const d = new Date(String(v).replace(" ", "T") + (String(v).endsWith("Z") ? "" : "Z"));
  if (isNaN(d)) return v;
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const badge = (v) => (v ? `<span class="badge ${esc(v)}">${esc(v)}</span>` : "");
const ipLink = (v) => (v ? `<a class="ip" data-ip="${esc(v)}">${esc(v)}</a>` : "");
const list = (v) => (Array.isArray(v) ? v.filter((x) => x !== "" && x != null).map(esc).join(", ") : esc(v));
const ipList = (v) => (Array.isArray(v) ? v.map(ipLink).join(" ") : ipLink(v));
const hexShort = (v) => (v ? `<span title="${esc(v)}">${esc(v.length > 48 ? v.slice(0, 48) + "…" : v)}</span>` : "");
function hexAscii(v) {
  if (!v) return "";
  let s = "";
  for (let i = 0; i + 1 < v.length && s.length < 32; i += 2) {
    const c = parseInt(v.slice(i, i + 2), 16);
    s += c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : ".";
  }
  return `<span title="${esc(v)}">${esc(s)}</span>`;
}

// 列定义：[key, 标题, 类型]，类型决定渲染方式
const T = {
  time: (v) => fmtTime(v),
  num: (v) => fmtNum(v),
  ip: ipLink,
  ips: ipList,
  badge,
  list,
  hex: hexShort,
  ascii: hexAscii,
  text: esc,
  mono: esc,
  wrap: esc,
  ms: (v) => (v == null || v < 0 ? "" : fmtNum(v)),
};
const NUMERIC = new Set(["num", "ms"]);

function renderTable(el, rows, cols, opts = {}) {
  if (!rows || rows.length === 0) {
    el.innerHTML = `<div class="empty">${opts.empty || "没有数据"}</div>`;
    return;
  }
  let sortKey = opts.sortKey || null;
  let asc = false;
  const draw = () => {
    let data = rows;
    if (sortKey) {
      data = [...rows].sort((a, b) => {
        const x = a[sortKey], y = b[sortKey];
        const r = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y));
        return asc ? r : -r;
      });
    }
    const head = cols
      .map(([k, label]) => `<th data-k="${k}" class="${k === sortKey ? "sorted" + (asc ? " asc" : "") : ""}">${label}</th>`)
      .join("");
    const body = data
      .slice(0, 1000)
      .map(
        (r) =>
          "<tr>" +
          cols
            .map(([k, , t = "text"]) => {
              const cls = NUMERIC.has(t) ? "num" : t === "mono" || t === "hex" || t === "ascii" ? "mono" : t === "wrap" ? "wrap" : "";
              return `<td class="${cls}">${(T[t] || esc)(r[k])}</td>`;
            })
            .join("") +
          "</tr>"
      )
      .join("");
    el.innerHTML = `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
    el.querySelectorAll("th").forEach((th) =>
      th.addEventListener("click", () => {
        const k = th.dataset.k;
        asc = sortKey === k ? !asc : false;
        sortKey = k;
        draw();
      })
    );
  };
  draw();
}

// ---------- 图表 ----------

function cssVar(n) {
  return getComputedStyle(document.documentElement).getPropertyValue(n).trim();
}

function chart(el) {
  const id = el.id;
  const old = state.charts[id];
  if (old && old.getDom() === el) return old;
  if (old) old.dispose();
  state.charts[id] = echarts.init(el);
  return state.charts[id];
}

function baseOption() {
  const text = cssVar("--muted");
  const border = cssVar("--border");
  return {
    textStyle: { color: text },
    grid: { left: 48, right: 16, top: 36, bottom: 36 },
    tooltip: { trigger: "axis" },
    legend: { top: 0, textStyle: { color: text } },
    xAxis: { axisLine: { lineStyle: { color: border } }, axisLabel: { color: text } },
    yAxis: { splitLine: { lineStyle: { color: border } }, axisLabel: { color: text } },
  };
}

const SERIES_COLORS = {
  unauth_node: "#ff6b6b",
  scan_syn: "#f5b84b",
  unauth_other: "#c678dd",
  rejected: "#e5c07b",
  udp: "#56b6c2",
  icmp: "#8b95a3",
  authed: "#4cc38a",
};

async function loadTimeline() {
  const rows = await q("timeline");
  const series = [
    ["unauth_node", "未认证流(节点端口)"],
    ["unauth_other", "未认证流(其他监听端口)"],
    ["scan_syn", "关闭端口 SYN"],
    ["rejected", "xray 拒绝"],
    ["udp", "UDP 流"],
    ["icmp", "ICMP"],
    ["authed", "已认证流"],
  ];
  const opt = baseOption();
  opt.xAxis.type = "time";
  // 扫端口的量通常比探测大几个数量级，单独放右轴，避免把未认证流压成一条线
  opt.yAxis = [
    { ...opt.yAxis, type: "value", name: "流", nameTextStyle: { color: cssVar("--muted") } },
    { ...opt.yAxis, type: "value", name: "SYN", splitLine: { show: false }, nameTextStyle: { color: cssVar("--muted") } },
  ];
  opt.grid.right = 56;
  opt.series = series.map(([k, name]) => ({
    name,
    type: "line",
    showSymbol: false,
    smooth: true,
    color: SERIES_COLORS[k],
    yAxisIndex: k === "scan_syn" ? 1 : 0,
    lineStyle: k === "scan_syn" ? { type: "dashed", width: 1 } : undefined,
    areaStyle: k === "unauth_node" ? { opacity: 0.15 } : undefined,
    data: rows.map((r) => [new Date(String(r.t).replace(" ", "T") + "Z"), r[k]]),
  }));
  opt.legend.selected = { "已认证流": false, ICMP: false };
  chart($("#timeline")).setOption(opt, true);
}

function barChart(el, rows, xKey, series, xName) {
  const opt = baseOption();
  opt.xAxis.type = "category";
  opt.xAxis.name = xName;
  opt.xAxis.data = rows.map((r) => r[xKey]);
  opt.yAxis.type = "value";
  opt.series = series.map(([k, name, color]) => ({ name, type: "bar", color, data: rows.map((r) => r[k]) }));
  chart(el).setOption(opt, true);
}

// ---------- KPI ----------

async function loadKPIs() {
  const [o] = await q("overview");
  const items = [
    ["未认证节点流", o.unauth_node_flows, `${fmtNum(o.unauth_sources)} 个来源`, "danger"],
    ["关闭端口 SYN", o.closed_syn, `${fmtNum(o.scanners)} 个扫描源`, "warn"],
    ["中国来源未认证事件", o.cn_unauth, "SYN / 未认证 TCP / UDP", "danger"],
    ["xray 拒绝", o.rejected, `REALITY 日志 ${fmtNum(o.reality_logs)}`, "warn"],
    ["已认证流", o.authed_flows, "按采样率记录", "ok"],
    ["关闭端口 UDP", o.udp_closed, "", ""],
    ["事件总数", o.events, `${fmtNum(o.sources)} 个来源 IP`, ""],
  ];
  $("#kpis").innerHTML = items
    .map(([l, v, s, c]) => `<div class="kpi ${c}"><div class="label">${l}</div><div class="value">${fmtNum(v)}</div><div class="sub">${esc(s)}</div></div>`)
    .join("");
}

// ---------- 标签页 ----------

function section(title, hint, body = "") {
  return `<div class="card"><div class="card-head"><h2>${title}</h2>${hint ? `<p class="hint">${hint}</p>` : ""}</div>${body}</div>`;
}

const TABS = [
  {
    id: "probes",
    title: "探测流量",
    async render(p) {
      p.innerHTML =
        section("来源汇总", "按来源 IP 聚合未认证的 TCP 流。“已认证=0”的来源从未成功使用节点，最可能是探测器；有已认证记录的多半是用户的失败连接。", '<div id="t1"></div>') +
        section("明细", "每条未认证流的 SYN 指纹、首包特征与结束方式。首包十六进制可悬停查看，first_ms 为 SYN 到首个数据包的毫秒数。", '<div id="t2"></div>');
      const [src, rows] = await Promise.all([q("probe_sources"), q("probes", { limit: 500 })]);
      renderTable($("#t1"), src, [
        ["src_ip", "来源", "ip"], ["geo", "地区", "badge"], ["unauth", "未认证", "num"], ["authed", "已认证", "num"],
        ["ports", "端口数", "num"], ["no_data", "无数据", "num"], ["lens", "首包长度", "list"], ["snis", "SNI", "list"],
        ["ttl", "TTL", "num"], ["opts", "TCP 选项", "mono"], ["nodes", "节点", "list"],
        ["first_seen", "首次", "time"], ["last_seen", "最近", "time"],
      ]);
      renderTable($("#t2"), rows, [
        ["ts", "时间", "time"], ["src_ip", "来源", "ip"], ["src_geo", "地区", "badge"], ["node", "节点"], ["dst_port", "端口", "num"],
        ["port_state", "端口", "badge"], ["node_type", "类型"], ["flow_end", "结束"], ["flow_ms", "时长ms", "num"],
        ["first_data_ms", "first_ms", "ms"], ["payload_len", "首包", "num"], ["entropy", "熵", "num"], ["printable", "可打印", "num"],
        ["tls_sni", "SNI"], ["tls_ver", "TLS"], ["ja4", "JA4", "mono"], ["tls_sid_len", "SID", "num"], ["payload_head", "首包 hex", "hex"],
        ["payload_head", "ASCII", "ascii"], ["ttl", "TTL", "num"], ["ip_id", "IPID", "num"], ["tcp_win", "窗口", "num"], ["tcp_opts", "TCP 选项", "mono"],
        ["ts_val", "TSval", "num"], ["syn_retrans", "SYN重传", "num"], ["flow_pkts", "包", "num"], ["flow_bytes", "字节", "num"],
      ]);
    },
  },
  {
    id: "scan",
    title: "扫端口",
    async render(p) {
      p.innerHTML =
        section("扫描源", "SYN 打到未监听端口的来源。端口数大的是全端口扫描器；只扫少数端口的值得和探测流量对照。", '<div id="t1"></div>') +
        section("扫描器 SYN 指纹", "相同 TTL / 窗口 / TCP 选项组合覆盖多个 IP，说明背后可能是同一套扫描程序。", '<div id="t2"></div>');
      const [s, f] = await Promise.all([q("scanners", { limit: 500 }), q("fp_scan")]);
      renderTable($("#t1"), s, [
        ["src_ip", "来源", "ip"], ["geo", "地区", "badge"], ["syns", "SYN", "num"], ["ports", "端口数", "num"],
        ["min_port", "最小端口", "num"], ["max_port", "最大端口", "num"], ["ttl", "TTL", "num"], ["win", "窗口", "num"],
        ["opts", "TCP 选项", "mono"], ["nodes", "节点", "list"], ["first_seen", "首次", "time"], ["last_seen", "最近", "time"],
      ]);
      renderTable($("#t2"), f, [
        ["ips", "IP 数", "num"], ["n", "SYN", "num"], ["ports", "端口数", "num"], ["cn", "中国", "num"], ["ttl", "TTL", "num"],
        ["tcp_win", "窗口", "num"], ["mss", "MSS", "num"], ["ip_df", "DF", "num"], ["tcp_opts", "TCP 选项", "mono"], ["sample_ips", "样例", "ips"],
      ]);
    },
  },
  {
    id: "replay",
    title: "重放检测",
    async render(p) {
      p.innerHTML = section(
        "首包重放",
        "同一首包（sha256）出现在多个来源 IP 上。如果第一次出现是已认证的用户连接、之后来自其他 IP，就是典型的重放探测。",
        '<div id="t1"></div>'
      );
      renderTable($("#t1"), await q("replays"), [
        ["payload_hash", "首包哈希", "mono"], ["n", "次数", "num"], ["ips", "IP 数", "num"], ["first_src", "首个来源", "ip"],
        ["first_auth", "首次认证", "badge"], ["authed", "已认证次数", "num"], ["sample_ips", "来源样例", "ips"], ["geos", "地区", "list"],
        ["len", "长度", "num"], ["sni", "SNI"], ["port", "端口", "num"], ["span_s", "跨度秒", "num"],
        ["first_seen", "首次", "time"], ["last_seen", "最近", "time"],
      ], { empty: "没有发现跨 IP 重复的首包" });
    },
  },
  {
    id: "fp",
    title: "指纹聚类",
    async render(p) {
      p.innerHTML = section(
        "探测器指纹",
        "按 TTL、TCP 窗口、TCP 选项、MSS、JA4 聚合未认证流。一组指纹对应大量不同 IP 时，这些 IP 很可能由同一个探测系统控制。",
        '<div id="t1"></div>'
      );
      renderTable($("#t1"), await q("fp_probe"), [
        ["ips", "IP 数", "num"], ["n", "流", "num"], ["cn", "中国", "num"], ["ttl", "TTL", "num"], ["tcp_win", "窗口", "num"],
        ["mss", "MSS", "num"], ["tcp_opts", "TCP 选项", "mono"], ["ja4", "JA4", "mono"], ["avg_len", "平均首包", "num"],
        ["avg_first_ms", "平均 first_ms", "num"], ["sample_ips", "样例", "ips"],
      ]);
    },
  },
  {
    id: "timing",
    title: "长度与时机",
    async render(p) {
      p.innerHTML =
        '<div class="grid2">' +
        section("未认证流首包长度", "已知的探测器会发出特定长度的首包；0 表示建连后没发数据就断开。", '<div id="c1" class="chart"></div>') +
        section("探测距上次用户连接的时间", "每条未认证流与同节点同端口上一次已认证连接的时间差。集中在短区间说明探测由真实用户流量触发。", '<div id="c2" class="chart"></div>') +
        "</div>" +
        section("首包长度明细", "", '<div id="t1"></div>');
      const [lens, react] = await Promise.all([q("payload_len"), q("reaction")]);
      barChart($("#c1"), lens.slice(0, 120), "payload_len", [["n", "流", "#ff6b6b"], ["ips", "IP 数", "#5aa9ff"]], "字节");
      barChart($("#c2"), react, "bucket", [["n", "流", "#f5b84b"], ["ips", "IP 数", "#5aa9ff"]], "");
      renderTable($("#t1"), lens, [["payload_len", "长度", "num"], ["n", "流", "num"], ["ips", "IP 数", "num"], ["entropy", "平均熵", "num"], ["tls", "TLS", "num"]]);
    },
  },
  {
    id: "dims",
    title: "SNI / 端口 / 地区",
    async render(p) {
      p.innerHTML =
        section("SNI", "探测连接带的 SNI。和节点配置的 serverName 对比，可以看出探测方是否知道你借用的域名。", '<div id="t1"></div>') +
        '<div class="grid2">' +
        section("端口", "", '<div id="t2"></div>') +
        section("地区", "地区标签来自节点配置 GeoTags，未列出的国家归为 other。", '<div id="c1" class="chart"></div><div id="t3"></div>') +
        "</div>";
      const [sni, ports, geo] = await Promise.all([q("sni"), q("ports"), q("geo")]);
      renderTable($("#t1"), sni, [["tls_sni", "SNI"], ["unauth", "未认证", "num"], ["unauth_ips", "未认证 IP", "num"], ["authed", "已认证", "num"], ["ja4s", "JA4", "list"]]);
      renderTable($("#t2"), ports, [["dst_port", "端口", "num"], ["proto", "协议"], ["state", "状态", "badge"], ["node_type", "类型"], ["syn", "SYN", "num"], ["unauth", "未认证", "num"], ["authed", "已认证", "num"], ["ips", "IP 数", "num"]]);
      barChart($("#c1"), geo, "geo", [["syn", "关闭端口 SYN", "#f5b84b"], ["unauth", "未认证", "#ff6b6b"], ["authed", "已认证", "#4cc38a"]], "");
      renderTable($("#t3"), geo, [["geo", "地区", "badge"], ["ips", "IP 数", "num"], ["syn", "SYN", "num"], ["unauth", "未认证", "num"], ["authed", "已认证", "num"], ["udp", "UDP", "num"]]);
    },
  },
  {
    id: "udp",
    title: "UDP",
    async render(p) {
      p.innerHTML = section("未认证 UDP 流", "到节点 UDP 端口（hysteria2 / tuic）以及低端口的 UDP 首包。QUIC 长包头会解析出版本号。", '<div id="t1"></div>');
      renderTable($("#t1"), await q("udp", { limit: 500 }), [
        ["ts", "时间", "time"], ["src_ip", "来源", "ip"], ["src_geo", "地区", "badge"], ["node", "节点"], ["dst_port", "端口", "num"],
        ["port_state", "端口", "badge"], ["node_type", "类型"], ["quic_ver", "QUIC"], ["payload_len", "首包", "num"], ["entropy", "熵", "num"],
        ["payload_head", "首包 hex", "hex"], ["flow_pkts", "包", "num"], ["flow_bytes", "字节", "num"], ["flow_ms", "时长ms", "num"], ["flow_end", "结束"],
      ]);
    },
  },
  {
    id: "xray",
    title: "Xray 日志",
    async render(p) {
      p.innerHTML = section("拒绝记录与相关日志", "xray 的拒绝记录和包含 REALITY / fallback / invalid 等关键字的日志。REALITY 的无效连接日志不带来源地址，按时间和“探测流量”对照。", '<div id="t1"></div>');
      renderTable($("#t1"), await q("xray", { limit: 1000 }), [
        ["ts", "时间", "time"], ["node", "节点"], ["kind", "类型"], ["src_ip", "来源", "ip"], ["src_port", "端口", "num"], ["src_geo", "地区", "badge"],
        ["xray_status", "状态", "badge"], ["severity", "级别"], ["xray_reason", "原因", "wrap"], ["message", "日志", "wrap"],
      ]);
    },
  },
  {
    id: "ip",
    title: "IP 查询",
    async render(p) {
      p.innerHTML = section(
        "单个 IP 的全部事件",
        "点击任意表格里的 IP 也会跳到这里。",
        `<div class="row"><input type="text" id="ipq" placeholder="输入 IP" value="${esc(state.ip)}"><button id="ipgo" type="button">查询</button></div><div id="t1"></div>`
      );
      const go = async () => {
        state.ip = $("#ipq").value.trim();
        if (!state.ip) {
          $("#t1").innerHTML = '<div class="empty">输入一个 IP</div>';
          return;
        }
        $("#t1").innerHTML = '<div class="loading">查询中…</div>';
        renderTable($("#t1"), await q("ip", { ip: state.ip, limit: 1000 }), [
          ["ts", "时间", "time"], ["node", "节点"], ["kind", "类型"], ["proto", "协议"], ["src_port", "源端口", "num"], ["dst_port", "端口", "num"],
          ["port_state", "端口", "badge"], ["auth", "认证", "badge"], ["flow_end", "结束"], ["flow_ms", "时长ms", "num"], ["payload_len", "首包", "num"],
          ["entropy", "熵", "num"], ["tls_sni", "SNI"], ["ja4", "JA4", "mono"], ["ttl", "TTL", "num"], ["tcp_win", "窗口", "num"],
          ["tcp_opts", "TCP 选项", "mono"], ["ts_val", "TSval", "num"], ["first_data_ms", "first_ms", "ms"], ["payload_head", "首包 hex", "hex"],
          ["xray_status", "xray", "badge"], ["xray_email", "用户"], ["xray_target", "目标"], ["xray_reason", "原因", "wrap"],
        ], { empty: "这个时间范围内没有该 IP 的事件" });
      };
      $("#ipgo").addEventListener("click", () => go().catch(showErr));
      $("#ipq").addEventListener("keydown", (e) => e.key === "Enter" && go().catch(showErr));
      await go();
    },
  },
  {
    id: "sql",
    title: "SQL",
    when: () => state.rawSQL,
    async render(p) {
      const def = "SELECT kind, count() FROM probe_events WHERE ts > now() - INTERVAL 1 DAY GROUP BY kind ORDER BY 2 DESC";
      p.innerHTML = section(
        "自定义查询",
        "只读执行，最多返回 10000 行。表名 probe_events。",
        `<textarea id="sqlq">${esc(localStorage.getItem("v2node.sql") || def)}</textarea><div class="row"><button id="sqlgo" type="button">执行</button></div><div id="t1"></div>`
      );
      $("#sqlgo").addEventListener("click", async () => {
        const sql = $("#sqlq").value;
        try { localStorage.setItem("v2node.sql", sql); } catch (_) {}
        $("#t1").innerHTML = '<div class="loading">执行中…</div>';
        try {
          const r = await rawSQL(sql);
          const cols = r.meta.map((m) => [m.name, m.name, /Int|Float|Decimal/.test(m.type) ? "num" : /DateTime/.test(m.type) ? "time" : "text"]);
          renderTable($("#t1"), r.data, cols);
        } catch (e) {
          $("#t1").innerHTML = `<div class="error">${esc(e.message)}</div>`;
        }
      });
    },
  },
  {
    id: "stats",
    title: "采集状态",
    async render(p) {
      p.innerHTML = section("各节点采集器状态", "每分钟一条。rate_dropped / sink_*_dropped 不为 0 说明有事件因限速或上传积压被丢弃。", '<div id="t1"></div>');
      const rows = (await q("stats")).map((r) => {
        let s = {};
        try { s = JSON.parse(r.stats); } catch (_) {}
        return { node: r.node, last_seen: r.last_seen, ...s };
      });
      renderTable($("#t1"), rows, [
        ["node", "节点"], ["last_seen", "最近上报", "time"], ["capture", "抓包"], ["packets", "抓包数", "num"], ["emitted", "事件", "num"],
        ["flows", "当前流", "num"], ["rate_dropped", "限速丢弃", "num"], ["sampled_out", "采样丢弃", "num"], ["parse_errors", "解析错误", "num"],
        ["sink_sent", "已上传", "num"], ["sink_pending", "待上传", "num"], ["sink_chan_dropped", "通道丢弃", "num"],
        ["sink_buffer_dropped", "缓冲丢弃", "num"], ["sink_send_errors", "上传错误", "num"], ["sink_last_error", "最近错误", "wrap"],
      ], { empty: "还没有采集器上报状态（每分钟一次）" });
    },
  },
];

function showErr(e) {
  toast(e.message || String(e));
}

function drawTabs() {
  $("#tabs").innerHTML = TABS.filter((t) => !t.when || t.when())
    .map((t) => `<button type="button" data-tab="${t.id}" class="${t.id === state.tab ? "active" : ""}">${t.title}</button>`)
    .join("");
}

async function loadTab() {
  const tab = TABS.find((t) => t.id === state.tab) || TABS[0];
  const p = $("#panel");
  p.innerHTML = '<div class="card loading">加载中…</div>';
  try {
    await tab.render(p);
  } catch (e) {
    p.innerHTML = `<div class="card error">${esc(e.message)}</div>`;
  }
}

async function refresh() {
  const results = await Promise.allSettled([loadKPIs(), loadTimeline(), loadTab()]);
  results.filter((r) => r.status === "rejected").forEach((r) => showErr(r.reason));
}

async function loadNodes() {
  try {
    const rows = await q("nodes");
    const sel = $("#node");
    const cur = sel.value;
    sel.innerHTML = '<option value="">全部</option>' + rows.map((r) => `<option>${esc(r.node)}</option>`).join("");
    sel.value = cur;
  } catch (e) {
    showErr(e);
  }
}

function saveView() {
  try {
    localStorage.setItem("v2node.view", JSON.stringify({ hours: $("#hours").value, tab: state.tab }));
  } catch (_) {}
}

async function init() {
  try {
    const v = JSON.parse(localStorage.getItem("v2node.view") || "{}");
    if (v.hours) $("#hours").value = v.hours;
    if (v.tab) state.tab = v.tab;
  } catch (_) {}
  try {
    state.rawSQL = (await (await fetch("api/config")).json()).raw_sql;
  } catch (_) {}
  if (!TABS.find((t) => t.id === state.tab && (!t.when || t.when()))) state.tab = "probes";
  drawTabs();

  $("#tabs").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-tab]");
    if (!b) return;
    state.tab = b.dataset.tab;
    saveView();
    drawTabs();
    loadTab();
  });
  document.addEventListener("click", (e) => {
    const a = e.target.closest("a.ip");
    if (!a) return;
    state.ip = a.dataset.ip;
    state.tab = "ip";
    drawTabs();
    loadTab();
    window.scrollTo({ top: $("#tabs").offsetTop - 70, behavior: "smooth" });
  });
  $("#hours").addEventListener("change", () => { saveView(); refresh(); });
  $("#node").addEventListener("change", refresh);
  $("#refresh").addEventListener("click", refresh);
  $("#auto").addEventListener("change", (e) => {
    clearInterval(state.timer);
    if (e.target.checked) state.timer = setInterval(refresh, 60000);
  });
  window.addEventListener("resize", () => Object.values(state.charts).forEach((c) => c.resize()));

  await loadNodes();
  await refresh();
}

init();
