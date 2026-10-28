package probelog

import "time"

// 事件类型
const (
	KindSyn        = "syn"         // SYN 到未监听端口（扫端口）
	KindTCPFlow    = "tcp_flow"    // 到监听端口的一条 TCP 流（握手指纹 + 首包特征 + 认证结果）
	KindUDPFlow    = "udp_flow"    // 一条 UDP 流（首包特征）
	KindICMP       = "icmp"        // 入站 ICMP
	KindXrayAccess = "xray_access" // xray 接受/拒绝记录
	KindXrayLog    = "xray_log"    // xray 中与探测相关的日志（REALITY、fallback 等）
	KindStats      = "stats"       // 采集器自身统计
)

// 端口状态
const (
	PortNode   = "node"   // v2node 节点端口
	PortListen = "listen" // 其他监听端口（如 SSH）
	PortClosed = "closed"
)

// 认证结果（来自 xray access 日志）
const (
	AuthNone     = "none"
	AuthAccepted = "accepted"
	AuthRejected = "rejected"
)

// Event 对应 ClickHouse 表的一行，json tag 即列名
type Event struct {
	Time time.Time `json:"-"`
	TS   string    `json:"ts"`
	Node string    `json:"node"`
	Kind string    `json:"kind"`

	Proto     string `json:"proto,omitempty"`
	SrcIP     string `json:"src_ip,omitempty"`
	SrcPort   uint16 `json:"src_port,omitempty"`
	DstIP     string `json:"dst_ip,omitempty"`
	DstPort   uint16 `json:"dst_port,omitempty"`
	SrcGeo    string `json:"src_geo,omitempty"`
	PortState string `json:"port_state,omitempty"`
	NodeTag   string `json:"node_tag,omitempty"`
	NodeType  string `json:"node_type,omitempty"`

	// IP / TCP 指纹（取自 SYN，没有 SYN 时取首包）
	TTL        uint8  `json:"ttl,omitempty"`
	IPID       uint16 `json:"ip_id,omitempty"`
	IPDF       uint8  `json:"ip_df,omitempty"`
	TCPFlags   string `json:"tcp_flags,omitempty"`
	TCPWin     uint16 `json:"tcp_win,omitempty"`
	TCPOpts    string `json:"tcp_opts,omitempty"`
	MSS        uint16 `json:"mss,omitempty"`
	TSVal      uint32 `json:"ts_val,omitempty"`
	TSEcr      uint32 `json:"ts_ecr,omitempty"`
	SynRetrans uint16 `json:"syn_retrans,omitempty"`

	// 首个数据包特征
	PayloadLen  uint32  `json:"payload_len,omitempty"`
	PayloadHead string  `json:"payload_head,omitempty"`
	PayloadHash string  `json:"payload_hash,omitempty"`
	Entropy     float32 `json:"entropy,omitempty"`
	Printable   float32 `json:"printable,omitempty"`
	FirstDataMs *int32  `json:"first_data_ms,omitempty"` // SYN 到首个数据包的间隔，未见 SYN 时为空

	// TLS ClientHello
	TLSVer   string `json:"tls_ver,omitempty"`
	TLSSNI   string `json:"tls_sni,omitempty"`
	TLSALPN  string `json:"tls_alpn,omitempty"`
	JA3      string `json:"ja3,omitempty"`
	JA4      string `json:"ja4,omitempty"`
	TLSSIDLn uint8  `json:"tls_sid_len,omitempty"`
	TLSCHLen uint32 `json:"tls_ch_len,omitempty"`

	QUICVer  string `json:"quic_ver,omitempty"`
	ICMPType uint8  `json:"icmp_type,omitempty"`
	ICMPCode uint8  `json:"icmp_code,omitempty"`

	// 流汇总
	FlowMs    uint32 `json:"flow_ms,omitempty"`
	FlowPkts  uint32 `json:"flow_pkts,omitempty"`
	FlowBytes uint64 `json:"flow_bytes,omitempty"`
	FlowEnd   string `json:"flow_end,omitempty"`
	Auth      string `json:"auth,omitempty"`

	// xray
	XrayStatus string `json:"xray_status,omitempty"`
	XrayEmail  string `json:"xray_email,omitempty"`
	XrayTarget string `json:"xray_target,omitempty"`
	XrayReason string `json:"xray_reason,omitempty"`
	XrayDetour string `json:"xray_detour,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Message    string `json:"message,omitempty"`
}
