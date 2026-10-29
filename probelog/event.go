package probelog

import "time"

// SchemaVersion 是事件模型版本。v1 为最初版本（无 flow_id），v2 起有连接实例、修订与质量字段；
// v3 起前缀采集与 TLS 判别分开（prefix_stop）、handshake 区分已核对与推定（hs_flags）、tls_state 增加 conflict；
// v4 起 udp_flow 解密 QUIC 客户端 Initial（quic_initial / quic_sni_first / quic_initials，并填写 tls_*）。
const SchemaVersion = 4

// 事件类型
const (
	KindSyn        = "syn"         // SYN 到未监听端口（扫端口）
	KindTCPFlow    = "tcp_flow"    // 到监听端口的一条 TCP 连接实例（可能有多条记录：snapshot / final / correction）
	KindUDPFlow    = "udp_flow"    // 一条 UDP 流
	KindICMP       = "icmp"        // 入站 ICMP
	KindXrayAccess = "xray_access" // xray access 记录
	KindXrayLog    = "xray_log"    // xray 中与探测相关的日志（关键字线索，不关联到具体连接）
	KindStats      = "stats"       // 采集器自身统计
)

// 流记录类型：同一 flow_id 可以有多条记录，取 revision 最大的一条为当前结论
const (
	RecordSnapshot   = "snapshot"   // 连接仍在进行时的阶段快照
	RecordFinal      = "final"      // 连接结束（或被回收）时的汇总
	RecordCorrection = "correction" // 已输出 final 之后，迟到的日志关联带来的修订（完整行）
)

// 端口状态
const (
	PortNode   = "node"   // v2node 节点端口
	PortListen = "listen" // 其他监听端口（如 SSH）
	PortClosed = "closed"
)

// auth：从 xray access 记录观察到的结果。它是 xray 实现的 access 状态，不等于 REALITY 握手成败。
const (
	AuthAccepted      = "accepted"
	AuthRejected      = "rejected"
	AuthUnknown       = "unknown"        // 没有关联到任何 access 记录（不代表失败）
	AuthNotApplicable = "not_applicable" // 非节点端口（如 SSH），xray 不处理
)

// auth_assoc：access 记录与连接的关联状态
const (
	AssocMatched       = "matched"        // 唯一匹配
	AssocUnmatched     = "unmatched"      // 没有找到 access 记录
	AssocAmbiguous     = "ambiguous"      // 有多个候选连接，未传播认证结果
	AssocNotApplicable = "not_applicable" // 非节点端口
)

// close_by：观察到的关闭方向。只表示采集器看到了哪个方向的 FIN/RST，不能单凭它确定实际发送主体。
const (
	CloseClientFIN = "client_fin"
	CloseClientRST = "client_rst"
	CloseServerFIN = "server_fin"
	CloseServerRST = "server_rst"
	CloseBothFIN   = "both_fin"
	CloseNone      = "none" // 没有观察到 FIN/RST（超时回收、进程退出、仍在进行）
)

// handshake：TCP 三次握手的观察证据
const (
	HandshakeSynOnly     = "syn_only"    // 只看到客户端 SYN
	HandshakeSynAck      = "synack"      // 看到服务端 SYN-ACK（需要双向观测）
	HandshakeEstablished = "established" // 核对过的证据：客户端段的 ACK 可接受（= 节点 ISN+1，full 模式下不超过节点已发送范围）
	HandshakeInferred    = "inferred"    // 推定：SYN 之后有带 ACK 标志的客户端数据/FIN，但 ACK 无法核对（没看到 SYN-ACK，或 control 模式下可能确认了看不到的节点数据）
	HandshakeUnknown     = "unknown"     // 只看入站且没有足够证据
)

// hs_flags：握手相关的异常证据，逗号分隔
const (
	HSFlagBadAck = "bad_ack" // 看到 SYN-ACK 后，客户端段的 ACK 不可接受（早于节点 ISN+1，或 full 模式下超出节点已发送范围）
	HSFlagNoAck  = "no_ack"  // SYN 之后的客户端数据/FIN 没有 ACK 标志
)

// prefix_stop：客户端前缀采集在什么条件下结束
const (
	PrefixStopBytes    = "bytes"    // 达到字节预算：前缀已满 4096 字节且 TLS 判别有结论，或重组缓存满 16 KiB
	PrefixStopWindow   = "window"   // 首个数据段之后 2 秒（按包时间）
	PrefixStopFlowEnd  = "flow_end" // 窗口内连接就结束了（final）
	PrefixStopSnapshot = "snapshot" // 窗口内到了 60 秒快照
	PrefixStopOverflow = "overflow" // 乱序暂存达到上限
)

// Event 对应 ClickHouse 表的一行，json tag 即列名
type Event struct {
	Time time.Time `json:"-"`
	TS   string    `json:"ts"` // 事件发生时间：流记录为连接首次观察时间

	SchemaVersion uint16 `json:"schema_version"`
	EventID       string `json:"event_id"`   // 一条记录的唯一标识，重试上传时不变
	EmittedAt     string `json:"emitted_at"` // 记录生成（处理）时间
	Node          string `json:"node"`
	Kind          string `json:"kind"`

	FlowID     string `json:"flow_id,omitempty"` // 连接实例标识，同一五元组的新连接会得到新 ID
	RecordType string `json:"record_type,omitempty"`
	Revision   uint32 `json:"revision,omitempty"`
	ObsMode    string `json:"obs_mode,omitempty"` // inbound / control / full

	Proto     string `json:"proto,omitempty"`
	SrcIP     string `json:"src_ip,omitempty"`
	SrcPort   uint16 `json:"src_port,omitempty"`
	DstIP     string `json:"dst_ip,omitempty"`
	DstPort   uint16 `json:"dst_port,omitempty"`
	SrcGeo    string `json:"src_geo,omitempty"`
	PortState string `json:"port_state,omitempty"`
	NodeTag   string `json:"node_tag,omitempty"`
	NodeType  string `json:"node_type,omitempty"`

	// IP / TCP 指纹（取自客户端 SYN，没有 SYN 时取首个入站包）
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

	// 首个捕获数据段（不是完整应用消息）
	PayloadLen       uint32  `json:"payload_len,omitempty"`       // 原始长度
	PayloadCapLen    uint32  `json:"payload_cap_len,omitempty"`   // 实际捕获长度
	PayloadTruncated uint8   `json:"payload_truncated,omitempty"` // 1 = 因捕获长度限制丢了尾部
	PayloadHead      string  `json:"payload_head,omitempty"`
	PayloadHash      string  `json:"payload_hash,omitempty"` // 首段捕获字节的 sha256 前 8 字节
	Entropy          float32 `json:"entropy,omitempty"`
	Printable        float32 `json:"printable,omitempty"`
	FirstDataMs      *int32  `json:"first_data_ms,omitempty"` // SYN 到首个数据段的间隔，未见 SYN 时为空

	// 重组后的客户端字节流前缀
	PrefixLen  uint32 `json:"prefix_len,omitempty"`
	PrefixHash string `json:"prefix_hash,omitempty"` // 前 prefix_len 字节的 sha256 前 8 字节
	ReasmFlags string `json:"reasm_flags,omitempty"` // gap / conflict / overflow / truncated / retrans，只描述 prefix_stop 之前
	PrefixStop string `json:"prefix_stop,omitempty"` // 前缀采集结束条件

	// TLS ClientHello（只有 tls_state=complete 时下列指纹才填写；conflict 不填写）
	TLSState string `json:"tls_state,omitempty"`
	TLSVer   string `json:"tls_ver,omitempty"`
	TLSSNI   string `json:"tls_sni,omitempty"`
	TLSALPN  string `json:"tls_alpn,omitempty"`
	JA3      string `json:"ja3,omitempty"`
	JA4      string `json:"ja4,omitempty"`
	TLSSIDLn uint8  `json:"tls_sid_len,omitempty"`
	TLSCHLen uint32 `json:"tls_ch_len,omitempty"`

	QUICVer string `json:"quic_ver,omitempty"`
	// QUIC 客户端 Initial（v4 起，只有 udp_flow）：解密后 CRYPTO 帧里的 ClientHello 写入上面的 tls_* 字段，JA4 以 q 开头
	QUICInitial  string `json:"quic_initial,omitempty"`   // ok / unsupported_version / decrypt_failed / truncated / malformed / no_initial
	QUICSNIFirst string `json:"quic_sni_first,omitempty"` // full / partial / none / no_sni：SNI 字节落在第一个数据报里的程度
	QUICInitials uint8  `json:"quic_initials,omitempty"`  // 含有可解密客户端 Initial 的数据报数（解析结束时）
	ICMPType     uint8  `json:"icmp_type,omitempty"`
	ICMPCode     uint8  `json:"icmp_code,omitempty"`

	// 连接汇总。flow_ms / flow_pkts / flow_bytes 只统计入站（客户端→节点）数据包
	FlowMs    uint32 `json:"flow_ms,omitempty"`
	FlowPkts  uint32 `json:"flow_pkts,omitempty"`
	FlowBytes uint64 `json:"flow_bytes,omitempty"`
	FlowEnd   string `json:"flow_end,omitempty"` // 记录生成原因，见 README
	CloseBy   string `json:"close_by,omitempty"`
	Handshake string `json:"handshake,omitempty"`
	HSFlags   string `json:"hs_flags,omitempty"`

	// 节点→客户端方向（obs_mode=control 时只有控制包，full 时才有数据统计）
	OutPkts       uint32 `json:"out_pkts,omitempty"`
	OutBytes      uint64 `json:"out_bytes,omitempty"`
	FirstRespMs   *int32 `json:"first_resp_ms,omitempty"` // SYN 到节点首个数据段
	RespRecords   string `json:"resp_records,omitempty"`  // 节点响应前几个 TLS record 的 类型:长度
	RespReasmFlag string `json:"resp_reasm_flags,omitempty"`

	Auth      string `json:"auth,omitempty"`
	AuthAssoc string `json:"auth_assoc,omitempty"`

	// xray
	XrayStatus string `json:"xray_status,omitempty"`
	XrayEmail  string `json:"xray_email,omitempty"`
	XrayTarget string `json:"xray_target,omitempty"`
	XrayReason string `json:"xray_reason,omitempty"`
	XrayDetour string `json:"xray_detour,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Message    string `json:"message,omitempty"`
}
