package probelog

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"hash/fnv"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxFlows          = 200000           // 活跃连接上限
	maxTracked        = 400000           // 活跃 + 等待迟到日志的已结束连接上限
	clientPrefixLimit = 16 * 1024        // 客户端字节流前缀上限
	serverPrefixLimit = 4 * 1024         // 节点响应前缀上限（full 模式）
	prefixHashMax     = 4096             // prefix_hash 覆盖的最大字节数
	respRecordsMax    = 8                // 记录节点响应前几个 TLS record
	firstFlightWait   = 2 * time.Second  // 首包/首个响应最多等待多久补齐
	closeGrace        = 2 * time.Second  // 观察到 RST 或双向 FIN 后，等迟到日志的时间
	halfCloseWait     = 10 * time.Second // 只看到单向 FIN 时等待另一方向的时间
	snapshotAfter     = 60 * time.Second // 长连接第一次快照
	tcpIdleTimeout    = 15 * time.Minute // 只看入站时，下载为主的连接可能长时间没有入站包
	tcpSynOnlyTimeout = 30 * time.Second
	udpIdleTimeout    = 30 * time.Second
	sweepInterval     = time.Second
	listenRefresh     = 15 * time.Second
)

// flowKey 是连接的完整五元组，始终以“客户端 → 节点”方向表示
type flowKey struct {
	proto  uint8
	client netip.AddrPort
	server netip.AddrPort
}

// srcKey 用于把 xray access 记录（只有来源地址）关联到连接
type srcKey struct {
	udp    bool
	client netip.AddrPort
}

type flow struct {
	id   string
	key  flowKey
	base Event // 不变字段：身份、指纹、首段特征、TLS；每次输出都复制一份

	first   time.Time
	last    time.Time // 最后一个入站包（flow_ms 的终点）
	lastAny time.Time // 任一方向最后一个可观察的包（回收计时）

	hasSyn   bool
	synAt    time.Time
	synSeq   uint32
	synCount uint16

	firstSegDone bool
	dataAt       time.Time
	pkts         uint32
	bytes        uint64

	cli        *reassembler
	cliFlags   string
	prefixDone bool // 客户端前缀采集已结束（与 TLS 判别是否结束无关）

	hasSynAck  bool
	srvISN     uint32
	srvSent    int64 // 观察到的节点已发送序列号跨度（数据 + FIN），相对 ISN+1
	hsVerified bool  // 客户端 ACK 了节点 ISN（可接受的 ACK）
	hsInferred bool  // 带 ACK 的客户端数据/FIN，但无法核对 ACK（没看到 SYN-ACK，或可能确认了看不到的节点数据）
	hsBadAck   bool  // 客户端段的 ACK 不可接受
	hsNoAck    bool  // 客户端数据/FIN 没有 ACK 标志
	srv        *reassembler
	quic       *quicState // UDP：客户端 Initial 解析，结束后置空
	respAt     time.Time
	respFrozen bool
	outPkts    uint32
	outBytes   uint64

	clientFin, clientRst, serverFin, serverRst bool
	closeDeadline                              time.Time // 观察到关闭后何时输出 final
	endAt                                      time.Time // final 输出时间

	auth  string
	assoc string

	revision     uint32
	snapshotDone bool
	finalized    bool
	emittedAny   bool
	suppressed   bool // 已认证流被采样丢弃（对整条连接稳定）
}

// access 记录的关联状态
const (
	logUndecided = iota // 候选窗口还没关闭
	logMatched          // 已归属到唯一候选
	logAmbiguous        // 有多个候选，没有传播认证结果
)

// pendingLog 是一条 access 记录。决定之后仍保留 lateWindow，用于复核之后才处理到的候选连接。
type pendingLog struct {
	at     time.Time
	status string
	state  int
	target *flow
}

// flowTable 跟踪到本机监听端口的连接实例，在快照、结束和迟到修订时输出记录
type flowTable struct {
	r         *Recorder
	mu        sync.Mutex
	flows     map[flowKey]*flow  // 活跃连接（含已观察到关闭、等待输出 final 的）
	bySrc     map[srcKey][]*flow // 用于日志关联：活跃 + 结束后 lateWindow 内的连接
	tracked   int                // bySrc 中的连接总数
	pending   map[srcKey][]pendingLog
	pendingN  int
	listenTCP atomic.Pointer[map[uint16]bool]
	listenUDP atomic.Pointer[map[uint16]bool]
	obsMode   string
	done      chan struct{}
	wg        sync.WaitGroup
}

func newFlowTable(r *Recorder, obsMode string) *flowTable {
	t := &flowTable{
		r:       r,
		flows:   make(map[flowKey]*flow),
		bySrc:   make(map[srcKey][]*flow),
		pending: make(map[srcKey][]pendingLog),
		obsMode: obsMode,
		done:    make(chan struct{}),
	}
	t.refreshListen()
	t.wg.Add(1)
	go t.sweepLoop()
	return t
}

func newFlowID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (t *flowTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.flows)
}

// Close 停止清理，把仍在进行的连接以 shutdown 输出 final
func (t *flowTable) Close() {
	close(t.done)
	t.wg.Wait()
	t.mu.Lock()
	var out []*Event
	for _, f := range t.flows {
		out = t.appendFinal(out, f, "shutdown", time.Now())
	}
	t.flows = map[flowKey]*flow{}
	t.mu.Unlock()
	for _, e := range out {
		t.r.emit(e)
	}
}

func (t *flowTable) refreshListen() {
	tcp, udp := readListenPorts()
	t.listenTCP.Store(&tcp)
	t.listenUDP.Store(&udp)
}

func (t *flowTable) portState(udp bool, port uint16) (string, NodePort) {
	if np, ok := lookupNodePort(udp, port); ok {
		return PortNode, np
	}
	m := t.listenTCP.Load()
	if udp {
		m = t.listenUDP.Load()
	}
	if m != nil && (*m)[port] {
		return PortListen, NodePort{}
	}
	return PortClosed, NodePort{}
}

func protoName(p uint8) string {
	if p == ipProtoUDP {
		return "udp"
	}
	return "tcp"
}

func baseEvent(kind string, key flowKey, state string, np NodePort, now time.Time) Event {
	nodeType := np.Type
	if np.Security != "" && np.Security != "none" {
		nodeType += "+" + np.Security
	}
	return Event{
		Time:      now,
		Kind:      kind,
		Proto:     protoName(key.proto),
		SrcIP:     key.client.Addr().String(),
		SrcPort:   key.client.Port(),
		DstIP:     key.server.Addr().String(),
		DstPort:   key.server.Port(),
		PortState: state,
		NodeTag:   np.Tag,
		NodeType:  nodeType,
	}
}

// handle 处理一个数据包
func (t *flowTable) handle(p *packet, now time.Time) {
	var out []*Event
	switch p.proto {
	case ipProtoICMP, ipProtoICMPv6:
		if p.outgoing {
			return
		}
		e := &Event{
			Time:     now,
			Kind:     KindICMP,
			Proto:    "icmp",
			SrcIP:    p.src.Unmap().String(),
			DstIP:    p.dst.Unmap().String(),
			ICMPType: p.icmpType,
			ICMPCode: p.icmpCode,
			TTL:      p.ttl,
			IPID:     p.ipID,
		}
		out = append(out, e)
	case ipProtoTCP:
		if p.outgoing {
			t.handleTCPOut(p, now)
		} else {
			out = t.handleTCPIn(p, now)
		}
	case ipProtoUDP:
		if !p.outgoing {
			out = t.handleUDP(p, now)
		}
	}
	for _, e := range out {
		t.r.emit(e)
	}
}

func inboundKey(p *packet) flowKey {
	return flowKey{
		proto:  p.proto,
		client: netip.AddrPortFrom(p.src.Unmap(), p.sport),
		server: netip.AddrPortFrom(p.dst.Unmap(), p.dport),
	}
}

// newFlow 建立新连接实例并登记到关联索引。调用方持有锁。
func (t *flowTable) newFlow(kind string, key flowKey, state string, np NodePort, now time.Time) (*flow, []*Event) {
	if len(t.flows) >= maxFlows || t.tracked >= maxTracked {
		t.r.stats.flowTableFull.Add(1)
		return nil, nil
	}
	f := &flow{
		id:      newFlowID(),
		key:     key,
		base:    baseEvent(kind, key, state, np, now),
		first:   now,
		last:    now,
		lastAny: now,
	}
	if state == PortNode {
		f.auth, f.assoc = AuthUnknown, AssocUnmatched
	} else {
		f.auth, f.assoc = AuthNotApplicable, AssocNotApplicable
	}
	t.flows[key] = f
	sk := srcKey{udp: key.proto == ipProtoUDP, client: key.client}
	t.bySrc[sk] = append(t.bySrc[sk], f)
	t.tracked++
	// 已经做出决定的 access 记录：如果新连接也落在它的候选窗口里，原来的归属不再唯一，改为 ambiguous。
	// 还没决定的记录在候选窗口关闭后统一处理（resolveLogs），不在这里抢先绑定第一个出现的连接。
	var out []*Event
	if state == PortNode {
		logs := t.pending[sk]
		for i := range logs {
			l := &logs[i]
			if l.state == logUndecided || !t.isCandidate(f, l.at) {
				continue
			}
			if l.state == logMatched && l.target != f {
				t.r.stats.assocAmbiguous.Add(1)
				if e := t.setAuth(l.target, AuthUnknown, AssocAmbiguous); e != nil {
					out = append(out, e)
				}
				l.state, l.target = logAmbiguous, nil
			}
			if l.state == logAmbiguous && f.assoc != AssocMatched {
				t.setAuth(f, f.auth, AssocAmbiguous)
			}
		}
	}
	return f, out
}

func (t *flowTable) handleTCPIn(p *packet, now time.Time) []*Event {
	isSyn := p.flags&tcpSYN != 0 && p.flags&tcpACK == 0
	state, np := t.portState(false, p.dport)
	if isSyn && state == PortClosed {
		// 关闭端口上的 SYN 不建流，直接记一条扫描事件
		key := inboundKey(p)
		e := baseEvent(KindSyn, key, state, np, now)
		fillIPFingerprint(&e, p)
		return []*Event{&e}
	}
	key := inboundKey(p)
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []*Event
	f := t.flows[key]
	if f != nil && isSyn {
		switch {
		case f.hasSyn && p.seq == f.synSeq:
			// 同一 ISN：SYN 重传
			f.synCount++
			f.last, f.lastAny = now, now
			return nil
		default:
			// 同一五元组的新连接（新 ISN，或旧连接是中途接上的）：旧连接结束，开始新实例
			out = t.appendFinal(out, f, "superseded", now)
			delete(t.flows, key)
			f = nil
		}
	}
	if f == nil {
		if !isSyn && len(p.payload) == 0 {
			// 不认识的连接上的 FIN/RST（多半在记录器启动前建立），忽略
			return out
		}
		var corr []*Event
		f, corr = t.newFlow(KindTCPFlow, key, state, np, now)
		if f == nil {
			return out
		}
		out = append(out, corr...)
		if isSyn {
			f.hasSyn = true
			f.synAt = now
			f.synSeq = p.seq
			f.cli = newReassembler(p.seq, clientPrefixLimit)
		} else {
			t.r.stats.midstreamFlows.Add(1)
		}
		fillIPFingerprint(&f.base, p)
		if isSyn {
			return out
		}
	}
	f.last, f.lastAny = now, now
	if p.flags&tcpRST == 0 {
		t.noteClientAck(f, p)
	}
	if n := len(p.payload); n > 0 {
		f.pkts++
		f.bytes += uint64(p.payloadWire)
		if !f.firstSegDone {
			f.firstSegDone = true
			f.dataAt = now
			fillFirstSegment(&f.base, p, t.r.cfg.PayloadHeadBytes)
			if f.hasSyn {
				ms := int32(now.Sub(f.synAt).Milliseconds())
				f.base.FirstDataMs = &ms
			}
		} else if !f.prefixDone && now.Sub(f.dataAt) > firstFlightWait {
			// 采集窗口按包时间判断，不依赖清理协程何时运行
			t.finishPrefix(f, PrefixStopWindow)
		}
		if f.cli != nil && !f.prefixDone {
			f.cli.add(p.seq, p.payload, p.truncated)
			t.checkClientPrefix(f)
		}
	}
	if p.flags&tcpRST != 0 {
		f.clientRst = true
		t.markClosing(f, now)
	} else if p.flags&tcpFIN != 0 {
		f.clientFin = true
		t.markClosing(f, now)
	}
	return out
}

// noteClientAck 根据客户端数据/FIN 段的 ACK 记录握手证据。
//
// 节点在 SYN-RECEIVED 状态只接受 ACK = 节点 ISN+1（RFC 9293 §3.10.7.4）；纯 ACK 被 BPF 排除，
// 所以看到的第一个客户端段可能已经确认了节点之后发出的数据。能核对时才算 verified，
// 不能核对时只给推定，确定不可接受的 ACK 不算握手证据。
func (t *flowTable) noteClientAck(f *flow, p *packet) {
	if !f.hasSyn || p.flags&tcpSYN != 0 {
		return
	}
	if p.flags&tcpACK == 0 {
		f.hsNoAck = true
		return
	}
	if f.hsVerified {
		return
	}
	if !f.hasSynAck {
		f.hsInferred = true
		return
	}
	d := int64(int32(p.ack - (f.srvISN + 1)))
	switch {
	case d == 0:
		f.hsVerified = true
	case d < 0:
		f.hsBadAck = true
	case t.obsMode == ObsFull && d <= f.srvSent:
		f.hsVerified = true
	case t.obsMode == ObsFull:
		// full 模式能看到节点数据，ACK 超出了节点已发送的范围
		f.hsBadAck = true
	default:
		// control 模式看不到节点数据，ACK 可能确认了这些数据
		f.hsInferred = true
	}
}

// handleTCPOut 处理节点发出的包（control / full 模式）
func (t *flowTable) handleTCPOut(p *packet, now time.Time) {
	key := flowKey{
		proto:  p.proto,
		client: netip.AddrPortFrom(p.dst.Unmap(), p.dport),
		server: netip.AddrPortFrom(p.src.Unmap(), p.sport),
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.flows[key]
	if f == nil {
		return
	}
	f.lastAny = now
	if p.flags&tcpSYN != 0 && p.flags&tcpACK != 0 {
		if !f.hasSynAck {
			f.hasSynAck = true
			f.srvISN = p.seq
			if t.obsMode == ObsFull {
				f.srv = newReassembler(p.seq, serverPrefixLimit)
			}
		}
		return
	}
	if f.hasSynAck && p.flags&tcpRST == 0 {
		end := int64(int32(p.seq-(f.srvISN+1))) + int64(p.payloadWire)
		if p.flags&tcpFIN != 0 {
			end++
		}
		f.srvSent = max(f.srvSent, end)
	}
	if n := len(p.payload); n > 0 && t.obsMode == ObsFull {
		f.outPkts++
		f.outBytes += uint64(p.payloadWire)
		if f.respAt.IsZero() {
			f.respAt = now
		}
		if f.srv != nil && !f.respFrozen {
			f.srv.add(p.seq, p.payload, p.truncated)
			if len(f.srv.prefix()) >= serverPrefixLimit {
				t.freezeResponse(f)
			}
		}
	}
	if p.flags&tcpRST != 0 {
		f.serverRst = true
		t.markClosing(f, now)
	} else if p.flags&tcpFIN != 0 {
		f.serverFin = true
		t.markClosing(f, now)
	}
}

// markClosing 根据已观察到的关闭包决定何时输出 final
func (t *flowTable) markClosing(f *flow, now time.Time) {
	var deadline time.Time
	switch {
	case f.clientRst || f.serverRst || (f.clientFin && f.serverFin):
		deadline = now.Add(closeGrace)
	case t.obsMode == ObsInbound:
		// 看不到节点方向时，客户端 FIN 之后不会再有可观察的客户端数据
		deadline = now.Add(closeGrace)
	default:
		deadline = now.Add(halfCloseWait)
	}
	if f.closeDeadline.IsZero() || deadline.Before(f.closeDeadline) {
		f.closeDeadline = deadline
	}
}

// checkClientPrefix 在收到客户端数据后判断前缀采集能否按字节预算提前结束。
//
// 前缀采集与 TLS 判别分开：首字节就能判断“不是 ClientHello”时，前缀仍按同样的预算继续采集，
// 否则同一字节流会因为 TCP 分段不同而得到不同长度的前缀。提前结束只看字节数，与分段无关。
func (t *flowTable) checkClientPrefix(f *flow) {
	if f.prefixDone || f.cli == nil {
		return
	}
	n := len(f.cli.prefix())
	switch {
	case f.cli.flags[reasmOverflow]:
		t.finishPrefix(f, PrefixStopOverflow)
	case n >= clientPrefixLimit:
		t.finishPrefix(f, PrefixStopBytes)
	case n >= prefixHashMax:
		if state, _ := classifyClientHello(f.cli.prefix()); state != tlsNeedMore {
			t.finishPrefix(f, PrefixStopBytes)
		}
	}
}

// finishPrefix 结束客户端前缀采集，给出 TLS 结论与前缀哈希，并释放重组缓存。
// 之后到达的客户端字节（包括其中的重叠冲突）不再检查，reasm_flags 只描述 prefix_stop 之前的观察。
func (t *flowTable) finishPrefix(f *flow, reason string) {
	if f.prefixDone || f.cli == nil {
		return
	}
	f.prefixDone = true
	prefix := f.cli.prefix()
	state, ch, used := classifyClientHelloN(prefix)
	switch state {
	case tlsNeedMore:
		if len(prefix) == 0 && !f.cli.hasGap() && !f.cli.flags[reasmTruncated] {
			state = ""
		} else {
			state = tlsIncomplete
		}
	case tlsComplete:
		if f.cli.conflictBefore(used) {
			// ClientHello 范围内有内容不一致的重叠段：语法可以解析，但不能当作可比较的指纹
			state = tlsConflict
		}
	}
	f.base.TLSState = state
	if state == tlsComplete {
		fillTLS(&f.base, ch)
	}
	switch state {
	case tlsIncomplete:
		t.r.stats.tlsIncomplete.Add(1)
	case tlsMalformed:
		t.r.stats.tlsMalformed.Add(1)
	case tlsConflict:
		t.r.stats.tlsConflict.Add(1)
	}
	n := min(len(prefix), prefixHashMax)
	f.base.PrefixLen = uint32(n)
	f.base.PrefixHash = prefixHash(prefix[:n])
	f.cliFlags = f.cli.flagString()
	if n > 0 || f.cliFlags != "" {
		f.base.PrefixStop = reason
	}
	if f.cli.flags[reasmConflict] {
		t.r.stats.reasmConflict.Add(1)
	}
	if f.cli.flags[reasmOverflow] {
		t.r.stats.reasmOverflow.Add(1)
	}
	if f.cli.flags[reasmTruncated] {
		t.r.stats.capTruncated.Add(1)
	}
	f.cli = nil
}

func (t *flowTable) freezeResponse(f *flow) {
	if f.respFrozen || f.srv == nil {
		return
	}
	f.respFrozen = true
	f.base.RespRecords = tlsRecordSummary(f.srv.prefix(), respRecordsMax)
	f.base.RespReasmFlag = f.srv.flagString()
	f.srv = nil
}

func (t *flowTable) handleUDP(p *packet, now time.Time) []*Event {
	state, np := t.portState(true, p.dport)
	key := inboundKey(p)
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []*Event
	f := t.flows[key]
	if f == nil {
		var corr []*Event
		f, corr = t.newFlow(KindUDPFlow, key, state, np, now)
		if f == nil {
			return nil
		}
		out = append(out, corr...)
		fillIPFingerprint(&f.base, p)
		fillFirstSegment(&f.base, p, t.r.cfg.PayloadHeadBytes)
		f.base.QUICVer = quicVersion(p.payload)
		f.firstSegDone = true
		f.dataAt = now
		if f.base.QUICVer != "" {
			f.quic = newQUICState()
		}
	} else if f.quic != nil && now.Sub(f.dataAt) > firstFlightWait {
		t.finishQUIC(f)
	}
	f.last, f.lastAny = now, now
	f.pkts++
	f.bytes += uint64(p.payloadWire)
	if f.quic != nil {
		f.quic.addDatagram(p.payload, p.truncated)
		if st, _, _ := classifyHandshakeStream(f.quic.crypto.prefix()); st != tlsNeedMore || f.quic.datagrams >= quicMaxDatagrams {
			t.finishQUIC(f)
		}
	}
	return out
}

// finishQUIC 结束客户端 Initial 解析：写入 ClientHello 指纹、SNI 在第一个数据报中的覆盖情况，并释放缓存。
// 结束条件：ClientHello 有结论、首个数据报后 2 秒、解析了 quicMaxDatagrams 个数据报，或流结束。
func (t *flowTable) finishQUIC(f *flow) {
	s := f.quic
	if s == nil {
		return
	}
	f.quic = nil
	f.base.QUICInitial = s.status()
	f.base.QUICInitials = uint8(min(s.initials, 255))
	if !s.decrypted {
		return
	}
	stream := s.crypto.prefix()
	state, ch, used := classifyHandshakeStream(stream)
	switch state {
	case tlsNeedMore:
		state = tlsIncomplete
	case tlsComplete:
		if s.crypto.conflictBefore(used) {
			state = tlsConflict
		}
	}
	f.base.TLSState = state
	f.base.ReasmFlags = s.crypto.flagString()
	switch state {
	case tlsComplete:
		fillTLSFor(&f.base, ch, 'q')
		if ch.sni == "" {
			f.base.QUICSNIFirst = QUICSNIFirstNoSNI
		} else {
			f.base.QUICSNIFirst = s.sniCoverage(ch.sniOff, ch.sniLen)
		}
	case tlsIncomplete:
		t.r.stats.tlsIncomplete.Add(1)
	case tlsMalformed:
		t.r.stats.tlsMalformed.Add(1)
	case tlsConflict:
		t.r.stats.tlsConflict.Add(1)
	}
	t.r.stats.quicInitials.Add(1)
}

// handshakeState 根据观察到的证据给出握手状态
func (t *flowTable) handshakeState(f *flow) string {
	switch {
	case f.key.proto != ipProtoTCP:
		return ""
	case f.hsVerified:
		return HandshakeEstablished
	case f.hsInferred:
		return HandshakeInferred
	case f.hasSynAck:
		return HandshakeSynAck
	case f.hasSyn && t.obsMode != ObsInbound:
		return HandshakeSynOnly
	case f.hasSyn && f.pkts == 0 && !f.clientRst:
		return HandshakeSynOnly
	}
	return HandshakeUnknown
}

func hsFlags(f *flow) string {
	switch {
	case f.hsBadAck && f.hsNoAck:
		return HSFlagBadAck + "," + HSFlagNoAck
	case f.hsBadAck:
		return HSFlagBadAck
	case f.hsNoAck:
		return HSFlagNoAck
	}
	return ""
}

func closeBy(f *flow) string {
	switch {
	case f.clientRst:
		return CloseClientRST
	case f.serverRst:
		return CloseServerRST
	case f.clientFin && f.serverFin:
		return CloseBothFIN
	case f.clientFin:
		return CloseClientFIN
	case f.serverFin:
		return CloseServerFIN
	}
	return CloseNone
}

// buildRecord 复制一份当前状态生成记录（不修改已入队的事件）
func (t *flowTable) buildRecord(f *flow, recordType, end string) *Event {
	f.revision++
	e := f.base
	e.FlowID = f.id
	e.RecordType = recordType
	e.Revision = f.revision
	e.EventID = f.id + "-" + itoa(f.revision)
	e.ObsMode = t.obsMode
	e.FlowMs = uint32(f.last.Sub(f.first).Milliseconds())
	e.FlowPkts = f.pkts
	e.FlowBytes = f.bytes
	e.FlowEnd = end
	e.Auth = f.auth
	e.AuthAssoc = f.assoc
	if f.key.proto == ipProtoTCP {
		e.SynRetrans = f.synCount
		e.CloseBy = closeBy(f)
		e.Handshake = t.handshakeState(f)
		e.HSFlags = hsFlags(f)
		e.ReasmFlags = f.cliFlags
		if t.obsMode == ObsFull {
			e.OutPkts = f.outPkts
			e.OutBytes = f.outBytes
			if !f.respAt.IsZero() && f.hasSyn {
				ms := int32(f.respAt.Sub(f.synAt).Milliseconds())
				e.FirstRespMs = &ms
			}
		}
	}
	return &e
}

// keep 决定是否输出：中途接上的 TCP 流不输出；已认证连接按 flow_id 稳定采样，一旦输出过就一直输出
func (t *flowTable) keep(f *flow) bool {
	if f.key.proto == ipProtoTCP && !f.hasSyn {
		return false
	}
	if f.suppressed {
		return false
	}
	if f.emittedAny || f.auth != AuthAccepted {
		return true
	}
	if !t.r.sampleFlow(f.id) {
		f.suppressed = true
		return false
	}
	return true
}

func (t *flowTable) appendSnapshot(out []*Event, f *flow) []*Event {
	f.snapshotDone = true
	t.finishPrefix(f, PrefixStopSnapshot)
	t.finishQUIC(f)
	t.freezeResponse(f)
	if !t.keep(f) {
		return out
	}
	f.emittedAny = true
	return append(out, t.buildRecord(f, RecordSnapshot, "open"))
}

// appendFinal 输出 final 并把连接移出活跃表（仍留在关联索引里等迟到日志）
func (t *flowTable) appendFinal(out []*Event, f *flow, end string, now time.Time) []*Event {
	if f.finalized {
		return out
	}
	t.finishPrefix(f, PrefixStopFlowEnd)
	t.finishQUIC(f)
	t.freezeResponse(f)
	f.finalized = true
	f.endAt = now
	if f.assoc == AssocUnmatched {
		t.r.stats.assocUnmatched.Add(1)
	}
	if !t.keep(f) {
		return out
	}
	f.emittedAny = true
	return append(out, t.buildRecord(f, RecordFinal, end))
}

// isCandidate 判断连接是否可能是 at 时刻那条 access 记录的来源。
// xray access 记录只有来源地址，没有入站目标，只能按来源 ip:port 与时间窗筛选。
func (t *flowTable) isCandidate(f *flow, at time.Time) bool {
	if f.base.PortState != PortNode || f.first.After(at.Add(closeGrace)) {
		return false
	}
	// 日志时间晚于 final：只接受在 closeGrace 内迟到的（日志处理延迟）
	return !f.finalized || at.Sub(f.endAt) <= closeGrace
}

func (t *flowTable) candidates(sk srcKey, at time.Time) []*flow {
	var cands []*flow
	for _, f := range t.bySrc[sk] {
		if t.isCandidate(f, at) {
			cands = append(cands, f)
		}
	}
	return cands
}

// onAccess 由 xray access 记录调用。
//
// 已有多个候选时立即标记 ambiguous（之后再出现候选也不会变成唯一）。否则等候选窗口关闭
// （日志时间 + assocDecideAfter）后由 resolveLogs 决定，避免按处理顺序把结果绑定到先出现的连接。
func (t *flowTable) onAccess(udp bool, ip string, port uint16, status string, at time.Time) []*Event {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	sk := srcKey{udp: udp, client: netip.AddrPortFrom(addr.Unmap(), port)}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pendingN >= maxPendingLogs {
		t.r.stats.pendingLogsDropped.Add(1)
		return nil
	}
	l := pendingLog{at: at, status: status}
	var out []*Event
	if cands := t.candidates(sk, at); len(cands) >= 2 {
		l.state = logAmbiguous
		out = t.markAmbiguous(cands)
	}
	t.pending[sk] = append(t.pending[sk], l)
	t.pendingN++
	return out
}

// markAmbiguous 把候选连接标记为 ambiguous；已被其他记录唯一匹配的连接保持不变
func (t *flowTable) markAmbiguous(cands []*flow) []*Event {
	t.r.stats.assocAmbiguous.Add(1)
	var out []*Event
	for _, f := range cands {
		if f.assoc == AssocMatched {
			continue
		}
		if e := t.setAuth(f, f.auth, AssocAmbiguous); e != nil {
			out = append(out, e)
		}
	}
	return out
}

// setAuth 更新认证结论。已输出 final 的连接结论有变化时生成 correction（完整行，revision+1）；
// 没有变化时不输出，重复的日志不会产生无意义的修订。
func (t *flowTable) setAuth(f *flow, auth, assoc string) *Event {
	if f.auth == auth && f.assoc == assoc {
		return nil
	}
	f.auth, f.assoc = auth, assoc
	if !f.finalized || !f.emittedAny || f.suppressed {
		return nil
	}
	t.r.stats.lateCorrections.Add(1)
	return t.buildRecord(f, RecordCorrection, "late_auth")
}

// resolveLogs 处理候选窗口已关闭的 access 记录，并清理过期记录。调用方持有锁。
func (t *flowTable) resolveLogs(now time.Time) []*Event {
	var out []*Event
	for sk, logs := range t.pending {
		kept := logs[:0]
		for _, l := range logs {
			age := now.Sub(l.at)
			if l.state == logUndecided && age > assocDecideAfter {
				cands := t.candidates(sk, l.at)
				switch len(cands) {
				case 0:
					// 还没有候选：可能是抓包处理落后，继续等到 pendingLogTTL
					if age > pendingLogTTL {
						t.r.stats.pendingLogsExpired.Add(1)
						t.pendingN--
						continue
					}
				case 1:
					f := cands[0]
					auth := l.status
					if f.auth == AuthAccepted {
						auth = AuthAccepted
					}
					l.state, l.target = logMatched, f
					if e := t.setAuth(f, auth, AssocMatched); e != nil {
						out = append(out, e)
					}
				default:
					l.state = logAmbiguous
					out = append(out, t.markAmbiguous(cands)...)
				}
			}
			if l.state != logUndecided && age > lateWindow {
				t.pendingN--
				continue
			}
			kept = append(kept, l)
		}
		if len(kept) == 0 {
			delete(t.pending, sk)
		} else {
			t.pending[sk] = kept
		}
	}
	return out
}

// awaitingLog 表示还有未决定的 access 记录可能属于这个连接
func (t *flowTable) awaitingLog(f *flow) bool {
	if f.base.PortState != PortNode {
		return false
	}
	for _, l := range t.pending[srcKey{udp: f.key.proto == ipProtoUDP, client: f.key.client}] {
		if l.state == logUndecided && t.isCandidate(f, l.at) {
			return true
		}
	}
	return false
}

func (t *flowTable) sweepLoop() {
	defer t.wg.Done()
	tick := time.NewTicker(sweepInterval)
	defer tick.Stop()
	lastListen := time.Now()
	for {
		select {
		case <-t.done:
			return
		case now := <-tick.C:
			if now.Sub(lastListen) >= listenRefresh {
				t.refreshListen()
				lastListen = now
			}
			t.sweep(now)
		}
	}
}

func (t *flowTable) sweep(now time.Time) {
	t.mu.Lock()
	// 先决定候选窗口已关闭的 access 记录，让同一轮输出的 final 带上结论
	out := t.resolveLogs(now)
	for k, f := range t.flows {
		if !f.dataAt.IsZero() && now.Sub(f.dataAt) > firstFlightWait {
			if !f.prefixDone {
				t.finishPrefix(f, PrefixStopWindow)
			}
			t.finishQUIC(f)
		}
		if !f.respFrozen && !f.respAt.IsZero() && now.Sub(f.respAt) > firstFlightWait {
			t.freezeResponse(f)
		}
		// 回收计时看任一方向最后一个可观察的包（full 模式的下行数据也算）
		idle := now.Sub(f.lastAny)
		var end string
		switch {
		case !f.closeDeadline.IsZero() && !now.Before(f.closeDeadline):
			if t.awaitingLog(f) {
				// 还有候选窗口未关闭的 access 记录：推迟到它决定（最多 assocDecideAfter）
				continue
			}
			end = "closed"
		case k.proto == ipProtoUDP && idle > udpIdleTimeout:
			end = "idle_timeout"
		case k.proto == ipProtoTCP && f.pkts == 0 && f.outPkts == 0 && idle > tcpSynOnlyTimeout:
			end = "no_data_timeout"
		case k.proto == ipProtoTCP && idle > tcpIdleTimeout:
			end = "idle_timeout"
		}
		if end != "" {
			out = t.appendFinal(out, f, end, now)
			delete(t.flows, k)
			continue
		}
		if !f.snapshotDone && now.Sub(f.first) >= snapshotAfter {
			out = t.appendSnapshot(out, f)
		}
	}
	// 关联索引：结束超过 lateWindow 的连接移出；过期的待匹配日志计数后丢弃
	for sk, list := range t.bySrc {
		kept := list[:0]
		for _, f := range list {
			if f.finalized && now.Sub(f.endAt) > lateWindow {
				t.tracked--
				continue
			}
			kept = append(kept, f)
		}
		if len(kept) == 0 {
			delete(t.bySrc, sk)
		} else {
			t.bySrc[sk] = kept
		}
	}
	t.mu.Unlock()
	for _, e := range out {
		t.r.emit(e)
	}
}

const (
	lateWindow    = 30 * time.Second // final 之后还接受迟到关联的时间（用于判断端口复用的候选）
	pendingLogTTL = 10 * time.Second // access 记录最多等多久出现候选连接
	// 候选窗口：日志时间 + closeGrace 之前出现的连接都算候选，再留 1 秒给抓包与日志处理的先后差
	assocDecideAfter = closeGrace + time.Second
	maxPendingLogs   = 10000
)

func itoa(v uint32) string {
	var b [10]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
		if v == 0 {
			return string(b[i:])
		}
	}
}

// flowSampleKey 把 flow_id 映射到 [0,1)，用于按连接稳定采样
func flowSampleKey(id string) float64 {
	h := fnv.New64a()
	h.Write([]byte(id))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], h.Sum64())
	return float64(binary.BigEndian.Uint64(b[:])>>11) / float64(1<<53)
}
