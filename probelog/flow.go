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

	first time.Time
	last  time.Time

	hasSyn   bool
	synAt    time.Time
	synSeq   uint32
	synCount uint16

	firstSegDone bool
	dataAt       time.Time
	pkts         uint32
	bytes        uint64

	cli          *reassembler
	cliFlags     string
	clientFrozen bool

	hasSynAck   bool
	srvISN      uint32
	established bool
	srv         *reassembler
	respAt      time.Time
	respFrozen  bool
	outPkts     uint32
	outBytes    uint64

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

type pendingLog struct {
	at     time.Time
	status string
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
func (t *flowTable) newFlow(kind string, key flowKey, state string, np NodePort, now time.Time) (*flow, *Event) {
	if len(t.flows) >= maxFlows || t.tracked >= maxTracked {
		t.r.stats.flowTableFull.Add(1)
		return nil, nil
	}
	f := &flow{
		id:    newFlowID(),
		key:   key,
		base:  baseEvent(kind, key, state, np, now),
		first: now,
		last:  now,
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
	// 日志比抓包先到：把等待中的 access 记录应用到新连接
	var corr *Event
	if logs := t.pending[sk]; len(logs) > 0 && state == PortNode {
		kept := logs[:0]
		for _, l := range logs {
			if !l.at.Before(now.Add(-closeGrace)) {
				corr = t.applyAuth(f, l.status)
			} else {
				kept = append(kept, l)
			}
		}
		t.pendingN -= len(logs) - len(kept)
		if len(kept) == 0 {
			delete(t.pending, sk)
		} else {
			t.pending[sk] = kept
		}
	}
	return f, corr
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
			f.last = now
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
		var corr *Event
		f, corr = t.newFlow(KindTCPFlow, key, state, np, now)
		if f == nil {
			return out
		}
		if corr != nil {
			out = append(out, corr)
		}
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
	f.last = now

	if f.hasSynAck && p.flags&tcpACK != 0 && p.ack == f.srvISN+1 {
		f.established = true
	}
	if n := len(p.payload); n > 0 {
		f.pkts++
		f.bytes += uint64(p.payloadWire)
		if f.hasSyn {
			f.established = true
		}
		if !f.firstSegDone {
			f.firstSegDone = true
			f.dataAt = now
			fillFirstSegment(&f.base, p, t.r.cfg.PayloadHeadBytes)
			if f.hasSyn {
				ms := int32(now.Sub(f.synAt).Milliseconds())
				f.base.FirstDataMs = &ms
			}
		}
		if f.cli != nil && !f.clientFrozen {
			f.cli.add(p.seq, p.payload, p.truncated)
			t.checkClientPrefix(f, false)
		}
	}
	if p.flags&tcpRST != 0 {
		f.clientRst = true
		t.markClosing(f, now)
	} else if p.flags&tcpFIN != 0 {
		f.clientFin = true
		if f.hasSyn {
			f.established = true
		}
		t.markClosing(f, now)
	}
	return out
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

// checkClientPrefix 判断 ClientHello 是否已有结论；force 表示不再等待（超时、结束、到达上限）
func (t *flowTable) checkClientPrefix(f *flow, force bool) {
	if f.clientFrozen || f.cli == nil {
		return
	}
	prefix := f.cli.prefix()
	state, ch := classifyClientHello(prefix)
	if state == tlsNeedMore {
		limited := len(prefix) >= clientPrefixLimit || f.cli.flags[reasmOverflow]
		if !force && !limited {
			return
		}
		if len(prefix) == 0 && !f.cli.hasGap() && !f.cli.flags[reasmTruncated] {
			state = ""
		} else {
			state = tlsIncomplete
		}
	}
	f.clientFrozen = true
	f.base.TLSState = state
	if state == tlsComplete {
		fillTLS(&f.base, ch)
	}
	switch state {
	case tlsIncomplete:
		t.r.stats.tlsIncomplete.Add(1)
	case tlsMalformed:
		t.r.stats.tlsMalformed.Add(1)
	}
	n := min(len(prefix), prefixHashMax)
	f.base.PrefixLen = uint32(n)
	f.base.PrefixHash = prefixHash(prefix[:n])
	f.cliFlags = f.cli.flagString()
	if f.cli.flags[reasmConflict] {
		t.r.stats.reasmConflict.Add(1)
	}
	if f.cli.flags[reasmOverflow] {
		t.r.stats.reasmOverflow.Add(1)
	}
	if f.cli.flags[reasmTruncated] {
		t.r.stats.capTruncated.Add(1)
	}
	f.cli = nil // 结论已定，释放缓存
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
		var corr *Event
		f, corr = t.newFlow(KindUDPFlow, key, state, np, now)
		if f == nil {
			return nil
		}
		if corr != nil {
			out = append(out, corr)
		}
		fillIPFingerprint(&f.base, p)
		fillFirstSegment(&f.base, p, t.r.cfg.PayloadHeadBytes)
		f.base.QUICVer = quicVersion(p.payload)
		f.firstSegDone = true
		f.dataAt = now
	}
	f.last = now
	f.pkts++
	f.bytes += uint64(p.payloadWire)
	return out
}

// handshakeState 根据观察到的证据给出握手状态
func (t *flowTable) handshakeState(f *flow) string {
	switch {
	case f.key.proto != ipProtoTCP:
		return ""
	case f.established:
		return HandshakeEstablished
	case f.hasSynAck:
		return HandshakeSynAck
	case f.hasSyn && t.obsMode != ObsInbound:
		return HandshakeSynOnly
	case f.hasSyn && f.pkts == 0 && !f.clientRst:
		return HandshakeSynOnly
	}
	return HandshakeUnknown
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
	t.checkClientPrefix(f, true)
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
	t.checkClientPrefix(f, true)
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

// onAccess 由 xray access 记录调用。只有唯一候选时才传播认证结果；多个候选标记 ambiguous。
func (t *flowTable) onAccess(udp bool, ip string, port uint16, status string, at time.Time) []*Event {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	sk := srcKey{udp: udp, client: netip.AddrPortFrom(addr.Unmap(), port)}
	t.mu.Lock()
	defer t.mu.Unlock()
	var cands []*flow
	for _, f := range t.bySrc[sk] {
		if f.base.PortState != PortNode {
			continue
		}
		if f.first.After(at.Add(closeGrace)) {
			continue
		}
		if f.finalized && at.After(f.endAt) {
			// 日志时间晚于 final：只接受在 closeGrace 内迟到的（日志处理延迟）
			if at.Sub(f.endAt) > closeGrace {
				continue
			}
		}
		cands = append(cands, f)
	}
	switch len(cands) {
	case 0:
		if t.pendingN >= maxPendingLogs {
			t.r.stats.pendingLogsDropped.Add(1)
			return nil
		}
		t.pending[sk] = append(t.pending[sk], pendingLog{at: at, status: status})
		t.pendingN++
		return nil
	case 1:
		if e := t.applyAuth(cands[0], status); e != nil {
			return []*Event{e}
		}
		return nil
	}
	t.r.stats.assocAmbiguous.Add(1)
	for _, f := range cands {
		if f.assoc != AssocMatched {
			f.assoc = AssocAmbiguous
		}
	}
	return nil
}

// applyAuth 把认证结果写到连接上；连接已输出 final 时生成 correction
func (t *flowTable) applyAuth(f *flow, status string) *Event {
	changed := f.assoc != AssocMatched
	f.assoc = AssocMatched
	if f.auth != AuthAccepted && f.auth != status {
		f.auth = status
		changed = true
	}
	if !changed || !f.finalized || !f.emittedAny || f.suppressed {
		return nil
	}
	t.r.stats.lateCorrections.Add(1)
	return t.buildRecord(f, RecordCorrection, "late_auth")
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
	var out []*Event
	t.mu.Lock()
	for k, f := range t.flows {
		if !f.clientFrozen && !f.dataAt.IsZero() && now.Sub(f.dataAt) > firstFlightWait {
			t.checkClientPrefix(f, true)
		}
		if !f.respFrozen && !f.respAt.IsZero() && now.Sub(f.respAt) > firstFlightWait {
			t.freezeResponse(f)
		}
		idle := now.Sub(f.last)
		var end string
		switch {
		case !f.closeDeadline.IsZero() && !now.Before(f.closeDeadline):
			end = "closed"
		case k.proto == ipProtoUDP && idle > udpIdleTimeout:
			end = "idle_timeout"
		case k.proto == ipProtoTCP && f.pkts == 0 && idle > tcpSynOnlyTimeout:
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
	for sk, logs := range t.pending {
		kept := logs[:0]
		for _, l := range logs {
			if now.Sub(l.at) > pendingLogTTL {
				t.r.stats.pendingLogsExpired.Add(1)
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
	t.mu.Unlock()
	for _, e := range out {
		t.r.emit(e)
	}
}

const (
	lateWindow     = 30 * time.Second // final 之后还接受迟到关联的时间（用于判断端口复用的候选）
	pendingLogTTL  = 10 * time.Second // 先于抓包到达的 access 记录最多等多久
	maxPendingLogs = 10000
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
