package probelog

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxFlows          = 200000
	maxFirstBytes     = 16 * 1024 // 为拼完整 ClientHello 最多缓存的字节数
	maxFirstSegments  = 8
	payloadWait       = 2 * time.Second  // 首包分段等待上限
	tcpEmitOpenAfter  = 60 * time.Second // 长连接在此之后先上报一次
	tcpIdleTimeout    = 15 * time.Minute // 只看得到上行数据包，下载为主的连接可能长时间没有入站数据
	tcpSynOnlyTimeout = 30 * time.Second
	udpIdleTimeout    = 30 * time.Second
	udpEmitOpenAfter  = 60 * time.Second
	sweepInterval     = 5 * time.Second
	listenRefresh     = 15 * time.Second
)

type flowKey struct {
	udp bool
	src netip.AddrPort
}

type flow struct {
	ev       *Event
	synAt    time.Time
	first    time.Time
	last     time.Time
	dataAt   time.Time
	buf      []byte
	firstSeg int
	segs     int
	bufDone  bool
	hasFP    bool
	pkts     uint32
	bytes    uint64
	synCount uint16
	auth     string
	emitted  bool
}

// flowTable 按来源 ip:port 跟踪到本机监听端口的流，在流结束时输出一条汇总事件
type flowTable struct {
	r         *Recorder
	mu        sync.Mutex
	flows     map[flowKey]*flow
	listenTCP atomic.Pointer[map[uint16]bool]
	listenUDP atomic.Pointer[map[uint16]bool]
	done      chan struct{}
	wg        sync.WaitGroup
}

func newFlowTable(r *Recorder) *flowTable {
	t := &flowTable{r: r, flows: make(map[flowKey]*flow), done: make(chan struct{})}
	t.refreshListen()
	t.wg.Add(1)
	go t.sweepLoop()
	return t
}

func (t *flowTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.flows)
}

// Close 停止清理并把剩余的流全部输出
func (t *flowTable) Close() {
	close(t.done)
	t.wg.Wait()
	t.mu.Lock()
	var out []*Event
	for k, f := range t.flows {
		if !f.emitted {
			if e := t.finish(f, "shutdown"); e != nil {
				out = append(out, e)
			}
		}
		delete(t.flows, k)
	}
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

func newFlowEvent(kind string, p *packet, state string, np NodePort, now time.Time) *Event {
	proto := "tcp"
	if p.proto == ipProtoUDP {
		proto = "udp"
	}
	nodeType := np.Type
	if np.Security != "" && np.Security != "none" {
		nodeType += "+" + np.Security
	}
	return &Event{
		Time:      now,
		Kind:      kind,
		Proto:     proto,
		SrcIP:     p.src.Unmap().String(),
		SrcPort:   p.sport,
		DstIP:     p.dst.Unmap().String(),
		DstPort:   p.dport,
		PortState: state,
		NodeTag:   np.Tag,
		NodeType:  nodeType,
	}
}

// handle 处理一个入站数据包
func (t *flowTable) handle(p *packet, now time.Time) {
	var out []*Event
	switch p.proto {
	case ipProtoICMP, ipProtoICMPv6:
		e := &Event{
			Time:     now,
			Kind:     KindICMP,
			Proto:    "icmp",
			SrcIP:    p.src.Unmap().String(),
			DstIP:    p.dst.Unmap().String(),
			ICMPType: p.icmpType,
			ICMPCode: p.icmpCode,
		}
		e.TTL = p.ttl
		e.IPID = p.ipID
		out = append(out, e)
	case ipProtoTCP:
		out = t.handleTCP(p, now)
	case ipProtoUDP:
		out = t.handleUDP(p, now)
	}
	for _, e := range out {
		t.r.emit(e)
	}
}

func (t *flowTable) handleTCP(p *packet, now time.Time) []*Event {
	isSyn := p.flags&tcpSYN != 0 && p.flags&tcpACK == 0
	state, np := t.portState(false, p.dport)
	if isSyn && state == PortClosed {
		// 关闭端口上的 SYN 不建流，直接记一条扫描事件
		e := newFlowEvent(KindSyn, p, state, np, now)
		fillIPFingerprint(e, p)
		return []*Event{e}
	}
	key := flowKey{src: netip.AddrPortFrom(p.src.Unmap(), p.sport)}
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.flows[key]
	if f == nil {
		if p.flags&(tcpFIN|tcpRST) != 0 && len(p.payload) == 0 && !isSyn {
			// 不认识的流的 FIN/RST（多半是记录器启动前的连接），忽略
			return nil
		}
		if len(t.flows) >= maxFlows {
			return nil
		}
		f = &flow{ev: newFlowEvent(KindTCPFlow, p, state, np, now), first: now}
		t.flows[key] = f
	}
	f.last = now
	if isSyn {
		if f.synAt.IsZero() {
			f.synAt = now
		} else {
			f.synCount++
		}
		if !f.hasFP {
			fillIPFingerprint(f.ev, p)
			f.hasFP = true
		}
		return nil
	}
	if !f.hasFP {
		fillIPFingerprint(f.ev, p)
		f.hasFP = true
	}
	if n := len(p.payload); n > 0 {
		f.pkts++
		f.bytes += uint64(n)
		if !f.bufDone && !f.emitted {
			if f.segs == 0 {
				f.dataAt = now
				f.firstSeg = n
			}
			f.segs++
			if len(f.buf) < maxFirstBytes {
				f.buf = append(f.buf, p.payload[:min(n, maxFirstBytes-len(f.buf))]...)
			}
			need := clientHelloNeed(f.buf)
			if need < 0 || len(f.buf) >= need || f.segs >= maxFirstSegments || len(f.buf) >= maxFirstBytes {
				t.finalizePayload(f)
			}
		}
	}
	if p.flags&(tcpFIN|tcpRST) != 0 {
		delete(t.flows, key)
		if f.emitted {
			return nil
		}
		end := "fin"
		if p.flags&tcpRST != 0 {
			end = "rst"
		}
		if e := t.finish(f, end); e != nil {
			return []*Event{e}
		}
	}
	return nil
}

func (t *flowTable) handleUDP(p *packet, now time.Time) []*Event {
	state, np := t.portState(true, p.dport)
	key := flowKey{udp: true, src: netip.AddrPortFrom(p.src.Unmap(), p.sport)}
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.flows[key]
	if f == nil {
		if len(t.flows) >= maxFlows {
			return nil
		}
		f = &flow{ev: newFlowEvent(KindUDPFlow, p, state, np, now), first: now, dataAt: now, bufDone: true}
		fillIPFingerprint(f.ev, p)
		fillPayloadFeatures(f.ev, p.payload, t.r.cfg.PayloadHeadBytes)
		f.ev.QUICVer = quicVersion(p.payload)
		t.flows[key] = f
	}
	f.last = now
	f.pkts++
	f.bytes += uint64(len(p.payload))
	return nil
}

// finalizePayload 计算首包特征并尝试解析 ClientHello
func (t *flowTable) finalizePayload(f *flow) {
	if f.bufDone || len(f.buf) == 0 {
		return
	}
	f.bufDone = true
	fillPayloadFeatures(f.ev, f.buf[:f.firstSeg], t.r.cfg.PayloadHeadBytes)
	if !f.synAt.IsZero() {
		ms := int32(f.dataAt.Sub(f.synAt).Milliseconds())
		f.ev.FirstDataMs = &ms
	}
	if clientHelloNeed(f.buf) > 0 {
		if ch, err := parseClientHello(f.buf); err == nil {
			fillTLS(f.ev, ch)
		} else {
			t.r.stats.parseErrors.Add(1)
		}
	}
	f.buf = nil
}

// finish 生成流的汇总事件；已认证的流按采样率丢弃，返回 nil
func (t *flowTable) finish(f *flow, end string) *Event {
	t.finalizePayload(f)
	f.emitted = true
	e := f.ev
	// 没见到 SYN 的 TCP 流是中途接上的长连接（记录器启动前建立，或空闲超时后又有数据），
	// 首包是加密流的中间部分，上报会被误当成探测，只跟踪不上报
	if e.Kind == KindTCPFlow && f.synAt.IsZero() {
		return nil
	}
	e.FlowMs = uint32(f.last.Sub(f.first).Milliseconds())
	e.FlowPkts = f.pkts
	e.FlowBytes = f.bytes
	e.FlowEnd = end
	e.SynRetrans = f.synCount
	e.Auth = f.auth
	if e.Auth == "" {
		e.Auth = AuthNone
	}
	if e.Auth == AuthAccepted && !t.r.sampleAuthed() {
		return nil
	}
	return e
}

// markAuth 由 xray access 日志调用，给对应的流打上认证结果
func (t *flowTable) markAuth(udp bool, ip string, port uint16, status string) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	key := flowKey{udp: udp, src: netip.AddrPortFrom(addr.Unmap(), port)}
	t.mu.Lock()
	if f := t.flows[key]; f != nil && f.auth != AuthAccepted {
		f.auth = status
	}
	t.mu.Unlock()
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
		if !f.bufDone && !f.dataAt.IsZero() && now.Sub(f.dataAt) > payloadWait {
			t.finalizePayload(f)
		}
		idle := now.Sub(f.last)
		age := now.Sub(f.first)
		var end string
		remove := false
		if k.udp {
			switch {
			case idle > udpIdleTimeout:
				end, remove = "idle", true
			case age > udpEmitOpenAfter:
				end = "open"
			}
		} else {
			switch {
			case f.pkts == 0 && idle > tcpSynOnlyTimeout:
				end, remove = "no_data", true
			case idle > tcpIdleTimeout:
				end, remove = "idle", true
			case age > tcpEmitOpenAfter:
				end = "open"
			}
		}
		if end != "" && !f.emitted {
			if e := t.finish(f, end); e != nil {
				out = append(out, e)
			}
		}
		if remove {
			delete(t.flows, k)
		}
	}
	t.mu.Unlock()
	for _, e := range out {
		t.r.emit(e)
	}
}
