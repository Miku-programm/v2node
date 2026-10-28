package probelog

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/wyx2685/v2node/conf"
	xlog "github.com/xtls/xray-core/common/log"
)

// ---------- 测试辅助 ----------

// captureClientHello 让 crypto/tls 客户端写出一个真实的 ClientHello（单个 TLS record）
func captureClientHello(t *testing.T, sni string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	go func() {
		cl := tls.Client(c1, &tls.Config{ServerName: sni, NextProtos: []string{"h2", "http/1.1"}})
		cl.Handshake()
	}()
	var buf []byte
	tmp := make([]byte, 4096)
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, err := c2.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if st, _ := classifyClientHello(buf); st == tlsComplete || err != nil {
			break
		}
	}
	c1.Close()
	c2.Close()
	return buf
}

// splitRecords 把单 record 的 ClientHello 重新封装成两个 handshake record
func splitRecords(rec []byte, at int) []byte {
	hs := rec[5:]
	mk := func(b []byte) []byte {
		h := []byte{0x16, 0x03, 0x01, 0, 0}
		binary.BigEndian.PutUint16(h[3:], uint16(len(b)))
		return append(h, b...)
	}
	return append(mk(hs[:at]), mk(hs[at:])...)
}

// buildTCP4 构造 IPv4 TCP 包，seq/ack 为真实序列号
func buildTCP4(src, dst string, sport, dport uint16, flags uint8, seq, ack uint32, payload []byte) []byte {
	opts := []byte{2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 7, 0, 0, 0, 0, 1, 3, 3, 7}
	tcpLen := 20 + len(opts)
	total := 20 + tcpLen + len(payload)
	b := make([]byte, total)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(total))
	binary.BigEndian.PutUint16(b[4:], 0x1234)
	binary.BigEndian.PutUint16(b[6:], 0x4000)
	b[8] = 47
	b[9] = ipProtoTCP
	s := netip.MustParseAddr(src).As4()
	d := netip.MustParseAddr(dst).As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	tcp := b[20:]
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = byte(tcpLen/4) << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 64240)
	copy(tcp[20:], opts)
	copy(tcp[tcpLen:], payload)
	return b
}

func buildUDP4(src, dst string, sport, dport uint16, payload []byte) []byte {
	total := 28 + len(payload)
	b := make([]byte, total)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(total))
	b[8] = 50
	b[9] = ipProtoUDP
	s := netip.MustParseAddr(src).As4()
	d := netip.MustParseAddr(dst).As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	binary.BigEndian.PutUint16(b[20:], sport)
	binary.BigEndian.PutUint16(b[22:], dport)
	copy(b[28:], payload)
	return b
}

type harness struct {
	t      *testing.T
	r      *Recorder
	ft     *flowTable
	events []*Event
	base   time.Time
}

const (
	nodeIP  = "5.6.7.8"
	nodeIP2 = "5.6.7.9"
)

func newHarness(t *testing.T, mode string, rate float64) *harness {
	t.Helper()
	c := conf.New().ProbeLogConfig
	c.AuthedSampleRate = rate
	r := &Recorder{cfg: c, node: "test", obsMode: mode, limit: newRateLimiter(0, 0), geo: &geoTagger{cache: map[string]string{}}}
	h := &harness{t: t, r: r, base: time.Now()}
	r.emitHook = func(e *Event) { h.events = append(h.events, e) }
	ft := &flowTable{r: r, flows: map[flowKey]*flow{}, bySrc: map[srcKey][]*flow{}, pending: map[srcKey][]pendingLog{}, obsMode: mode, done: make(chan struct{})}
	tcp := map[uint16]bool{22: true}
	udp := map[uint16]bool{}
	ft.listenTCP.Store(&tcp)
	ft.listenUDP.Store(&udp)
	r.flows = ft
	h.ft = ft
	RegisterNode(NodePort{Tag: "n443", Type: "vless", Security: "reality", Port: 443})
	RegisterNode(NodePort{Tag: "n8443", Type: "vless", Security: "reality", Port: 8443})
	RegisterNode(NodePort{Tag: "hy", Type: "hysteria2", UDP: true, Port: 9443})
	t.Cleanup(func() {
		UnregisterNode("n443")
		UnregisterNode("n8443")
		UnregisterNode("hy")
	})
	return h
}

func (h *harness) at(d time.Duration) time.Time { return h.base.Add(d) }

func (h *harness) feed(raw []byte, origLen int, outgoing bool, d time.Duration) {
	h.t.Helper()
	p, err := parsePacket(raw, ethPIPv4, origLen)
	if err != nil {
		h.t.Fatal(err)
	}
	p.outgoing = outgoing
	h.ft.handle(p, h.at(d))
}

// in 客户端 → 节点
func (h *harness) in(client string, cport uint16, server string, sport uint16, flags uint8, seq, ack uint32, payload []byte, d time.Duration) {
	h.t.Helper()
	h.feed(buildTCP4(client, server, cport, sport, flags, seq, ack, payload), 0, false, d)
}

// out 节点 → 客户端
func (h *harness) out(client string, cport uint16, server string, sport uint16, flags uint8, seq, ack uint32, payload []byte, d time.Duration) {
	h.t.Helper()
	h.feed(buildTCP4(server, client, sport, cport, flags, seq, ack, payload), 0, true, d)
}

func (h *harness) sweep(d time.Duration) { h.ft.sweep(h.at(d)) }

func (h *harness) access(ip string, port uint16, status xlog.AccessStatus, d time.Duration) {
	for _, e := range h.ft.onAccess(false, ip, port, string(status), h.at(d)) {
		h.r.emit(e)
	}
}

func (h *harness) kind(k string) []*Event {
	var out []*Event
	for _, e := range h.events {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

// latest 按 flow_id 取 revision 最大的记录
func (h *harness) latest() map[string]*Event {
	m := map[string]*Event{}
	for _, e := range h.events {
		if e.FlowID == "" {
			continue
		}
		if old, ok := m[e.FlowID]; !ok || e.Revision > old.Revision {
			m[e.FlowID] = e
		}
	}
	return m
}

func (h *harness) only(t *testing.T) *Event {
	t.Helper()
	l := h.latest()
	if len(l) != 1 {
		t.Fatalf("want 1 flow, got %d: %+v", len(l), h.events)
	}
	for _, e := range l {
		return e
	}
	return nil
}

const (
	cIP  = "1.2.3.4"
	isn  = uint32(1000)
	sISN = uint32(900000)
)

// ---------- TLS ----------

func TestParseClientHello(t *testing.T) {
	raw := captureClientHello(t, "www.example.com")
	ch, err := parseClientHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ch.sni != "www.example.com" || len(ch.alpn) != 2 || ch.alpn[0] != "h2" || tlsVersionName(ch.version()) != "1.3" {
		t.Fatalf("parsed %+v", ch)
	}
	ja4 := ch.ja4()
	if !strings.HasPrefix(ja4, "t13d") || !strings.HasSuffix(strings.Split(ja4, "_")[0], "h2") || len(ja4) != 36 {
		t.Fatalf("ja4 = %s", ja4)
	}
	if len(ch.ja3()) != 32 {
		t.Fatalf("ja3 = %s", ch.ja3())
	}
}

func TestClassifyClientHello(t *testing.T) {
	raw := captureClientHello(t, "a.example")
	for n := 1; n <= 4; n++ {
		if st, _ := classifyClientHello(raw[:n]); st != tlsNeedMore {
			t.Fatalf("%d-byte prefix: %s", n, st)
		}
	}
	if st, _ := classifyClientHello(raw[:len(raw)-1]); st != tlsNeedMore {
		t.Fatalf("short record: %s", st)
	}
	if st, _ := classifyClientHello([]byte("GET / HTTP/1.1\r\n")); st != tlsNotCH {
		t.Fatalf("http: %s", st)
	}
	if st, _ := classifyClientHello([]byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0, 0, 0}); st != tlsNotCH {
		t.Fatalf("server hello: %s", st)
	}
	// 跨两个 record 的 ClientHello
	multi := splitRecords(raw, 40)
	st, ch := classifyClientHello(multi)
	if st != tlsComplete || ch.sni != "a.example" {
		t.Fatalf("multi-record: %s %+v", st, ch)
	}
	one, _ := parseClientHello(raw)
	if ch.ja4() != one.ja4() {
		t.Fatal("ja4 differs between single and multi-record")
	}
	// 第一个 record 收到、第二个还没到
	if st, _ := classifyClientHello(multi[:5+40+3]); st != tlsNeedMore {
		t.Fatalf("partial second record: %s", st)
	}
	// ClientHello 没收齐就出现了 application data record
	bad := append(append([]byte{}, multi[:5+40]...), 0x17, 0x03, 0x03, 0x00, 0x01, 0x00)
	if st, _ := classifyClientHello(bad); st != tlsMalformed {
		t.Fatalf("interleaved record: %s", st)
	}
	// handshake 长度声明比扩展区实际内容多：record 齐了但结构不合法
	bad = bytes.Clone(raw)
	binary.BigEndian.PutUint16(bad[3:5], binary.BigEndian.Uint16(bad[3:5])+1)
	hl := int(bad[6])<<16 | int(bad[7])<<8 | int(bad[8]) + 1 // handshake 长度 +1
	bad[6], bad[7], bad[8] = byte(hl>>16), byte(hl>>8), byte(hl)
	bad = append(bad, 0)
	if st, _ := classifyClientHello(bad); st != tlsMalformed {
		t.Fatalf("trailing garbage: %s", st)
	}
}

func TestTLSRecordSummary(t *testing.T) {
	b := []byte{22, 3, 3, 0, 2, 1, 1, 20, 3, 3, 0, 1, 1, 23, 3, 3, 0x10, 0}
	if s := tlsRecordSummary(b, 8); s != "22:2,20:1,23:4096" {
		t.Fatalf("summary = %s", s)
	}
	if s := tlsRecordSummary([]byte("HTTP/1.1 200"), 8); s != "non_tls" {
		t.Fatalf("non tls = %s", s)
	}
}

// ---------- 重组 ----------

func TestReassembler(t *testing.T) {
	data := []byte("0123456789abcdefghij")
	for _, base := range []uint32{100, 0xfffffff8} { // 含序列号回绕
		r := newReassembler(base, 1024)
		s := base + 1
		r.add(s+10, data[10:15], false) // 乱序
		r.add(s, data[0:6], false)
		r.add(s+4, data[4:10], false)   // 与前一段相同内容的重叠
		r.add(s, data[0:6], false)      // 重传
		r.add(s+15, data[15:20], false) // 补齐
		if !bytes.Equal(r.prefix(), data) || !r.clean() {
			t.Fatalf("base %x: prefix %q flags %s", base, r.prefix(), r.flagString())
		}
		if !strings.Contains(r.flagString(), reasmRetrans) {
			t.Fatalf("retrans not flagged: %s", r.flagString())
		}
	}

	r := newReassembler(0, 1024)
	r.add(1, []byte("abcdef"), false)
	r.add(4, []byte("XYZ"), false) // 内容冲突，保留先到的字节
	if string(r.prefix()) != "abcdef" || !strings.Contains(r.flagString(), reasmConflict) || r.clean() {
		t.Fatalf("conflict: %q %s", r.prefix(), r.flagString())
	}

	r = newReassembler(0, 1024)
	r.add(1, []byte("abc"), false)
	r.add(10, []byte("zzz"), false) // 缺口
	if string(r.prefix()) != "abc" || !r.hasGap() || !strings.Contains(r.flagString(), reasmGap) {
		t.Fatalf("gap: %q %s", r.prefix(), r.flagString())
	}

	// 截断：只放入捕获到的字节，后续数据不会被拼到缺失位置
	r = newReassembler(0, 1024)
	r.add(1, []byte("abc"), true) // 原始 6 字节，只捕获 3 字节
	r.add(7, []byte("ghi"), false)
	if string(r.prefix()) != "abc" || !r.hasGap() || !strings.Contains(r.flagString(), reasmTruncated) {
		t.Fatalf("truncated: %q %s", r.prefix(), r.flagString())
	}

	// 上限
	r = newReassembler(0, 8)
	r.add(1, []byte("0123456789"), false)
	if len(r.prefix()) != 8 || !strings.Contains(r.flagString(), reasmOverflow) {
		t.Fatalf("limit: %q %s", r.prefix(), r.flagString())
	}
	r = newReassembler(0, 1<<20)
	for i := 0; i < maxPendingSegs+5; i++ {
		r.add(uint32(100+i*10), []byte("x"), false)
	}
	if len(r.pending) > maxPendingSegs || !strings.Contains(r.flagString(), reasmOverflow) {
		t.Fatalf("pending limit: %d %s", len(r.pending), r.flagString())
	}
}

// ---------- 解析 ----------

func TestParsePacketAndTruncation(t *testing.T) {
	raw := buildTCP4("1.2.3.4", "5.6.7.8", 40000, 443, tcpSYN, 7, 0, nil)
	p, err := parsePacket(raw, ethPIPv4, 0)
	if err != nil {
		t.Fatal(err)
	}
	if p.src.String() != "1.2.3.4" || p.dport != 443 || p.ttl != 47 || !p.df || p.seq != 7 || p.opts != "M1460,S,T,N,W7" || p.tsVal != 7 {
		t.Fatalf("bad parse: %+v", p)
	}
	full := buildTCP4("1.2.3.4", "5.6.7.8", 40000, 443, tcpACK|tcpPSH, 8, 1, bytes.Repeat([]byte{1}, 1000))
	p, err = parsePacket(full[:200], ethPIPv4, len(full))
	if err != nil {
		t.Fatal(err)
	}
	if !p.truncated || p.payloadWire != 1000 || len(p.payload) != 200-60 {
		t.Fatalf("truncation: wire=%d cap=%d trunc=%v", p.payloadWire, len(p.payload), p.truncated)
	}
}

func TestBuildFilter(t *testing.T) {
	ports := make([]uint16, 300)
	for i := range ports {
		ports[i] = uint16(10000 + i)
	}
	for _, mode := range []string{ObsInbound, ObsControl, ObsFull} {
		raw, err := buildFilter(ports, ports, mode)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if len(raw) == 0 || len(raw) > 4096 {
			t.Fatalf("%s: filter length %d", mode, len(raw))
		}
		if _, err := buildFilter(nil, nil, mode); err != nil {
			t.Fatal(err)
		}
	}
}

// ---------- 连接身份 ----------

func TestFlowIdentitySeparation(t *testing.T) {
	h := newHarness(t, ObsInbound, 1)
	// 同一来源 ip:port 同时连 443、8443，以及另一个本地地址的 443
	h.in(cIP, 5000, nodeIP, 443, tcpSYN, isn, 0, nil, 0)
	h.in(cIP, 5000, nodeIP, 8443, tcpSYN, isn+50, 0, nil, 0)
	h.in(cIP, 5000, nodeIP2, 443, tcpSYN, isn+90, 0, nil, 0)
	if len(h.ft.flows) != 3 {
		t.Fatalf("flows = %d", len(h.ft.flows))
	}
	// 443 上的 RST 不影响另外两条
	h.in(cIP, 5000, nodeIP, 443, tcpRST, isn+1, 0, nil, time.Second)
	h.in(cIP, 5000, nodeIP, 8443, tcpACK|tcpPSH, isn+51, 0, []byte("hello"), time.Second)
	h.sweep(5 * time.Second)
	if len(h.ft.flows) != 2 {
		t.Fatalf("flows after rst = %d", len(h.ft.flows))
	}
	// access 记录只有来源地址，多个候选时不传播认证结果
	h.access(cIP, 5000, xlog.AccessAccepted, 2*time.Second)
	for _, f := range h.ft.flows {
		if f.auth != AuthUnknown || f.assoc != AssocAmbiguous {
			t.Fatalf("ambiguous candidate got auth=%s assoc=%s", f.auth, f.assoc)
		}
	}
	h.in(cIP, 5000, nodeIP, 8443, tcpFIN|tcpACK, isn+56, 0, nil, 3*time.Second)
	h.in(cIP, 5000, nodeIP2, 443, tcpFIN|tcpACK, isn+91, 0, nil, 3*time.Second)
	h.sweep(10 * time.Second)
	got := h.latest()
	if len(got) != 3 {
		t.Fatalf("records for %d flows", len(got))
	}
	seen := map[string]bool{}
	for _, e := range got {
		key := e.DstIP + ":" + itoa(uint32(e.DstPort))
		if seen[key] {
			t.Fatalf("duplicate flow for %s", key)
		}
		seen[key] = true
		switch key {
		case nodeIP + ":443":
			if e.CloseBy != CloseClientRST || e.FlowPkts != 0 {
				t.Fatalf("443: %+v", e)
			}
		case nodeIP + ":8443":
			if e.FlowPkts != 1 || e.CloseBy != CloseClientFIN || e.PrefixLen != 5 {
				t.Fatalf("8443: %+v", e)
			}
		}
	}
}

func TestSynRetransVsNewConnection(t *testing.T) {
	h := newHarness(t, ObsInbound, 1)
	h.in(cIP, 6000, nodeIP, 443, tcpSYN, isn, 0, nil, 0)
	h.in(cIP, 6000, nodeIP, 443, tcpSYN, isn, 0, nil, time.Second) // 重传
	f := h.ft.flows[flowKey{ipProtoTCP, netip.MustParseAddrPort(cIP + ":6000"), netip.MustParseAddrPort(nodeIP + ":443")}]
	if f == nil || f.synCount != 1 {
		t.Fatalf("retrans not counted: %+v", f)
	}
	firstID := f.id
	// 同五元组、新 ISN 的 SYN：旧连接以 superseded 结束，开始新实例
	h.in(cIP, 6000, nodeIP, 443, tcpSYN, isn+100000, 0, nil, 2*time.Second)
	h.in(cIP, 6000, nodeIP, 443, tcpFIN|tcpACK, isn+100001, 0, nil, 3*time.Second)
	h.sweep(10 * time.Second)
	// 关闭后再次建立
	h.in(cIP, 6000, nodeIP, 443, tcpSYN, isn+200000, 0, nil, 11*time.Second)
	h.sweep(60 * time.Second)
	got := h.latest()
	if len(got) != 3 {
		t.Fatalf("want 3 instances, got %d", len(got))
	}
	if got[firstID].FlowEnd != "superseded" || got[firstID].SynRetrans != 1 {
		t.Fatalf("first: %+v", got[firstID])
	}
}

func TestUDPFlowSeparation(t *testing.T) {
	h := newHarness(t, ObsInbound, 1)
	h.feed(buildUDP4(cIP, nodeIP, 7000, 9443, []byte{0xc0, 0, 0, 0, 1}), 0, false, 0)
	h.feed(buildUDP4(cIP, nodeIP2, 7000, 9443, []byte{0xc0, 0, 0, 0, 1}), 0, false, 0)
	h.sweep(time.Minute)
	if got := h.latest(); len(got) != 2 {
		t.Fatalf("udp flows = %d", len(got))
	}
}

// ---------- 首包与重组 ----------

func feedSegments(h *harness, port uint16, segs [][2]int, data []byte) {
	h.in(cIP, port, nodeIP, 443, tcpSYN, isn, 0, nil, 0)
	for i, s := range segs {
		h.in(cIP, port, nodeIP, 443, tcpACK|tcpPSH, isn+1+uint32(s[0]), 1, data[s[0]:s[1]], time.Duration(i+1)*10*time.Millisecond)
	}
	h.in(cIP, port, nodeIP, 443, tcpRST, isn+1+uint32(len(data)), 0, nil, 500*time.Millisecond)
}

func TestClientHelloReassemblyVariants(t *testing.T) {
	ch := captureClientHello(t, "www.microsoft.com")
	n := len(ch)
	cases := map[string][][2]int{
		"single":    {{0, n}},
		"segmented": {{0, 300}, {300, 600}, {600, n}},
		"retrans":   {{0, 300}, {0, 300}, {300, n}, {300, 400}},
		"reorder":   {{300, n}, {0, 300}},
		"tiny":      {{0, 3}, {3, n}},
	}
	var ref *Event
	for name, segs := range cases {
		h := newHarness(t, ObsInbound, 1)
		feedSegments(h, 7000, segs, ch)
		h.sweep(5 * time.Second)
		e := h.only(t)
		if e.TLSState != tlsComplete || e.TLSSNI != "www.microsoft.com" || e.JA4 == "" {
			t.Fatalf("%s: tls_state=%s sni=%s flags=%s", name, e.TLSState, e.TLSSNI, e.ReasmFlags)
		}
		if strings.Contains(e.ReasmFlags, reasmConflict) || strings.Contains(e.ReasmFlags, reasmGap) {
			t.Fatalf("%s: flags %s", name, e.ReasmFlags)
		}
		if ref == nil {
			ref = e
		} else if e.JA4 != ref.JA4 || e.PrefixHash != ref.PrefixHash || e.PrefixLen != ref.PrefixLen {
			t.Fatalf("%s: prefix/ja4 differ from reference", name)
		}
	}
}

func TestIncompleteClientHelloHasNoFingerprint(t *testing.T) {
	ch := captureClientHello(t, "www.microsoft.com")
	n := len(ch)
	// 中间缺一段
	h := newHarness(t, ObsInbound, 1)
	feedSegments(h, 7100, [][2]int{{0, 100}, {200, n}}, ch)
	h.sweep(5 * time.Second)
	e := h.only(t)
	if e.TLSState != tlsIncomplete || e.JA4 != "" || e.TLSSNI != "" || !strings.Contains(e.ReasmFlags, reasmGap) || e.PrefixLen != 100 {
		t.Fatalf("gap: %+v", e)
	}

	// 捕获截断
	h = newHarness(t, ObsInbound, 1)
	h.in(cIP, 7200, nodeIP, 443, tcpSYN, isn, 0, nil, 0)
	full := buildTCP4(cIP, nodeIP, 7200, 443, tcpACK|tcpPSH, isn+1, 1, ch)
	h.feed(full[:60+200], len(full), false, 10*time.Millisecond)
	h.sweep(5 * time.Second) // 超过 firstFlightWait
	h.in(cIP, 7200, nodeIP, 443, tcpFIN|tcpACK, isn+1+uint32(n), 1, nil, 6*time.Second)
	h.sweep(10 * time.Second)
	e = h.only(t)
	if e.TLSState != tlsIncomplete || e.JA4 != "" || e.PayloadTruncated != 1 || e.PayloadLen != uint32(n) || e.PayloadCapLen != 200 || !strings.Contains(e.ReasmFlags, reasmTruncated) {
		t.Fatalf("truncated: %+v", e)
	}

	// 非 TLS
	h = newHarness(t, ObsInbound, 1)
	feedSegments(h, 7300, [][2]int{{0, 16}}, []byte("GET / HTTP/1.1\r\n"))
	h.sweep(5 * time.Second)
	if e := h.only(t); e.TLSState != tlsNotCH || e.JA4 != "" {
		t.Fatalf("http: %+v", e)
	}
}

// ---------- 认证关联 ----------

func TestAuthCorrelation(t *testing.T) {
	ch := captureClientHello(t, "x.example")

	// 先日志后流
	h := newHarness(t, ObsInbound, 1)
	h.access(cIP, 8000, xlog.AccessAccepted, 0)
	h.in(cIP, 8000, nodeIP, 443, tcpSYN, isn, 0, nil, 100*time.Millisecond)
	h.in(cIP, 8000, nodeIP, 443, tcpFIN|tcpACK, isn+1, 0, nil, time.Second)
	h.sweep(5 * time.Second)
	if e := h.only(t); e.Auth != AuthAccepted || e.AuthAssoc != AssocMatched {
		t.Fatalf("log-first: %s/%s", e.Auth, e.AuthAssoc)
	}

	// 先流后日志
	h = newHarness(t, ObsInbound, 1)
	feedSegments(h, 8001, [][2]int{{0, len(ch)}}, ch)
	h.access(cIP, 8001, xlog.AccessAccepted, 100*time.Millisecond)
	h.sweep(5 * time.Second)
	if e := h.only(t); e.Auth != AuthAccepted || e.AuthAssoc != AssocMatched || e.RecordType != RecordFinal {
		t.Fatalf("flow-first: %+v", e)
	}

	// final 之后迟到的日志 → correction（同 flow_id，revision+1，完整行）
	h = newHarness(t, ObsInbound, 1)
	feedSegments(h, 8002, [][2]int{{0, len(ch)}}, ch)
	h.sweep(5 * time.Second)
	h.access(cIP, 8002, xlog.AccessAccepted, 6*time.Second)
	recs := h.kind(KindTCPFlow)
	if len(recs) != 2 || recs[0].RecordType != RecordFinal || recs[1].RecordType != RecordCorrection ||
		recs[0].FlowID != recs[1].FlowID || recs[1].Revision != recs[0].Revision+1 || recs[1].Auth != AuthAccepted ||
		recs[0].Auth != AuthUnknown || recs[1].JA4 == "" {
		t.Fatalf("late: %+v", recs)
	}

	// 没有日志：unknown，不是失败
	h = newHarness(t, ObsInbound, 1)
	feedSegments(h, 8003, [][2]int{{0, len(ch)}}, ch)
	h.sweep(5 * time.Second)
	if e := h.only(t); e.Auth != AuthUnknown || e.AuthAssoc != AssocUnmatched {
		t.Fatalf("no log: %s/%s", e.Auth, e.AuthAssoc)
	}

	// 来源端口复用：旧连接结束很久后，新连接的日志只应用到新连接
	h = newHarness(t, ObsInbound, 1)
	h.in(cIP, 8004, nodeIP, 443, tcpSYN, isn, 0, nil, 0)
	h.in(cIP, 8004, nodeIP, 443, tcpRST, isn+1, 0, nil, time.Second)
	h.sweep(5 * time.Second)
	h.in(cIP, 8004, nodeIP, 443, tcpSYN, isn+500000, 0, nil, 20*time.Second)
	h.access(cIP, 8004, xlog.AccessAccepted, 20*time.Second+100*time.Millisecond)
	h.in(cIP, 8004, nodeIP, 443, tcpFIN|tcpACK, isn+500001, 0, nil, 21*time.Second)
	h.sweep(30 * time.Second)
	var accepted, unknown int
	for _, e := range h.latest() {
		switch e.Auth {
		case AuthAccepted:
			accepted++
		case AuthUnknown:
			unknown++
		}
	}
	if accepted != 1 || unknown != 1 || len(h.kind(KindTCPFlow)) != 2 {
		t.Fatalf("reuse: accepted=%d unknown=%d events=%d", accepted, unknown, len(h.kind(KindTCPFlow)))
	}

	// SSH 等非节点端口：not_applicable
	h = newHarness(t, ObsInbound, 1)
	h.in(cIP, 8005, nodeIP, 22, tcpSYN, isn, 0, nil, 0)
	h.in(cIP, 8005, nodeIP, 22, tcpACK|tcpPSH, isn+1, 1, []byte("SSH-2.0-x\r\n"), 10*time.Millisecond)
	h.access(cIP, 8005, xlog.AccessRejected, 20*time.Millisecond)
	h.in(cIP, 8005, nodeIP, 22, tcpFIN|tcpACK, isn+12, 1, nil, time.Second)
	h.sweep(5 * time.Second)
	if e := h.only(t); e.Auth != AuthNotApplicable || e.AuthAssoc != AssocNotApplicable || e.PortState != PortListen {
		t.Fatalf("ssh: %+v", e)
	}
}

// ---------- 双向观测与关闭方向 ----------

func TestCloseDirection(t *testing.T) {
	type step func(h *harness, port uint16)
	syn := func(h *harness, p uint16) { h.in(cIP, p, nodeIP, 443, tcpSYN, isn, 0, nil, 0) }
	synack := func(h *harness, p uint16) {
		h.out(cIP, p, nodeIP, 443, tcpSYN|tcpACK, sISN, isn+1, nil, 5*time.Millisecond)
	}
	ack := func(h *harness, p uint16) {
		h.in(cIP, p, nodeIP, 443, tcpACK|tcpPSH, isn+1, sISN+1, []byte("hi"), 10*time.Millisecond)
	}
	cases := []struct {
		name      string
		steps     []step
		close     string
		end       string
		handshake string
	}{
		{"server_rst", []step{syn, synack, ack, func(h *harness, p uint16) {
			h.out(cIP, p, nodeIP, 443, tcpRST, sISN+1, 0, nil, 20*time.Millisecond)
		}}, CloseServerRST, "closed", HandshakeEstablished},
		{"client_rst", []step{syn, synack, func(h *harness, p uint16) {
			h.in(cIP, p, nodeIP, 443, tcpRST, isn+1, 0, nil, 20*time.Millisecond)
		}}, CloseClientRST, "closed", HandshakeSynAck},
		{"client_fin_only", []step{syn, synack, ack, func(h *harness, p uint16) {
			h.in(cIP, p, nodeIP, 443, tcpFIN|tcpACK, isn+3, sISN+1, nil, 20*time.Millisecond)
		}}, CloseClientFIN, "closed", HandshakeEstablished},
		{"both_fin", []step{syn, synack, ack, func(h *harness, p uint16) {
			h.out(cIP, p, nodeIP, 443, tcpFIN|tcpACK, sISN+1, isn+3, nil, 20*time.Millisecond)
			h.in(cIP, p, nodeIP, 443, tcpFIN|tcpACK, isn+3, sISN+2, nil, 30*time.Millisecond)
		}}, CloseBothFIN, "closed", HandshakeEstablished},
		{"syn_only", []step{syn}, CloseNone, "no_data_timeout", HandshakeSynOnly},
		{"timeout_no_close", []step{syn, synack, ack}, CloseNone, "idle_timeout", HandshakeEstablished},
	}
	for i, c := range cases {
		h := newHarness(t, ObsControl, 1)
		port := uint16(9000 + i)
		for _, s := range c.steps {
			s(h, port)
		}
		h.sweep(time.Second)
		h.sweep(20 * time.Second) // 半关闭等待
		h.sweep(40 * time.Second)
		h.sweep(16 * time.Minute)
		recs := h.kind(KindTCPFlow)
		final := recs[len(recs)-1]
		if final.RecordType != RecordFinal || final.CloseBy != c.close || final.FlowEnd != c.end || final.Handshake != c.handshake {
			t.Fatalf("%s: close_by=%s end=%s handshake=%s type=%s", c.name, final.CloseBy, final.FlowEnd, final.Handshake, final.RecordType)
		}
		if final.ObsMode != ObsControl {
			t.Fatalf("%s: obs_mode %s", c.name, final.ObsMode)
		}
	}
}

func TestFullModeResponse(t *testing.T) {
	h := newHarness(t, ObsFull, 1)
	ch := captureClientHello(t, "x.example")
	h.in(cIP, 9500, nodeIP, 443, tcpSYN, isn, 0, nil, 0)
	h.out(cIP, 9500, nodeIP, 443, tcpSYN|tcpACK, sISN, isn+1, nil, 5*time.Millisecond)
	h.in(cIP, 9500, nodeIP, 443, tcpACK|tcpPSH, isn+1, sISN+1, ch, 10*time.Millisecond)
	resp := []byte{22, 3, 3, 0, 3, 2, 0, 0, 20, 3, 3, 0, 1, 1, 23, 3, 3, 0, 4, 9, 9, 9, 9}
	h.out(cIP, 9500, nodeIP, 443, tcpACK|tcpPSH, sISN+1+13, isn+1, resp[13:], 40*time.Millisecond) // 乱序
	h.out(cIP, 9500, nodeIP, 443, tcpACK|tcpPSH, sISN+1, isn+1, resp[:13], 50*time.Millisecond)
	h.out(cIP, 9500, nodeIP, 443, tcpACK|tcpPSH, sISN+1, isn+1, resp[:13], 60*time.Millisecond) // 出站重传
	h.in(cIP, 9500, nodeIP, 443, tcpRST, isn+1+uint32(len(ch)), 0, nil, 100*time.Millisecond)
	h.sweep(5 * time.Second)
	e := h.only(t)
	if e.RespRecords != "22:3,20:1,23:4" || e.OutPkts != 3 || e.FirstRespMs == nil || *e.FirstRespMs != 40 || e.FlowPkts != 1 {
		t.Fatalf("full mode: resp=%s out=%d first=%v in=%d", e.RespRecords, e.OutPkts, e.FirstRespMs, e.FlowPkts)
	}
}

// ---------- 快照 / 终态 / 采样 ----------

func TestSnapshotThenFinal(t *testing.T) {
	h := newHarness(t, ObsInbound, 1)
	h.in(cIP, 9600, nodeIP, 443, tcpSYN, isn, 0, nil, 0)
	h.in(cIP, 9600, nodeIP, 443, tcpACK|tcpPSH, isn+1, 1, []byte("abc"), time.Second)
	h.sweep(61 * time.Second)
	h.in(cIP, 9600, nodeIP, 443, tcpACK|tcpPSH, isn+4, 1, []byte("defg"), 90*time.Second)
	h.in(cIP, 9600, nodeIP, 443, tcpFIN|tcpACK, isn+8, 1, nil, 100*time.Second)
	h.sweep(105 * time.Second)
	recs := h.kind(KindTCPFlow)
	if len(recs) != 2 || recs[0].RecordType != RecordSnapshot || recs[1].RecordType != RecordFinal || recs[0].FlowID != recs[1].FlowID {
		t.Fatalf("records: %+v", recs)
	}
	if recs[0].FlowPkts != 1 || recs[1].FlowPkts != 2 || recs[1].FlowBytes != 7 || recs[1].Revision != 2 || recs[1].EventID == recs[0].EventID {
		t.Fatalf("counts: snap=%d final=%d bytes=%d", recs[0].FlowPkts, recs[1].FlowPkts, recs[1].FlowBytes)
	}
	if recs[0].FlowEnd != "open" || recs[1].CloseBy != CloseClientFIN {
		t.Fatalf("snapshot mutated or wrong end: %s %s", recs[0].FlowEnd, recs[1].CloseBy)
	}
}

func TestStableSampling(t *testing.T) {
	// 采样率 0：一开始就已认证的连接整条不输出
	h := newHarness(t, ObsInbound, 0)
	h.access(cIP, 9700, xlog.AccessAccepted, 0)
	h.in(cIP, 9700, nodeIP, 443, tcpSYN, isn, 0, nil, 10*time.Millisecond)
	h.in(cIP, 9700, nodeIP, 443, tcpACK|tcpPSH, isn+1, 1, []byte("x"), time.Second)
	h.sweep(61 * time.Second)
	h.in(cIP, 9700, nodeIP, 443, tcpFIN|tcpACK, isn+2, 1, nil, 70*time.Second)
	h.sweep(80 * time.Second)
	if n := len(h.kind(KindTCPFlow)); n != 0 {
		t.Fatalf("sampled-out flow emitted %d records", n)
	}
	// 快照时还是 unknown，之后才认证：后续记录照常输出，不会只剩快照
	h = newHarness(t, ObsInbound, 0)
	h.in(cIP, 9701, nodeIP, 443, tcpSYN, isn, 0, nil, 0)
	h.in(cIP, 9701, nodeIP, 443, tcpACK|tcpPSH, isn+1, 1, []byte("x"), time.Second)
	h.sweep(61 * time.Second)
	h.access(cIP, 9701, xlog.AccessAccepted, 62*time.Second)
	h.in(cIP, 9701, nodeIP, 443, tcpFIN|tcpACK, isn+2, 1, nil, 70*time.Second)
	h.sweep(80 * time.Second)
	recs := h.kind(KindTCPFlow)
	if len(recs) != 2 || recs[1].Auth != AuthAccepted {
		t.Fatalf("late auth sampling: %+v", recs)
	}
}

func TestClosedPortSynAndMidstream(t *testing.T) {
	h := newHarness(t, ObsInbound, 1)
	h.in("9.9.9.9", 1111, nodeIP, 12345, tcpSYN, 1, 0, nil, 0)
	if s := h.kind(KindSyn); len(s) != 1 || s[0].PortState != PortClosed || s[0].TCPOpts == "" {
		t.Fatalf("syn: %+v", s)
	}
	// 中途接上的连接：只跟踪不上报
	h.in(cIP, 9800, nodeIP, 443, tcpACK|tcpPSH, 555, 1, []byte("middle"), 0)
	h.in(cIP, 9800, nodeIP, 443, tcpFIN|tcpACK, 561, 1, nil, time.Second)
	h.sweep(5 * time.Second)
	if n := len(h.kind(KindTCPFlow)); n != 0 || h.r.stats.midstreamFlows.Load() != 1 {
		t.Fatalf("midstream emitted=%d counted=%d", n, h.r.stats.midstreamFlows.Load())
	}
}

func TestXrayMessages(t *testing.T) {
	h := newHarness(t, ObsInbound, 1)
	h.r.onXrayMessage(&xlog.GeneralMessage{Severity: xlog.Severity_Info, Content: "REALITY: processed invalid connection"})
	h.r.onXrayMessage(&xlog.AccessMessage{From: "tcp:7.7.7.7:3333", To: "tcp:google.com:443", Status: xlog.AccessAccepted, Email: "u1"})
	if l := h.kind(KindXrayLog); len(l) != 1 || l[0].Severity != "info" {
		t.Fatalf("xray log: %+v", l)
	}
	if a := h.kind(KindXrayAccess); len(a) != 1 || a[0].XrayEmail != "u1" || a[0].SrcPort != 3333 || a[0].SchemaVersion != SchemaVersion || a[0].EventID == "" {
		t.Fatalf("access: %+v", a)
	}
}

func TestEventColumnsMatchSchema(t *testing.T) {
	// schema.sql 必须包含事件模型的所有列
	for _, c := range eventColumns() {
		if !strings.Contains(schemaSQL, "\n    "+c+" ") {
			t.Errorf("schema.sql missing column %s", c)
		}
	}
}
