package probelog

// 第二轮复审（ac04263）中列出、但 review_regression_test.go 没有覆盖的验收条件

import (
	"bytes"
	"strings"
	"testing"
	"time"

	xlog "github.com/xtls/xray-core/common/log"
)

// ---------- 前缀采集与分段无关 ----------

func TestPrefixSegmentationVariants(t *testing.T) {
	data := []byte("GET /index.html HTTP/1.1\r\nHost: example.test\r\nUser-Agent: x\r\n\r\n")
	n := len(data)
	cases := map[string][][2]int{
		"single":  {{0, n}},
		"first1":  {{0, 1}, {1, n}},
		"many":    {{0, 3}, {3, 10}, {10, 30}, {30, n}},
		"reorder": {{10, n}, {0, 10}},
		"dup":     {{0, 5}, {0, 5}, {5, n}},
	}
	var ref *Event
	for name, segs := range cases {
		h := newHarness(t, ObsInbound, 1)
		feedSegments(h, 13000, segs, data)
		h.sweep(5 * time.Second)
		e := h.only(t)
		if e.PrefixLen != uint32(n) || e.PrefixStop != PrefixStopWindow || e.TLSState != tlsNotCH {
			t.Fatalf("%s: len=%d stop=%s tls=%s", name, e.PrefixLen, e.PrefixStop, e.TLSState)
		}
		if ref == nil {
			ref = e
		} else if e.PrefixHash != ref.PrefixHash {
			t.Fatalf("%s: hash %s != %s", name, e.PrefixHash, ref.PrefixHash)
		}
	}
}

// ClientHello 之后紧跟的数据在同一段还是下一段，前缀范围都一样
func TestPrefixTLSWithTrailingData(t *testing.T) {
	ch := captureClientHello(t, "trail.example")
	stream := append(bytes.Clone(ch), []byte{0x14, 3, 3, 0, 1, 1, 0x17, 3, 3, 0, 2, 9, 9}...)
	var hashes []string
	for i, segs := range [][][2]int{{{0, len(stream)}}, {{0, len(ch)}, {len(ch), len(stream)}}} {
		h := newHarness(t, ObsInbound, 1)
		feedSegments(h, uint16(13100+i), segs, stream)
		h.sweep(5 * time.Second)
		e := h.only(t)
		if e.TLSState != tlsComplete || e.PrefixLen != uint32(len(stream)) {
			t.Fatalf("case %d: tls=%s len=%d", i, e.TLSState, e.PrefixLen)
		}
		hashes = append(hashes, e.PrefixHash)
	}
	if hashes[0] != hashes[1] {
		t.Fatalf("hash depends on segmentation: %v", hashes)
	}
}

// 首段之后超过采集窗口才到的字节不进入前缀（按包时间，不取决于清理何时运行）
func TestPrefixWindowByPacketTime(t *testing.T) {
	h := newHarness(t, ObsInbound, 1)
	h.in(cIP, 13200, nodeIP, 22, tcpSYN, isn, 0, nil, 0)
	h.in(cIP, 13200, nodeIP, 22, tcpACK|tcpPSH, isn+1, 1, []byte("SSH-2.0-a\r\n"), 10*time.Millisecond)
	h.in(cIP, 13200, nodeIP, 22, tcpACK|tcpPSH, isn+12, 1, []byte("late"), 3*time.Second)
	h.in(cIP, 13200, nodeIP, 22, tcpFIN|tcpACK, isn+16, 1, nil, 3*time.Second)
	h.sweep(10 * time.Second)
	if e := h.only(t); e.PrefixLen != 11 || e.PrefixStop != PrefixStopWindow {
		t.Fatalf("len=%d stop=%s", e.PrefixLen, e.PrefixStop)
	}
}

func TestPrefixStopsAtByteBudget(t *testing.T) {
	data := bytes.Repeat([]byte("A"), prefixHashMax+100)
	h := newHarness(t, ObsInbound, 1)
	feedSegments(h, 13300, [][2]int{{0, 1000}, {1000, len(data)}}, data)
	h.sweep(5 * time.Second)
	if e := h.only(t); e.PrefixLen != prefixHashMax || e.PrefixStop != PrefixStopBytes {
		t.Fatalf("len=%d stop=%s", e.PrefixLen, e.PrefixStop)
	}
}

// ---------- TLS 结构与冲突 ----------

func TestMalformedHelloVectors(t *testing.T) {
	good := reviewHelloWithExtensions(nil, 0)
	if st, _ := classifyClientHello(good); st != tlsComplete {
		t.Fatalf("baseline hello: %s", st)
	}
	ext := func(typ uint16, body []byte) []byte {
		b := []byte{byte(typ >> 8), byte(typ), byte(len(body) >> 8), byte(len(body))}
		return append(b, body...)
	}
	cases := map[string][]byte{
		"groups_odd":        ext(0x000a, []byte{0, 3, 0, 0x1d, 0}),
		"sigalgs_overrun":   ext(0x000d, []byte{0, 8, 4, 3}),
		"alpn_empty_name":   ext(0x0010, []byte{0, 1, 0}),
		"sni_trailing":      ext(0x0000, []byte{0, 4, 0, 0, 1, 'a', 0xff}),
		"supvers_odd":       ext(0x002b, []byte{3, 3, 4, 3}),
		"unknown_overrun":   append(ext(0xfe0d, nil)[:2], 0, 9, 1),
		"ext_header_trunc":  {0, 0x0a, 0},
		"point_fmts_empty":  ext(0x000b, []byte{0}),
		"sni_list_trailing": ext(0x0000, []byte{0, 3, 0, 0, 0, 0}),
	}
	for name, e := range cases {
		raw := reviewHelloWithExtensions(e, len(e))
		if st, ch := classifyClientHello(raw); st != tlsMalformed || ch != nil {
			t.Errorf("%s: state=%s", name, st)
		}
	}
	// 未知扩展按声明长度跳过，不算畸形
	unk := ext(0xfe0d, []byte{1, 2, 3})
	if st, _ := classifyClientHello(reviewHelloWithExtensions(unk, len(unk))); st != tlsComplete {
		t.Fatalf("unknown extension: %s", st)
	}
}

// 冲突在 ClientHello 之后：指纹仍可用，质量标记保留
func TestConflictAfterHelloKeepsFingerprint(t *testing.T) {
	ch := captureClientHello(t, "after.example")
	n := uint32(len(ch))
	h := newHarness(t, ObsInbound, 1)
	h.in(cIP, 13400, nodeIP, 443, tcpSYN, isn, 0, nil, 0)
	h.in(cIP, 13400, nodeIP, 443, tcpACK|tcpPSH, isn+1, 1, ch, 10*time.Millisecond)
	h.in(cIP, 13400, nodeIP, 443, tcpACK|tcpPSH, isn+1+n, 1, []byte("AAAA"), 20*time.Millisecond)
	h.in(cIP, 13400, nodeIP, 443, tcpACK|tcpPSH, isn+1+n, 1, []byte("AAAB"), 30*time.Millisecond)
	h.in(cIP, 13400, nodeIP, 443, tcpRST, isn+5+n, 0, nil, time.Second)
	h.sweep(5 * time.Second)
	e := h.only(t)
	if e.TLSState != tlsComplete || e.JA4 == "" || !strings.Contains(e.ReasmFlags, reasmConflict) {
		t.Fatalf("tls=%s ja4=%s flags=%s", e.TLSState, e.JA4, e.ReasmFlags)
	}
}

func TestConflictingHelloState(t *testing.T) {
	ch := captureClientHello(t, "c.example")
	h := newHarness(t, ObsInbound, 1)
	h.in(cIP, 13500, nodeIP, 443, tcpSYN, isn, 0, nil, 0)
	h.in(cIP, 13500, nodeIP, 443, tcpACK|tcpPSH, isn+1, 1, ch, 10*time.Millisecond)
	bad := bytes.Clone(ch[:60])
	bad[30] ^= 0xff
	h.in(cIP, 13500, nodeIP, 443, tcpACK|tcpPSH, isn+1, 1, bad, 20*time.Millisecond)
	h.in(cIP, 13500, nodeIP, 443, tcpRST, isn+1+uint32(len(ch)), 0, nil, time.Second)
	h.sweep(5 * time.Second)
	e := h.only(t)
	if e.TLSState != tlsConflict || e.JA3 != "" || e.JA4 != "" || e.TLSSNI != "" {
		t.Fatalf("tls=%s ja4=%s sni=%s", e.TLSState, e.JA4, e.TLSSNI)
	}
}

// ---------- 重叠：先到达的字节优先 ----------

func TestReassemblerFirstArrival(t *testing.T) {
	type seg struct {
		off  uint32
		data string
	}
	cases := []struct {
		name string
		base uint32
		segs []seg
		want string
		conf bool
	}{
		{"contiguous_overlap", 0, []seg{{0, "0000AAAA"}, {4, "BBBB"}}, "0000AAAA", true},
		{"pending_pending", 0, []seg{{4, "AAAA"}, {6, "BBBB"}, {0, "0000"}}, "0000AAAABB", true},
		{"filler_overlaps_pending", 0, []seg{{4, "AA"}, {8, "CC"}, {0, "0000XXYYZZ"}}, "0000AAYYCC", true},
		{"same_offset_order1", 0, []seg{{4, "AAAA"}, {4, "BBBB"}, {0, "0000"}}, "0000AAAA", true},
		{"same_offset_order2", 0, []seg{{4, "BBBB"}, {4, "AAAA"}, {0, "0000"}}, "0000BBBB", true},
		{"identical_overlap", 0, []seg{{4, "AAAA"}, {2, "00AAAA"}, {0, "00"}}, "0000AAAA", false},
		{"wraparound", 0xfffffffc, []seg{{2, "AAAA"}, {0, "00BBBB"}}, "00AAAA", true},
	}
	for _, c := range cases {
		r := newReassembler(c.base, 64)
		for _, s := range c.segs {
			r.add(c.base+1+s.off, []byte(s.data), false)
		}
		if string(r.prefix()) != c.want || r.flags[reasmConflict] != c.conf || r.hasGap() {
			t.Errorf("%s: got %q flags=%s", c.name, r.prefix(), r.flagString())
		}
	}
}

// ---------- 认证关联不取决于处理顺序 ----------

func TestAuthAssociationOrderIndependent(t *testing.T) {
	type step func(h *harness)
	const port = 13600
	log := func(h *harness) { h.access(cIP, port, xlog.AccessAccepted, 50*time.Millisecond) }
	syn443 := func(h *harness) { h.in(cIP, port, nodeIP, 443, tcpSYN, isn, 0, nil, 100*time.Millisecond) }
	syn8443 := func(h *harness) { h.in(cIP, port, nodeIP, 8443, tcpSYN, isn+100, 0, nil, 110*time.Millisecond) }
	orders := map[string][]step{
		"log_first":   {log, syn443, syn8443},
		"flows_first": {syn443, syn8443, log},
		"interleaved": {syn443, log, syn8443},
	}
	for name, steps := range orders {
		h := newHarness(t, ObsInbound, 1)
		for _, s := range steps {
			s(h)
		}
		h.in(cIP, port, nodeIP, 443, tcpRST, isn+1, 0, nil, time.Second)
		h.in(cIP, port, nodeIP, 8443, tcpRST, isn+101, 0, nil, time.Second)
		h.sweep(5 * time.Second)
		latest := h.latest()
		if len(latest) != 2 {
			t.Fatalf("%s: %d flows", name, len(latest))
		}
		for _, e := range latest {
			if e.Auth != AuthUnknown || e.AuthAssoc != AssocAmbiguous {
				t.Errorf("%s: dst=%d auth=%s assoc=%s", name, e.DstPort, e.Auth, e.AuthAssoc)
			}
		}
	}
}

// 已唯一匹配并输出后，抓包处理落后的另一个候选才出现：撤回为 ambiguous 并发 correction
func TestLateCandidateRevokesMatch(t *testing.T) {
	h := newHarness(t, ObsInbound, 1)
	h.in(cIP, 13700, nodeIP, 443, tcpSYN, isn, 0, nil, 0)
	h.access(cIP, 13700, xlog.AccessAccepted, 100*time.Millisecond)
	h.in(cIP, 13700, nodeIP, 443, tcpRST, isn+1, 0, nil, time.Second)
	h.sweep(5 * time.Second)
	if e := h.only(t); e.Auth != AuthAccepted || e.AuthAssoc != AssocMatched || e.RecordType != RecordFinal {
		t.Fatalf("initial: %s/%s %s", e.Auth, e.AuthAssoc, e.RecordType)
	}
	// 时间戳落在候选窗口内（日志时间 + closeGrace），但处理得晚
	h.in(cIP, 13700, nodeIP, 8443, tcpSYN, isn+500, 0, nil, 1500*time.Millisecond)
	h.in(cIP, 13700, nodeIP, 8443, tcpRST, isn+501, 0, nil, 6*time.Second)
	h.sweep(10 * time.Second)
	for _, e := range h.latest() {
		if e.Auth == AuthAccepted || e.AuthAssoc != AssocAmbiguous {
			t.Errorf("dst=%d auth=%s assoc=%s record=%s", e.DstPort, e.Auth, e.AuthAssoc, e.RecordType)
		}
	}
	recs := 0
	for _, e := range h.kind(KindTCPFlow) {
		if e.DstPort == 443 {
			recs++
			if e.RecordType == RecordCorrection && e.Revision != 2 {
				t.Fatalf("correction revision %d", e.Revision)
			}
		}
	}
	if recs != 2 {
		t.Fatalf("443 records = %d, want final + correction", recs)
	}
}

func TestRepeatedAmbiguousLogNoExtraRevisions(t *testing.T) {
	h := newHarness(t, ObsInbound, 1)
	for i, port := range []uint16{443, 8443} {
		seq := isn + uint32(i)*100
		h.in(cIP, 13800, nodeIP, port, tcpSYN, seq, 0, nil, 0)
		h.in(cIP, 13800, nodeIP, port, tcpRST, seq+1, 0, nil, time.Second)
	}
	h.sweep(5 * time.Second)
	for i := 0; i < 3; i++ {
		h.access(cIP, 13800, xlog.AccessAccepted, 6*time.Second)
	}
	h.sweep(12 * time.Second)
	if n := len(h.kind(KindTCPFlow)); n != 4 {
		t.Fatalf("records = %d, want 2 final + 2 correction", n)
	}
	for _, e := range h.kind(KindTCPFlow) {
		if e.RecordType == RecordFinal && e.AuthAssoc != AssocUnmatched {
			t.Fatal("final row mutated in place")
		}
	}
}

// ---------- 握手证据 ----------

func TestHandshakeEvidence(t *testing.T) {
	cases := []struct {
		name  string
		mode  string
		steps func(h *harness, p uint16)
		want  string
		flags string
	}{
		{"valid_ack_data", ObsControl, func(h *harness, p uint16) {
			h.out(cIP, p, nodeIP, 443, tcpSYN|tcpACK, sISN, isn+1, nil, 5*time.Millisecond)
			h.in(cIP, p, nodeIP, 443, tcpACK|tcpPSH, isn+1, sISN+1, []byte("x"), 10*time.Millisecond)
		}, HandshakeEstablished, ""},
		{"ack_before_isn", ObsControl, func(h *harness, p uint16) {
			h.out(cIP, p, nodeIP, 443, tcpSYN|tcpACK, sISN, isn+1, nil, 5*time.Millisecond)
			h.in(cIP, p, nodeIP, 443, tcpACK|tcpPSH, isn+1, sISN-5, []byte("x"), 10*time.Millisecond)
		}, HandshakeSynAck, HSFlagBadAck},
		{"no_ack_flag", ObsControl, func(h *harness, p uint16) {
			h.out(cIP, p, nodeIP, 443, tcpSYN|tcpACK, sISN, isn+1, nil, 5*time.Millisecond)
			h.in(cIP, p, nodeIP, 443, tcpPSH, isn+1, 0, []byte("x"), 10*time.Millisecond)
		}, HandshakeSynAck, HSFlagNoAck},
		{"fin_without_ack", ObsControl, func(h *harness, p uint16) {
			h.out(cIP, p, nodeIP, 443, tcpSYN|tcpACK, sISN, isn+1, nil, 5*time.Millisecond)
			h.in(cIP, p, nodeIP, 443, tcpFIN, isn+1, 0, nil, 10*time.Millisecond)
		}, HandshakeSynAck, HSFlagNoAck},
		{"inbound_data", ObsInbound, func(h *harness, p uint16) {
			h.in(cIP, p, nodeIP, 443, tcpACK|tcpPSH, isn+1, 77, []byte("x"), 10*time.Millisecond)
		}, HandshakeInferred, ""},
		{"inbound_no_ack", ObsInbound, func(h *harness, p uint16) {
			h.in(cIP, p, nodeIP, 443, tcpPSH, isn+1, 0, []byte("x"), 10*time.Millisecond)
		}, HandshakeUnknown, HSFlagNoAck},
		{"full_server_first", ObsFull, func(h *harness, p uint16) {
			h.out(cIP, p, nodeIP, 443, tcpSYN|tcpACK, sISN, isn+1, nil, 5*time.Millisecond)
			h.out(cIP, p, nodeIP, 443, tcpACK|tcpPSH, sISN+1, isn+1, []byte("banner"), 8*time.Millisecond)
			h.in(cIP, p, nodeIP, 443, tcpACK|tcpPSH, isn+1, sISN+7, []byte("x"), 10*time.Millisecond)
		}, HandshakeEstablished, ""},
		{"full_ack_beyond_sent", ObsFull, func(h *harness, p uint16) {
			h.out(cIP, p, nodeIP, 443, tcpSYN|tcpACK, sISN, isn+1, nil, 5*time.Millisecond)
			h.in(cIP, p, nodeIP, 443, tcpACK|tcpPSH, isn+1, sISN+1234, []byte("x"), 10*time.Millisecond)
		}, HandshakeSynAck, HSFlagBadAck},
		{"control_ack_unseen_data", ObsControl, func(h *harness, p uint16) {
			h.out(cIP, p, nodeIP, 443, tcpSYN|tcpACK, sISN, isn+1, nil, 5*time.Millisecond)
			h.in(cIP, p, nodeIP, 443, tcpACK|tcpPSH, isn+1, sISN+7, []byte("x"), 10*time.Millisecond)
		}, HandshakeInferred, ""},
	}
	for i, c := range cases {
		h := newHarness(t, c.mode, 1)
		p := uint16(13900 + i)
		h.in(cIP, p, nodeIP, 443, tcpSYN, isn, 0, nil, 0)
		c.steps(h, p)
		h.in(cIP, p, nodeIP, 443, tcpRST, isn+2, 0, nil, time.Second)
		h.sweep(5 * time.Second)
		e := h.only(t)
		if e.Handshake != c.want || e.HSFlags != c.flags {
			t.Errorf("%s: handshake=%s hs_flags=%s, want %s/%s", c.name, e.Handshake, e.HSFlags, c.want, c.flags)
		}
	}
}

// ---------- 回收计时 ----------

func TestIdleExpiryBothDirections(t *testing.T) {
	// full 模式：双向都没有可见活动超过预算时仍会回收
	h := newHarness(t, ObsFull, 1)
	h.in(cIP, 14000, nodeIP, 443, tcpSYN, isn, 0, nil, 0)
	h.out(cIP, 14000, nodeIP, 443, tcpSYN|tcpACK, sISN, isn+1, nil, 5*time.Millisecond)
	h.in(cIP, 14000, nodeIP, 443, tcpACK|tcpPSH, isn+1, sISN+1, []byte("r"), 10*time.Millisecond)
	h.out(cIP, 14000, nodeIP, 443, tcpACK|tcpPSH, sISN+1, isn+2, []byte("data"), time.Minute)
	h.sweep(time.Minute + tcpIdleTimeout - time.Second)
	if len(h.kind(KindTCPFlow)) != 1 || h.kind(KindTCPFlow)[0].RecordType != RecordSnapshot {
		t.Fatal("expired before idle budget")
	}
	h.sweep(time.Minute + tcpIdleTimeout + time.Second)
	if e := h.only(t); e.RecordType != RecordFinal || e.FlowEnd != "idle_timeout" {
		t.Fatalf("record=%s end=%s", e.RecordType, e.FlowEnd)
	}

	// server-first：客户端没有数据，但节点有数据，不按 no_data_timeout 回收
	h = newHarness(t, ObsFull, 1)
	h.in(cIP, 14001, nodeIP, 443, tcpSYN, isn, 0, nil, 0)
	h.out(cIP, 14001, nodeIP, 443, tcpSYN|tcpACK, sISN, isn+1, nil, 5*time.Millisecond)
	for i := 1; i <= 3; i++ {
		h.out(cIP, 14001, nodeIP, 443, tcpACK|tcpPSH, sISN+uint32(i), isn+1, []byte{1}, time.Duration(i)*20*time.Second)
		h.sweep(time.Duration(i)*20*time.Second + time.Millisecond)
	}
	for _, e := range h.kind(KindTCPFlow) {
		if e.RecordType == RecordFinal {
			t.Fatalf("server-first expired: %s", e.FlowEnd)
		}
	}
}
