package probelog

// Additional review cases for ac04263b08b63ce9aae09cb2fc72293152770415.
// These assert proposed correctness requirements and intentionally expose
// failures in that revision. They use only synthetic local packets.

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	xlog "github.com/xtls/xray-core/common/log"
)

func TestReviewNonTLSPrefixSegmentationInvariant(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	cases := [][][2]int{{{0, len(data)}}, {{0, 1}, {1, len(data)}}}
	var events []*Event
	for i, segs := range cases {
		h := newHarness(t, ObsInbound, 1)
		feedSegments(h, uint16(12000+i), segs, data)
		h.sweep(5 * time.Second)
		events = append(events, h.only(t))
	}
	if events[0].PrefixLen != events[1].PrefixLen || events[0].PrefixHash != events[1].PrefixHash {
		t.Fatalf("same stream: single=(len=%d hash=%s), split=(len=%d hash=%s)", events[0].PrefixLen, events[0].PrefixHash, events[1].PrefixLen, events[1].PrefixHash)
	}
}

func TestReviewPendingOverlapFirstArrivalWins(t *testing.T) {
	r := newReassembler(isn, 64)
	r.add(isn+1+4, []byte("AAAA"), false) // Arrived first, initially out of order.
	r.add(isn+1, []byte("0000BBBB"), false)
	if !r.flags[reasmConflict] {
		t.Fatal("expected conflicting-overlap quality flag")
	}
	if !bytes.Equal(r.prefix(), []byte("0000AAAA")) {
		t.Fatalf("first-arrival-wins: got %q, want %q (flags=%s)", r.prefix(), "0000AAAA", r.flagString())
	}
}

func TestReviewConflictingHelloNotTrusted(t *testing.T) {
	ch := captureClientHello(t, "review.example")
	h := newHarness(t, ObsControl, 1)
	h.in(cIP, 12010, nodeIP, 443, tcpSYN, isn, 0, nil, 0)
	h.in(cIP, 12010, nodeIP, 443, tcpACK|tcpPSH, isn+1, 1, ch[:50], 10*time.Millisecond)
	conflict := bytes.Clone(ch[:50])
	conflict[20] ^= 1 // Different random byte; both interpretations parse.
	h.in(cIP, 12010, nodeIP, 443, tcpACK|tcpPSH, isn+1, 1, conflict, 20*time.Millisecond)
	h.in(cIP, 12010, nodeIP, 443, tcpACK|tcpPSH, isn+51, 1, ch[50:], 30*time.Millisecond)
	h.in(cIP, 12010, nodeIP, 443, tcpRST, isn+1+uint32(len(ch)), 0, nil, time.Second)
	h.sweep(5 * time.Second)
	e := h.only(t)
	if !strings.Contains(e.ReasmFlags, reasmConflict) {
		t.Fatal("fixture did not record conflict")
	}
	// A syntax-only 'complete' can be retained if a separate trust field and
	// downstream quality filters are added. The current schema has neither.
	if e.TLSState == tlsComplete && (e.JA3 != "" || e.JA4 != "") {
		t.Fatalf("ambiguous bytes exported as usable fingerprint: state=%s flags=%s JA3=%s JA4=%s", e.TLSState, e.ReasmFlags, e.JA3, e.JA4)
	}
}

func reviewHelloWithExtensions(ext []byte, declared int) []byte {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0) // sid, cipher vector, compression.
	body = append(body, byte(declared>>8), byte(declared))
	body = append(body, ext...)
	hs := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 3, 1, 0, 0}
	binary.BigEndian.PutUint16(rec[3:], uint16(len(hs)))
	return append(rec, hs...)
}

func TestReviewMalformedHelloLengthValidation(t *testing.T) {
	// Both record and handshake lengths are correct. The malformed length is
	// internal, so this must be malformed rather than need_more or complete.
	cases := map[string][]byte{
		"nested_sni_length":       reviewHelloWithExtensions([]byte{0, 0, 0, 2, 0xff, 0xff}, 6),
		"extension_vector_length": reviewHelloWithExtensions(nil, 2),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			state, ch := classifyClientHello(raw)
			if state != tlsMalformed || ch != nil {
				t.Fatalf("invalid internal length: state=%s, returnedHello=%t", state, ch != nil)
			}
		})
	}
}

func TestReviewInvalidAckDoesNotProveHandshake(t *testing.T) {
	h := newHarness(t, ObsControl, 1)
	h.in(cIP, 12020, nodeIP, 443, tcpSYN, isn, 0, nil, 0)
	h.out(cIP, 12020, nodeIP, 443, tcpSYN|tcpACK, sISN, isn+1, nil, 5*time.Millisecond)
	h.in(cIP, 12020, nodeIP, 443, tcpACK|tcpPSH, isn+1, sISN+1234, []byte("probe"), 10*time.Millisecond)
	h.out(cIP, 12020, nodeIP, 443, tcpRST, sISN+1, 0, nil, 20*time.Millisecond)
	h.sweep(5 * time.Second)
	e := h.only(t)
	if e.Handshake == HandshakeEstablished {
		t.Fatalf("incorrect ACK plus data treated as established: handshake=%s close_by=%s", e.Handshake, e.CloseBy)
	}
}

func TestReviewPendingAuthRechecksAmbiguity(t *testing.T) {
	h := newHarness(t, ObsInbound, 1)
	h.access(cIP, 12030, xlog.AccessAccepted, 0)
	h.in(cIP, 12030, nodeIP, 443, tcpSYN, isn, 0, nil, 100*time.Millisecond)
	h.in(cIP, 12030, nodeIP, 8443, tcpSYN, isn+100, 0, nil, 110*time.Millisecond)
	h.in(cIP, 12030, nodeIP, 443, tcpRST, isn+1, 0, nil, time.Second)
	h.in(cIP, 12030, nodeIP, 8443, tcpRST, isn+101, 0, nil, time.Second)
	h.sweep(5 * time.Second)
	for _, e := range h.latest() {
		if e.Auth == AuthAccepted || e.AuthAssoc == AssocMatched {
			t.Errorf("log without destination assigned before candidate window closed: dst=%d auth=%s assoc=%s", e.DstPort, e.Auth, e.AuthAssoc)
		}
	}
}

func TestReviewLateAmbiguityEmitsCorrection(t *testing.T) {
	h := newHarness(t, ObsInbound, 1)
	for i, port := range []uint16{443, 8443} {
		seq := isn + uint32(i)*100
		h.in(cIP, 12040, nodeIP, port, tcpSYN, seq, 0, nil, 0)
		h.in(cIP, 12040, nodeIP, port, tcpRST, seq+1, 0, nil, time.Second)
	}
	h.sweep(5 * time.Second)
	h.access(cIP, 12040, xlog.AccessAccepted, 6*time.Second)
	for _, e := range h.latest() {
		if e.AuthAssoc != AssocAmbiguous || e.RecordType != RecordCorrection {
			t.Errorf("final row not revised for late ambiguity: dst=%d record=%s assoc=%s revision=%d", e.DstPort, e.RecordType, e.AuthAssoc, e.Revision)
		}
	}
}

func TestReviewServerActivityPreventsIdleExpiry(t *testing.T) {
	h := newHarness(t, ObsFull, 1)
	h.in(cIP, 12050, nodeIP, 443, tcpSYN, isn, 0, nil, 0)
	h.out(cIP, 12050, nodeIP, 443, tcpSYN|tcpACK, sISN, isn+1, nil, 5*time.Millisecond)
	h.in(cIP, 12050, nodeIP, 443, tcpACK|tcpPSH, isn+1, sISN+1, []byte("request"), 10*time.Millisecond)
	for i := 1; i <= 16; i++ {
		h.out(cIP, 12050, nodeIP, 443, tcpACK|tcpPSH, sISN+uint32(i), isn+8, []byte{0x42}, time.Duration(i)*time.Minute)
		h.sweep(time.Duration(i)*time.Minute + time.Millisecond)
	}
	e := h.only(t)
	if e.RecordType == RecordFinal {
		t.Fatalf("active server stream expired: record=%s reason=%s out_pkts=%d", e.RecordType, e.FlowEnd, e.OutPkts)
	}
}
