package probelog

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	quic "github.com/apernet/quic-go"
)

// ---------- 测试辅助：构造客户端 Initial ----------

func quicVarintAppend(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, 0x40|byte(v>>8), byte(v))
	case v < 1<<30:
		return append(b, 0x80|byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	return append(b, 0xc0|byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func cryptoFrame(off int, data []byte) []byte {
	b := quicVarintAppend([]byte{0x06}, uint64(off))
	b = quicVarintAppend(b, uint64(len(data)))
	return append(b, data...)
}

// sealInitial 按 RFC 9001 加密一个客户端 Initial（4 字节包号）。payload 不足时补 PADDING。
func sealInitial(t *testing.T, version uint32, dcid []byte, pn uint32, frames []byte) []byte {
	t.Helper()
	key, iv, hp, err := quicClientInitialSecrets(version, dcid)
	if err != nil {
		t.Fatal(err)
	}
	for len(frames) < 32 {
		frames = append(frames, 0)
	}
	typ := byte(0)
	if version == quicVersion2 {
		typ = 1
	}
	hdr := []byte{0xc0 | typ<<4 | 3}
	hdr = binary.BigEndian.AppendUint32(hdr, version)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0, 0) // SCID 长度 0、token 长度 0
	length := 4 + len(frames) + 16
	hdr = append(hdr, 0x40|byte(length>>8), byte(length))
	pnOff := len(hdr)
	hdr = binary.BigEndian.AppendUint32(hdr, pn)
	kb, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(kb)
	nonce := bytes.Clone(iv)
	for i := 0; i < 4; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	pkt := aead.Seal(bytes.Clone(hdr), nonce, frames, hdr)
	hb, _ := aes.NewCipher(hp)
	var mask [16]byte
	hb.Encrypt(mask[:], pkt[pnOff+4:pnOff+20])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < 4; i++ {
		pkt[pnOff+i] ^= mask[1+i]
	}
	return pkt
}

// helloHandshake 取出 crypto/tls 生成的 ClientHello handshake 消息（去掉 TLS record 头）及 SNI 位置
func helloHandshake(t *testing.T, sni string) ([]byte, int, int) {
	t.Helper()
	hs := captureClientHello(t, sni)[5:]
	ch, err := parseHandshake(hs)
	if err != nil || ch.sni != sni {
		t.Fatalf("hello: %v %q", err, ch.sni)
	}
	if string(hs[ch.sniOff:ch.sniOff+ch.sniLen]) != sni {
		t.Fatalf("sni offset %d wrong", ch.sniOff)
	}
	return hs, ch.sniOff, ch.sniLen
}

func (h *harness) udp(port uint16, payload []byte, d time.Duration) {
	h.t.Helper()
	h.feed(buildUDP4(cIP, nodeIP, port, 9443, payload), 0, false, d)
}

var testDCID = []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}

// ---------- 密钥推导 ----------

func TestQUICInitialSecretsVectors(t *testing.T) {
	// RFC 9001 附录 A.1 与 RFC 9369 附录 A.1 的客户端 Initial 密钥
	cases := []struct {
		version     uint32
		key, iv, hp string
	}{
		{quicVersion1, "1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c", "9f50449e04a0e810283a1e9933adedd2"},
		{quicVersion2, "8b1a0bc121284290a29e0971b5cd045d", "91f73e2351d8fa91660e909f", "45b95e15235d6f45a6b19cbcb0294ba9"},
	}
	for _, c := range cases {
		key, iv, hp, err := quicClientInitialSecrets(c.version, testDCID)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(key) != c.key || hex.EncodeToString(iv) != c.iv || hex.EncodeToString(hp) != c.hp {
			t.Errorf("version %#x: key=%x iv=%x hp=%x", c.version, key, iv, hp)
		}
	}
}

// ---------- 真实客户端（quic-go）发出的 Initial ----------

// captureQUICInitials 用 quic-go 客户端向本地 UDP 端口拨号，收集它发出的第一轮数据报
func captureQUICInitials(t *testing.T, v quic.Version, sni string) [][]byte {
	t.Helper()
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go quic.Dial(ctx, cli, srv.LocalAddr(), &tls.Config{ServerName: sni, NextProtos: []string{"h3"}}, &quic.Config{Versions: []quic.Version{v}})
	var out [][]byte
	buf := make([]byte, 65536)
	for {
		wait := 2 * time.Second
		if len(out) > 0 {
			wait = 150 * time.Millisecond // 第一轮之后的停顿：之后的是重传
		}
		srv.SetReadDeadline(time.Now().Add(wait))
		n, _, err := srv.ReadFromUDP(buf)
		if err != nil {
			break
		}
		out = append(out, bytes.Clone(buf[:n]))
	}
	if len(out) == 0 {
		t.Fatal("quic-go sent nothing")
	}
	return out
}

func TestQUICInitialRealClient(t *testing.T) {
	for _, v := range []quic.Version{quic.Version1, quic.Version2} {
		dgs := captureQUICInitials(t, v, "real.quic.example")
		h := newHarness(t, ObsInbound, 1)
		for i, d := range dgs {
			h.udp(15000, d, time.Duration(i)*time.Millisecond)
		}
		h.sweep(time.Minute)
		e := h.only(t)
		if e.QUICInitial != QUICInitialOK || e.TLSState != tlsComplete || e.TLSSNI != "real.quic.example" ||
			!strings.HasPrefix(e.JA4, "q13d") || e.TLSALPN != "h3" || e.QUICInitials == 0 {
			t.Fatalf("version %v (%d datagrams): initial=%s tls=%s sni=%s ja4=%s alpn=%s initials=%d flags=%s",
				v, len(dgs), e.QUICInitial, e.TLSState, e.TLSSNI, e.JA4, e.TLSALPN, e.QUICInitials, e.ReasmFlags)
		}
		switch e.QUICSNIFirst {
		case QUICSNIFirstFull, QUICSNIFirstPartial, QUICSNIFirstNone:
		default:
			t.Fatalf("quic_sni_first = %q", e.QUICSNIFirst)
		}
		t.Logf("version %v: %d datagrams, %d with Initial, sni_first=%s, ja4=%s", v, len(dgs), e.QUICInitials, e.QUICSNIFirst, e.JA4)
	}
}

// ---------- SNI 在第一个数据报中的位置 ----------

func TestQUICSNIFirstDatagram(t *testing.T) {
	hs, off, n := helloHandshake(t, "split.quic.example")
	mid := off + n/2
	cases := []struct {
		name string
		dgs  [][]byte // 每个数据报的 CRYPTO 帧
		want string
		pkts uint8
	}{
		{"single", [][]byte{cryptoFrame(0, hs)}, QUICSNIFirstFull, 1},
		{"after_sni", [][]byte{cryptoFrame(0, hs[:off+n]), cryptoFrame(off+n, hs[off+n:])}, QUICSNIFirstFull, 2},
		{"sni_cut", [][]byte{cryptoFrame(0, hs[:mid]), cryptoFrame(mid, hs[mid:])}, QUICSNIFirstPartial, 2},
		{"sni_later", [][]byte{cryptoFrame(0, hs[:off-1]), cryptoFrame(off-1, hs[off-1:])}, QUICSNIFirstNone, 2},
		// 第一个数据报带的是后半段（乱序发送）
		{"reversed", [][]byte{cryptoFrame(mid, hs[mid:]), cryptoFrame(0, hs[:mid])}, QUICSNIFirstPartial, 2},
		// 同一数据报里多个 CRYPTO 帧、打乱顺序
		{"shuffled_frames", [][]byte{append(cryptoFrame(mid, hs[mid:]), cryptoFrame(0, hs[:mid])...)}, QUICSNIFirstFull, 1},
	}
	for i, c := range cases {
		h := newHarness(t, ObsInbound, 1)
		for j, frames := range c.dgs {
			h.udp(uint16(15100+i), sealInitial(t, quicVersion1, testDCID, uint32(j), frames), time.Duration(j)*time.Millisecond)
		}
		h.sweep(time.Minute)
		e := h.only(t)
		if e.TLSState != tlsComplete || e.TLSSNI != "split.quic.example" || e.QUICSNIFirst != c.want || e.QUICInitials != c.pkts {
			t.Errorf("%s: tls=%s sni=%s sni_first=%s initials=%d", c.name, e.TLSState, e.TLSSNI, e.QUICSNIFirst, e.QUICInitials)
		}
	}
}

// ---------- 合并包、异常与质量 ----------

func TestQUICInitialEdgeCases(t *testing.T) {
	hs, _, _ := helloHandshake(t, "edge.quic.example")
	good := sealInitial(t, quicVersion1, testDCID, 0, cryptoFrame(0, hs))

	// Initial 后面合并了别的长包头包（0-RTT），以及数据报末尾的填充字节
	zeroRTT := bytes.Clone(sealInitial(t, quicVersion1, testDCID, 1, []byte{1}))
	zeroRTT[0] = (zeroRTT[0] &^ 0x30) | 0x10        // 改成 0-RTT 类型（头部保护只影响低 4 位）
	zeroRTT = append(zeroRTT[:15], zeroRTT[16:]...) // 0-RTT 没有 token 长度字段
	coalesced := append(append(bytes.Clone(good), zeroRTT...), make([]byte, 40)...)

	badTag := bytes.Clone(good)
	badTag[len(badTag)-1] ^= 1

	unsupported := bytes.Clone(good)
	binary.BigEndian.PutUint32(unsupported[1:5], 0xff00001d)

	type result struct{ initial, tls string }
	cases := []struct {
		name  string
		dgs   [][]byte
		trunc int // >0 时第一个数据报只捕获这么多字节
		want  result
	}{
		{"coalesced", [][]byte{coalesced}, 0, result{QUICInitialOK, tlsComplete}},
		{"bad_tag", [][]byte{badTag}, 0, result{QUICInitialDecrypt, ""}},
		{"unsupported", [][]byte{unsupported}, 0, result{QUICInitialUnsupported, ""}},
		{"truncated", [][]byte{good}, 300, result{QUICInitialTruncated, ""}},
		{"partial_hello", [][]byte{sealInitial(t, quicVersion1, testDCID, 0, cryptoFrame(0, hs[:100]))}, 0, result{QUICInitialOK, tlsIncomplete}},
		{"not_hello", [][]byte{sealInitial(t, quicVersion1, testDCID, 0, cryptoFrame(0, []byte{2, 0, 0, 1, 0}))}, 0, result{QUICInitialOK, tlsNotCH}},
		{"bad_frame", [][]byte{sealInitial(t, quicVersion1, testDCID, 0, append(cryptoFrame(0, hs), 0x08))}, 0, result{QUICInitialMalformed, ""}},
		{"conflict", [][]byte{
			sealInitial(t, quicVersion1, testDCID, 0, cryptoFrame(0, hs[:60])),
			sealInitial(t, quicVersion1, testDCID, 1, cryptoFrame(0, append(bytes.Clone(hs[:20]), bytes.Repeat([]byte{0xee}, 40)...))),
			sealInitial(t, quicVersion1, testDCID, 2, cryptoFrame(60, hs[60:])),
		}, 0, result{QUICInitialOK, tlsConflict}},
	}
	for i, c := range cases {
		h := newHarness(t, ObsInbound, 1)
		for j, d := range c.dgs {
			raw := buildUDP4(cIP, nodeIP, uint16(15200+i), 9443, d)
			if j == 0 && c.trunc > 0 {
				h.feed(raw[:28+c.trunc], len(raw), false, 0)
				continue
			}
			h.feed(raw, 0, false, time.Duration(j)*time.Millisecond)
		}
		h.sweep(time.Minute)
		e := h.only(t)
		if e.QUICInitial != c.want.initial || e.TLSState != c.want.tls {
			t.Errorf("%s: initial=%s tls=%s flags=%s", c.name, e.QUICInitial, e.TLSState, e.ReasmFlags)
		}
		if c.want.tls != tlsComplete && (e.JA4 != "" || e.TLSSNI != "") {
			t.Errorf("%s: fingerprint exported: %s %s", c.name, e.JA4, e.TLSSNI)
		}
	}

	// 非 QUIC 的 UDP 不解析
	h := newHarness(t, ObsInbound, 1)
	h.udp(15300, []byte("\x00\x01hello dns?"), 0)
	h.sweep(time.Minute)
	if e := h.only(t); e.QUICInitial != "" || e.TLSState != "" {
		t.Fatalf("non-quic: %+v", e)
	}
}

// 解析窗口：首个数据报 2 秒后才到的 Initial 不再解析；最多解析 quicMaxDatagrams 个数据报
func TestQUICInitialWindow(t *testing.T) {
	hs, _, _ := helloHandshake(t, "win.quic.example")
	h := newHarness(t, ObsInbound, 1)
	h.udp(15400, sealInitial(t, quicVersion1, testDCID, 0, cryptoFrame(0, hs[:100])), 0)
	h.udp(15400, sealInitial(t, quicVersion1, testDCID, 1, cryptoFrame(100, hs[100:])), 3*time.Second)
	h.sweep(time.Minute)
	if e := h.only(t); e.TLSState != tlsIncomplete || e.QUICInitials != 1 || e.FlowPkts != 2 {
		t.Fatalf("window: tls=%s initials=%d pkts=%d", e.TLSState, e.QUICInitials, e.FlowPkts)
	}

	h = newHarness(t, ObsInbound, 1)
	for i := 0; i < quicMaxDatagrams+3; i++ {
		h.udp(15401, sealInitial(t, quicVersion1, testDCID, uint32(i), []byte{1}), time.Duration(i)*time.Millisecond)
	}
	h.sweep(time.Minute)
	if e := h.only(t); e.QUICInitials != quicMaxDatagrams || e.TLSState != tlsIncomplete {
		t.Fatalf("datagram limit: initials=%d tls=%s", e.QUICInitials, e.TLSState)
	}
}
