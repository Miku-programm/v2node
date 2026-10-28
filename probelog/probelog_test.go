package probelog

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wyx2685/v2node/conf"
	xlog "github.com/xtls/xray-core/common/log"
)

// captureClientHello 让 crypto/tls 客户端写出一个真实的 ClientHello
func captureClientHello(t *testing.T, sni string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	go func() {
		cl := tls.Client(c1, &tls.Config{ServerName: sni, NextProtos: []string{"h2", "http/1.1"}})
		cl.Handshake()
	}()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, err := c2.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if need := clientHelloNeed(buf); need > 0 && len(buf) >= need || err != nil {
			break
		}
	}
	c1.Close()
	c2.Close()
	return buf
}

func TestParseClientHello(t *testing.T) {
	raw := captureClientHello(t, "www.example.com")
	ch, err := parseClientHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ch.sni != "www.example.com" {
		t.Fatalf("sni = %q", ch.sni)
	}
	if len(ch.alpn) != 2 || ch.alpn[0] != "h2" {
		t.Fatalf("alpn = %v", ch.alpn)
	}
	if tlsVersionName(ch.version()) != "1.3" {
		t.Fatalf("version = %x", ch.version())
	}
	ja4 := ch.ja4()
	if !strings.HasPrefix(ja4, "t13d") || !strings.HasSuffix(strings.Split(ja4, "_")[0], "h2") || len(ja4) != 36 {
		t.Fatalf("ja4 = %s", ja4)
	}
	if len(ch.ja3()) != 32 {
		t.Fatalf("ja3 = %s", ch.ja3())
	}
}

// buildTCP4 构造一个 IPv4 TCP 包
func buildTCP4(src, dst string, sport, dport uint16, flags uint8, payload []byte) []byte {
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
	tcp[12] = byte(tcpLen/4) << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 64240)
	copy(tcp[20:], opts)
	copy(tcp[tcpLen:], payload)
	return b
}

func TestParsePacket(t *testing.T) {
	p, err := parsePacket(buildTCP4("1.2.3.4", "5.6.7.8", 40000, 443, tcpSYN, nil), ethPIPv4)
	if err != nil {
		t.Fatal(err)
	}
	if p.src.String() != "1.2.3.4" || p.dport != 443 || p.ttl != 47 || !p.df || p.ipID != 0x1234 {
		t.Fatalf("bad header: %+v", p)
	}
	if p.opts != "M1460,S,T,N,W7" || p.mss != 1460 || p.tsVal != 7 || p.win != 64240 {
		t.Fatalf("bad options: %q mss=%d ts=%d", p.opts, p.mss, p.tsVal)
	}
	if tcpFlagString(tcpSYN|tcpACK) != "SA" {
		t.Fatal("flag string")
	}
}

func TestBuildFilter(t *testing.T) {
	ports := make([]uint16, 300)
	for i := range ports {
		ports[i] = uint16(10000 + i)
	}
	raw, err := buildFilter(ports, ports)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || len(raw) > 4096 {
		t.Fatalf("filter length %d", len(raw))
	}
	if _, err := buildFilter(nil, nil); err != nil {
		t.Fatal(err)
	}
}

func readEvents(t *testing.T, path string) []Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func TestFlowEndToEnd(t *testing.T) {
	file := filepath.Join(t.TempDir(), "events.jsonl")
	c := conf.New().ProbeLogConfig
	c.Enable = true
	c.Capture = false
	c.GeoTags = nil
	c.NodeName = "test"
	c.LocalFile = file
	if err := Start(&c); err != nil {
		t.Fatal(err)
	}
	RegisterNode(NodePort{Tag: "n1", Type: "vless", Security: "reality", Port: 443})
	defer UnregisterNode("n1")
	r := current()
	now := time.Now()
	hello := captureClientHello(t, "www.microsoft.com")
	handle := func(b []byte, d time.Duration) {
		p, err := parsePacket(b, ethPIPv4)
		if err != nil {
			t.Fatal(err)
		}
		r.flows.handle(p, now.Add(d))
	}

	// 1. 扫关闭端口
	handle(buildTCP4("9.9.9.9", "5.6.7.8", 1111, 8443, tcpSYN, nil), 0)
	// 2. 未认证的探测：SYN -> ClientHello -> RST
	handle(buildTCP4("8.8.4.4", "5.6.7.8", 2222, 443, tcpSYN, nil), 0)
	handle(buildTCP4("8.8.4.4", "5.6.7.8", 2222, 443, tcpACK|tcpPSH, hello), 30*time.Millisecond)
	handle(buildTCP4("8.8.4.4", "5.6.7.8", 2222, 443, tcpRST, nil), 500*time.Millisecond)
	// 3. 正常用户：SYN -> ClientHello -> xray accepted -> FIN
	handle(buildTCP4("7.7.7.7", "5.6.7.8", 3333, 443, tcpSYN, nil), 0)
	handle(buildTCP4("7.7.7.7", "5.6.7.8", 3333, 443, tcpACK|tcpPSH, hello), 20*time.Millisecond)
	r.onXrayMessage(&xlog.AccessMessage{From: "tcp:7.7.7.7:3333", To: "tcp:google.com:443", Status: xlog.AccessAccepted, Email: "u1"})
	handle(buildTCP4("7.7.7.7", "5.6.7.8", 3333, 443, tcpFIN|tcpACK, nil), time.Second)
	// 4. xray 日志
	r.onXrayMessage(&xlog.GeneralMessage{Severity: xlog.Severity_Info, Content: "REALITY: processed invalid connection"})
	Stop()

	byKind := map[string][]Event{}
	for _, e := range readEvents(t, file) {
		byKind[e.Kind] = append(byKind[e.Kind], e)
	}
	if s := byKind[KindSyn]; len(s) != 1 || s[0].DstPort != 8443 || s[0].PortState != PortClosed || s[0].TCPOpts == "" {
		t.Fatalf("syn events: %+v", s)
	}
	flows := byKind[KindTCPFlow]
	if len(flows) != 2 {
		t.Fatalf("tcp flows: %+v", flows)
	}
	for _, f := range flows {
		if f.TLSSNI != "www.microsoft.com" || f.JA4 == "" || f.NodeType != "vless+reality" || f.PortState != PortNode {
			t.Fatalf("flow fields: %+v", f)
		}
		switch f.SrcIP {
		case "8.8.4.4":
			if f.Auth != AuthNone || f.FlowEnd != "rst" || f.FirstDataMs == nil || *f.FirstDataMs != 30 {
				t.Fatalf("probe flow: %+v", f)
			}
		case "7.7.7.7":
			if f.Auth != AuthAccepted || f.FlowEnd != "fin" {
				t.Fatalf("user flow: %+v", f)
			}
		}
	}
	if a := byKind[KindXrayAccess]; len(a) != 1 || a[0].XrayEmail != "u1" || a[0].SrcPort != 3333 {
		t.Fatalf("access: %+v", a)
	}
	if l := byKind[KindXrayLog]; len(l) != 1 || l[0].Severity != "info" {
		t.Fatalf("xray log: %+v", l)
	}
}
