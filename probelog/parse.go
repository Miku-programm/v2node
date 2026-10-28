package probelog

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"net/netip"
	"strconv"
	"strings"
)

const (
	ipProtoICMP   = 1
	ipProtoTCP    = 6
	ipProtoUDP    = 17
	ipProtoICMPv6 = 58

	ethPIPv4 = 0x0800
	ethPIPv6 = 0x86dd

	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
)

var errShortPacket = errors.New("short packet")

// packet 是解析后的入站数据包（只保留记录需要的字段）
type packet struct {
	v6    bool
	src   netip.Addr
	dst   netip.Addr
	proto uint8
	ttl   uint8
	ipID  uint16
	df    bool

	sport uint16
	dport uint16

	flags   uint8
	seq     uint32
	ack     uint32
	win     uint16
	opts    string
	mss     uint16
	tsVal   uint32
	tsEcr   uint32
	payload []byte // 实际捕获到的负载

	payloadWire int  // 按 IP 长度字段（或捕获元数据）推算的原始负载长度
	truncated   bool // 负载因捕获长度限制丢了尾部
	outgoing    bool // 本机发出的包（PACKET_OUTGOING）

	icmpType uint8
	icmpCode uint8
}

// parsePacket 解析从网络层开始的数据（AF_PACKET SOCK_DGRAM）。
// data 是实际捕获的字节，origLen 是内核报告的原始长度（MSG_TRUNC，未知时为 0）。
func parsePacket(data []byte, ethProto uint16, origLen int) (*packet, error) {
	p := &packet{}
	var l4 []byte
	wireLen := 0 // 原始 IP 包长度
	switch ethProto {
	case ethPIPv4:
		if len(data) < 20 || data[0]>>4 != 4 {
			return nil, errShortPacket
		}
		ihl := int(data[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(data[2:4]))
		if ihl < 20 || len(data) < ihl {
			return nil, errShortPacket
		}
		if total >= ihl && total < len(data) {
			data = data[:total]
		}
		if total >= ihl {
			wireLen = total
		}
		p.ipID = binary.BigEndian.Uint16(data[4:6])
		fragField := binary.BigEndian.Uint16(data[6:8])
		p.df = fragField&0x4000 != 0
		if fragField&0x1fff != 0 {
			return nil, errors.New("fragment")
		}
		p.ttl = data[8]
		p.proto = data[9]
		p.src = netip.AddrFrom4([4]byte(data[12:16]))
		p.dst = netip.AddrFrom4([4]byte(data[16:20]))
		l4 = data[ihl:]
	case ethPIPv6:
		if len(data) < 40 || data[0]>>4 != 6 {
			return nil, errShortPacket
		}
		p.v6 = true
		plen := int(binary.BigEndian.Uint16(data[4:6]))
		if 40+plen < len(data) {
			data = data[:40+plen]
		}
		if plen > 0 {
			wireLen = 40 + plen
		}
		p.ttl = data[7]
		p.src = netip.AddrFrom16([16]byte(data[8:24]))
		p.dst = netip.AddrFrom16([16]byte(data[24:40]))
		next := data[6]
		l4 = data[40:]
		// 跳过常见扩展头
		for next == 0 || next == 43 || next == 60 {
			if len(l4) < 8 {
				return nil, errShortPacket
			}
			hl := (int(l4[1]) + 1) * 8
			if len(l4) < hl {
				return nil, errShortPacket
			}
			next = l4[0]
			l4 = l4[hl:]
		}
		p.proto = next
	default:
		return nil, errors.New("not ip")
	}

	switch p.proto {
	case ipProtoTCP:
		if len(l4) < 20 {
			return nil, errShortPacket
		}
		p.sport = binary.BigEndian.Uint16(l4[0:2])
		p.dport = binary.BigEndian.Uint16(l4[2:4])
		p.seq = binary.BigEndian.Uint32(l4[4:8])
		p.ack = binary.BigEndian.Uint32(l4[8:12])
		off := int(l4[12]>>4) * 4
		if off < 20 || len(l4) < off {
			return nil, errShortPacket
		}
		p.flags = l4[13]
		p.win = binary.BigEndian.Uint16(l4[14:16])
		p.parseTCPOptions(l4[20:off])
		p.payload = l4[off:]
		p.setWire(len(data)-len(p.payload), wireLen, origLen)
	case ipProtoUDP:
		if len(l4) < 8 {
			return nil, errShortPacket
		}
		p.sport = binary.BigEndian.Uint16(l4[0:2])
		p.dport = binary.BigEndian.Uint16(l4[2:4])
		p.payload = l4[8:]
		p.setWire(len(data)-len(p.payload), wireLen, origLen)
	case ipProtoICMP, ipProtoICMPv6:
		if len(l4) < 2 {
			return nil, errShortPacket
		}
		p.icmpType = l4[0]
		p.icmpCode = l4[1]
	default:
		return nil, errors.New("unsupported l4")
	}
	return p, nil
}

// setWire 计算原始负载长度与截断状态。hdr 为负载之前的头部字节数。
// IP 长度字段为 0（如超大 GRO 包）时退回使用捕获元数据给出的原始长度。
func (p *packet) setWire(hdr, wireLen, origLen int) {
	if wireLen == 0 {
		wireLen = origLen
	}
	p.payloadWire = len(p.payload)
	if wireLen > hdr {
		p.payloadWire = wireLen - hdr
	}
	p.truncated = p.payloadWire > len(p.payload)
}

// parseTCPOptions 生成 p0f 风格的选项序列，如 M1460,S,T,N,W7
func (p *packet) parseTCPOptions(b []byte) {
	var parts []string
	for len(b) > 0 {
		kind := b[0]
		if kind == 0 {
			parts = append(parts, "E")
			break
		}
		if kind == 1 {
			parts = append(parts, "N")
			b = b[1:]
			continue
		}
		if len(b) < 2 || int(b[1]) < 2 || len(b) < int(b[1]) {
			parts = append(parts, "?")
			break
		}
		l := int(b[1])
		switch kind {
		case 2:
			if l == 4 {
				p.mss = binary.BigEndian.Uint16(b[2:4])
			}
			parts = append(parts, "M"+strconv.Itoa(int(p.mss)))
		case 3:
			if l == 3 {
				parts = append(parts, "W"+strconv.Itoa(int(b[2])))
			} else {
				parts = append(parts, "W?")
			}
		case 4:
			parts = append(parts, "S")
		case 5:
			parts = append(parts, "K")
		case 8:
			if l == 10 {
				p.tsVal = binary.BigEndian.Uint32(b[2:6])
				p.tsEcr = binary.BigEndian.Uint32(b[6:10])
			}
			parts = append(parts, "T")
		default:
			parts = append(parts, "?"+strconv.Itoa(int(kind)))
		}
		b = b[l:]
	}
	p.opts = strings.Join(parts, ",")
}

func tcpFlagString(f uint8) string {
	const names = "FSRPAUEC"
	var sb strings.Builder
	for i := 0; i < 8; i++ {
		if f&(1<<i) != 0 {
			sb.WriteByte(names[i])
		}
	}
	return sb.String()
}

// fillIPFingerprint 把 IP/TCP 层指纹写入事件
func fillIPFingerprint(e *Event, p *packet) {
	e.TTL = p.ttl
	e.IPID = p.ipID
	if p.df {
		e.IPDF = 1
	}
	if p.proto == ipProtoTCP {
		e.TCPFlags = tcpFlagString(p.flags)
		e.TCPWin = p.win
		e.TCPOpts = p.opts
		e.MSS = p.mss
		e.TSVal = p.tsVal
		e.TSEcr = p.tsEcr
	}
}

// fillFirstSegment 写入首个捕获数据段的特征：原始长度、实际捕获长度、截断标记、头部、哈希、熵和可打印比例。
// 这些只描述“第一个到达的数据段”，不是完整的应用层消息；熵和哈希只对实际捕获的字节计算。
func fillFirstSegment(e *Event, p *packet, headBytes int) {
	e.PayloadLen = uint32(p.payloadWire)
	e.PayloadCapLen = uint32(len(p.payload))
	if p.truncated {
		e.PayloadTruncated = 1
	}
	fillPayloadFeatures(e, p.payload, headBytes)
}

// prefixHash 对重组后的连续前缀计算哈希（sha256 前 8 字节，hex）。比较时必须连同 prefix_len 一起比较。
func prefixHash(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// fillPayloadFeatures 写入头部、哈希、熵和可打印字符比例（基于传入的字节）
func fillPayloadFeatures(e *Event, b []byte, headBytes int) {
	if len(b) == 0 {
		return
	}
	if headBytes > 0 {
		e.PayloadHead = hex.EncodeToString(b[:min(len(b), headBytes)])
	}
	sum := sha256.Sum256(b)
	e.PayloadHash = hex.EncodeToString(sum[:8])
	var counts [256]int
	printable := 0
	for _, c := range b {
		counts[c]++
		if c >= 0x20 && c <= 0x7e {
			printable++
		}
	}
	var ent float64
	n := float64(len(b))
	for _, c := range counts {
		if c > 0 {
			q := float64(c) / n
			ent -= q * math.Log2(q)
		}
	}
	e.Entropy = float32(ent)
	e.Printable = float32(printable) / float32(len(b))
}

// quicVersion 识别 QUIC 长包头并返回版本号
func quicVersion(b []byte) string {
	if len(b) < 5 || b[0]&0x80 == 0 {
		return ""
	}
	v := binary.BigEndian.Uint32(b[1:5])
	return "0x" + strconv.FormatUint(uint64(v), 16)
}
