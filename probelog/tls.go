package probelog

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

type clientHello struct {
	legacyVer uint16
	sidLen    int
	ciphers   []uint16
	exts      []uint16
	groups    []uint16
	pointFmts []uint8
	sigAlgs   []uint16
	supVers   []uint16
	sni       string
	alpn      []string
	length    int
}

var errNotClientHello = errors.New("not a tls client hello")

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// ClientHello 解析状态（tls_state 列）
const (
	tlsNeedMore   = "need_more"        // 数据还不够判断，继续等
	tlsNotCH      = "not_client_hello" // 已能确定不是 TLS ClientHello
	tlsMalformed  = "malformed"        // 像 TLS ClientHello 但结构不合法
	tlsComplete   = "complete"         // 完整解析，指纹可用
	tlsIncomplete = "incomplete"       // 结束时仍是 need_more（缺口、截断、超时或连接结束）
	tlsConflict   = "conflict"         // 语法可解析，但 ClientHello 范围内有内容不一致的重叠段，不输出指纹
)

const (
	maxTLSRecordLen     = 16384 + 2048
	maxClientHelloBytes = 1 << 17
)

// classifyClientHello 判断字节流前缀是否是 TLS ClientHello，跨多个 handshake record 时先拼接再解析。
// 只有返回 tlsComplete 时 ClientHello 可用。
func classifyClientHello(b []byte) (string, *clientHello) {
	state, ch, _ := classifyClientHelloN(b)
	return state, ch
}

// classifyClientHelloN 同 classifyClientHello，另外返回 ClientHello 在字节流中占用的长度
// （到最后一个包含 ClientHello 字节的 record 末尾），用于判断重组质量问题是否落在 ClientHello 范围内。
func classifyClientHelloN(b []byte) (string, *clientHello, int) {
	if len(b) == 0 {
		return tlsNeedMore, nil, 0
	}
	if b[0] != 0x16 || (len(b) >= 2 && b[1] != 3) {
		return tlsNotCH, nil, 0
	}
	var hs []byte
	hsLen := -1
	used := 0
	for {
		if len(b) < 5 {
			return tlsNeedMore, nil, 0
		}
		if b[0] != 0x16 || b[1] != 3 {
			// ClientHello 还没收齐就出现了别的记录
			return tlsMalformed, nil, 0
		}
		l := int(binary.BigEndian.Uint16(b[3:5]))
		if l == 0 || l > maxTLSRecordLen {
			return tlsMalformed, nil, 0
		}
		if len(b) < 5+l {
			return tlsNeedMore, nil, 0
		}
		hs = append(hs, b[5:5+l]...)
		b = b[5+l:]
		used += 5 + l
		if hsLen < 0 && len(hs) >= 4 {
			if hs[0] != 1 {
				return tlsNotCH, nil, 0
			}
			hsLen = int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if hsLen > maxClientHelloBytes {
				return tlsMalformed, nil, 0
			}
		}
		if hsLen >= 0 && len(hs) >= hsLen+4 {
			break
		}
	}
	ch, err := parseHandshake(hs[:hsLen+4])
	if err != nil {
		return tlsMalformed, nil, used
	}
	return tlsComplete, ch, used
}

// parseClientHello 解析完整的 ClientHello（测试与工具使用）
func parseClientHello(b []byte) (*clientHello, error) {
	state, ch := classifyClientHello(b)
	if state != tlsComplete {
		return nil, fmt.Errorf("%w: %s", errNotClientHello, state)
	}
	return ch, nil
}

var errMalformedHello = errors.New("malformed client hello")

// u16List 把 uint16 向量拆成元素；长度必须是偶数，且至少 min 个元素
func u16List(v []byte, min int) ([]uint16, error) {
	if len(v)%2 != 0 || len(v)/2 < min {
		return nil, errMalformedHello
	}
	out := make([]uint16, 0, len(v)/2)
	for i := 0; i < len(v); i += 2 {
		out = append(out, binary.BigEndian.Uint16(v[i:]))
	}
	return out, nil
}

// parseHandshake 解析一条完整的 ClientHello handshake 消息（含 4 字节头）。
//
// 消息已完整收到，所以任何一层向量的声明长度与实际内容不符（越界、剩余尾部、元素大小不对）都是结构畸形，
// 不是“还要等数据”。未知扩展按声明长度整体跳过。
func parseHandshake(hs []byte) (*clientHello, error) {
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	ch := &clientHello{length: hsLen + 4}
	r := reader{b: hs[4 : 4+hsLen]}
	ch.legacyVer = r.u16()
	r.skip(32)
	sid := r.vec8()
	ch.sidLen = len(sid)
	cs := r.vec16()
	comp := r.vec8()
	if r.err != nil || len(sid) > 32 || len(comp) == 0 {
		return nil, errMalformedHello
	}
	var err error
	if ch.ciphers, err = u16List(cs, 1); err != nil {
		return nil, err
	}
	if r.left() == 0 {
		return ch, nil
	}
	exts := reader{b: r.vec16()}
	if r.err != nil || r.left() != 0 {
		return nil, errMalformedHello
	}
	for exts.left() > 0 {
		typ := exts.u16()
		data := reader{b: exts.vec16()}
		if exts.err != nil {
			return nil, errMalformedHello
		}
		ch.exts = append(ch.exts, typ)
		if err := ch.parseExtension(typ, &data); err != nil {
			return nil, err
		}
	}
	return ch, nil
}

// parseExtension 解析已识别的扩展；要求扩展内容被完整、恰好消费
func (ch *clientHello) parseExtension(typ uint16, data *reader) error {
	var err error
	switch typ {
	case 0x0000: // server_name
		list := reader{b: data.vec16()}
		if len(list.b) == 0 {
			return errMalformedHello
		}
		for list.left() > 0 {
			nt := list.u8()
			name := list.vec16()
			if list.err != nil {
				return errMalformedHello
			}
			if nt == 0 && ch.sni == "" {
				ch.sni = string(name)
			}
		}
	case 0x0010: // ALPN
		list := reader{b: data.vec16()}
		if len(list.b) == 0 {
			return errMalformedHello
		}
		for list.left() > 0 {
			name := list.vec8()
			if list.err != nil || len(name) == 0 {
				return errMalformedHello
			}
			ch.alpn = append(ch.alpn, string(name))
		}
	case 0x000a: // supported_groups
		ch.groups, err = u16List(data.vec16(), 1)
	case 0x000b: // ec_point_formats
		ch.pointFmts = append(ch.pointFmts, data.vec8()...)
		if len(ch.pointFmts) == 0 {
			err = errMalformedHello
		}
	case 0x000d: // signature_algorithms
		ch.sigAlgs, err = u16List(data.vec16(), 1)
	case 0x002b: // supported_versions
		ch.supVers, err = u16List(data.vec8(), 1)
	default:
		data.skip(data.left())
	}
	if err != nil || data.err != nil || data.left() != 0 {
		return errMalformedHello
	}
	return nil
}

func (ch *clientHello) version() uint16 {
	best := uint16(0)
	for _, v := range ch.supVers {
		if !isGREASE(v) && v > best {
			best = v
		}
	}
	if best == 0 {
		best = ch.legacyVer
	}
	return best
}

func tlsVersionName(v uint16) string {
	switch v {
	case 0x0304:
		return "1.3"
	case 0x0303:
		return "1.2"
	case 0x0302:
		return "1.1"
	case 0x0301:
		return "1.0"
	case 0x0300:
		return "ssl3"
	}
	return "0x" + strconv.FormatUint(uint64(v), 16)
}

func joinDec[T uint8 | uint16](vals []T, skipGrease bool) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		if skipGrease && isGREASE(uint16(v)) {
			continue
		}
		parts = append(parts, strconv.Itoa(int(v)))
	}
	return strings.Join(parts, "-")
}

func (ch *clientHello) ja3() string {
	s := strings.Join([]string{
		strconv.Itoa(int(ch.legacyVer)),
		joinDec(ch.ciphers, true),
		joinDec(ch.exts, true),
		joinDec(ch.groups, true),
		joinDec(ch.pointFmts, false),
	}, ",")
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hash12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func hexList(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// ja4 计算 TCP 上 TLS ClientHello 的 JA4 指纹
func (ch *clientHello) ja4() string {
	ver := map[uint16]string{0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}[ch.version()]
	if ver == "" {
		ver = "00"
	}
	sni := "i"
	if ch.sni != "" {
		sni = "d"
	}
	var ciphers, exts, extsNoSNI []uint16
	for _, c := range ch.ciphers {
		if !isGREASE(c) {
			ciphers = append(ciphers, c)
		}
	}
	for _, e := range ch.exts {
		if isGREASE(e) {
			continue
		}
		exts = append(exts, e)
		if e != 0x0000 && e != 0x0010 {
			extsNoSNI = append(extsNoSNI, e)
		}
	}
	alpn := "00"
	if len(ch.alpn) > 0 && ch.alpn[0] != "" {
		a := ch.alpn[0]
		if isAlnum(a[0]) && isAlnum(a[len(a)-1]) {
			alpn = string([]byte{a[0], a[len(a)-1]})
		} else {
			h := hex.EncodeToString([]byte(a))
			alpn = string([]byte{h[0], h[len(h)-1]})
		}
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", ver, sni, min(len(ciphers), 99), min(len(exts), 99), alpn)
	slices.Sort(ciphers)
	slices.Sort(extsNoSNI)
	c := hexList(extsNoSNI)
	if len(ch.sigAlgs) > 0 {
		c += "_" + hexList(ch.sigAlgs)
	}
	return a + "_" + hash12(hexList(ciphers)) + "_" + hash12(c)
}

// fillTLS 把 ClientHello 信息写入事件
func fillTLS(e *Event, ch *clientHello) {
	e.TLSVer = tlsVersionName(ch.version())
	e.TLSSNI = truncate(ch.sni, 255)
	e.TLSALPN = truncate(strings.Join(ch.alpn, ","), 128)
	e.JA3 = ch.ja3()
	e.JA4 = ch.ja4()
	e.TLSSIDLn = uint8(ch.sidLen)
	e.TLSCHLen = uint32(ch.length)
}

// tlsRecordSummary 从字节流前缀读出前 max 个 TLS record 的“类型:长度”序列，只读记录头，不解密。
// 遇到不是 TLS 记录的数据时返回 "non_tls"。
func tlsRecordSummary(b []byte, max int) string {
	var parts []string
	for len(parts) < max && len(b) >= 5 {
		typ := b[0]
		if typ < 20 || typ > 24 || b[1] != 3 {
			if len(parts) == 0 {
				return "non_tls"
			}
			break
		}
		l := int(binary.BigEndian.Uint16(b[3:5]))
		parts = append(parts, strconv.Itoa(int(typ))+":"+strconv.Itoa(l))
		if len(b) < 5+l {
			break
		}
		b = b[5+l:]
	}
	return strings.Join(parts, ",")
}

// reader 是一个出错后只返回空值的简单字节读取器
type reader struct {
	b   []byte
	err error
}

func (r *reader) left() int { return len(r.b) }

func (r *reader) take(n int) []byte {
	if r.err != nil || n > len(r.b) {
		r.err = errShortPacket
		r.b = nil
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) skip(n int) { r.take(n) }

func (r *reader) u8() uint8 {
	if v := r.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (r *reader) u16() uint16 {
	if v := r.take(2); v != nil {
		return binary.BigEndian.Uint16(v)
	}
	return 0
}

func (r *reader) vec8() []byte  { return r.take(int(r.u8())) }
func (r *reader) vec16() []byte { return r.take(int(r.u16())) }
