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

// clientHelloNeed 返回读完整个 ClientHello 所需的字节数；不是 TLS 握手时返回 -1
func clientHelloNeed(b []byte) int {
	if len(b) < 5 || b[0] != 0x16 || b[1] != 3 {
		return -1
	}
	if len(b) >= 9 && b[5] == 1 {
		hsLen := int(b[6])<<16 | int(b[7])<<8 | int(b[8])
		return 9 + hsLen
	}
	return 5 + int(binary.BigEndian.Uint16(b[3:5]))
}

// parseClientHello 从 TLS 记录开始解析 ClientHello。跨多个记录的 ClientHello 会先把记录体拼起来。
func parseClientHello(b []byte) (*clientHello, error) {
	var hs []byte
	for len(b) >= 5 && b[0] == 0x16 {
		l := int(binary.BigEndian.Uint16(b[3:5]))
		end := min(5+l, len(b))
		hs = append(hs, b[5:end]...)
		b = b[end:]
	}
	if len(hs) < 4 || hs[0] != 1 {
		return nil, errNotClientHello
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	ch := &clientHello{length: hsLen + 4}
	body := hs[4:]
	if len(body) < hsLen {
		return nil, fmt.Errorf("truncated client hello %d/%d", len(body), hsLen)
	}
	body = body[:hsLen]
	r := reader{b: body}
	ch.legacyVer = r.u16()
	r.skip(32)
	sid := r.vec8()
	ch.sidLen = len(sid)
	cs := r.vec16()
	for i := 0; i+1 < len(cs); i += 2 {
		ch.ciphers = append(ch.ciphers, binary.BigEndian.Uint16(cs[i:]))
	}
	r.vec8() // compression
	if r.err != nil {
		return nil, r.err
	}
	if r.left() == 0 {
		return ch, nil
	}
	exts := reader{b: r.vec16()}
	for exts.left() >= 4 && exts.err == nil {
		typ := exts.u16()
		data := reader{b: exts.vec16()}
		ch.exts = append(ch.exts, typ)
		switch typ {
		case 0x0000: // server_name
			list := reader{b: data.vec16()}
			for list.left() > 3 {
				nt := list.u8()
				name := list.vec16()
				if nt == 0 {
					ch.sni = string(name)
					break
				}
			}
		case 0x0010: // ALPN
			list := reader{b: data.vec16()}
			for list.left() > 0 && list.err == nil {
				ch.alpn = append(ch.alpn, string(list.vec8()))
			}
		case 0x000a: // supported_groups
			g := data.vec16()
			for i := 0; i+1 < len(g); i += 2 {
				ch.groups = append(ch.groups, binary.BigEndian.Uint16(g[i:]))
			}
		case 0x000b: // ec_point_formats
			ch.pointFmts = append(ch.pointFmts, data.vec8()...)
		case 0x000d: // signature_algorithms
			s := data.vec16()
			for i := 0; i+1 < len(s); i += 2 {
				ch.sigAlgs = append(ch.sigAlgs, binary.BigEndian.Uint16(s[i:]))
			}
		case 0x002b: // supported_versions
			v := data.vec8()
			for i := 0; i+1 < len(v); i += 2 {
				ch.supVers = append(ch.supVers, binary.BigEndian.Uint16(v[i:]))
			}
		}
	}
	return ch, nil
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
