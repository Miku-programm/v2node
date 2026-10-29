package probelog

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// QUIC 客户端 Initial 解析。
//
// Initial 包的密钥由公开的版本盐和客户端选的 Destination Connection ID 推导（RFC 9001 §5.2、RFC 9369 §3.3.1），
// 任何在路径上的观察者都能解密——GFW 正是这样按 SNI 封锁 QUIC 的（Zohaib et al., USENIX Security 2025）。
// 这里用同样的方法解出客户端 Initial 里的 CRYPTO 帧，重组 ClientHello，并记录 SNI 是否完整落在第一个 UDP 数据报里
// （论文观察到 GFW 不跨数据报重组，只看第一个数据报）。

const (
	quicVersion1 = 0x00000001
	quicVersion2 = 0x6b3343cf

	quicMaxDatagrams = 8         // 每个流最多解析几个客户端数据报
	quicCryptoLimit  = 64 * 1024 // CRYPTO 流重组上限
	quicMaxCIDLen    = 20        // v1/v2 的连接 ID 长度上限
)

var (
	quicSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicSaltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

// quic_initial：客户端 Initial 的解析结果
const (
	QUICInitialOK          = "ok"                  // 至少一个客户端 Initial 解密成功
	QUICInitialUnsupported = "unsupported_version" // 长包头，但不是 v1 / v2（无法推导密钥）
	QUICInitialDecrypt     = "decrypt_failed"      // 结构像 Initial，但 AEAD 校验失败
	QUICInitialTruncated   = "truncated"           // 数据报被捕获长度截断，无法解密
	QUICInitialMalformed   = "malformed"           // 长包头或帧结构不合法
	QUICInitialNone        = "no_initial"          // 有长包头，但没有客户端 Initial（如只有 0-RTT / Handshake）
)

// quic_sni_first：SNI 的字节有多少落在第一个数据报的 CRYPTO 帧里
const (
	QUICSNIFirstFull    = "full"    // 全部在第一个数据报里（论文中 GFW 能看到的情形）
	QUICSNIFirstPartial = "partial" // 一部分在第一个数据报里（SNI 被切开）
	QUICSNIFirstNone    = "none"    // 第一个数据报里完全没有 SNI 字节
	QUICSNIFirstNoSNI   = "no_sni"  // ClientHello 没有 SNI 扩展
)

var (
	errQUICNotInitial  = errors.New("quic: not an initial packet")
	errQUICUnsupported = errors.New("quic: unsupported version")
	errQUICTruncated   = errors.New("quic: truncated")
	errQUICMalformed   = errors.New("quic: malformed")
	errQUICDecrypt     = errors.New("quic: decryption failed")
)

type quicKeys struct {
	aead cipher.AEAD
	iv   []byte
	hp   cipher.Block
}

// hkdfExpandLabel 是 TLS 1.3 的 HKDF-Expand-Label（context 为空）
func hkdfExpandLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = append(info, byte(n>>8), byte(n), byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), n)
	if err != nil {
		panic(err) // 长度固定且很小，不会失败
	}
	return out
}

// quicClientInitialSecrets 推导客户端 Initial 的 key / iv / hp
func quicClientInitialSecrets(version uint32, dcid []byte) (key, iv, hp []byte, err error) {
	salt, prefix := quicSaltV1, "quic "
	switch version {
	case quicVersion1:
	case quicVersion2:
		salt, prefix = quicSaltV2, "quicv2 "
	default:
		return nil, nil, nil, errQUICUnsupported
	}
	initial, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return nil, nil, nil, err
	}
	client := hkdfExpandLabel(initial, "client in", 32)
	return hkdfExpandLabel(client, prefix+"key", 16), hkdfExpandLabel(client, prefix+"iv", 12), hkdfExpandLabel(client, prefix+"hp", 16), nil
}

func newQUICKeys(version uint32, dcid []byte) (*quicKeys, error) {
	key, iv, hp, err := quicClientInitialSecrets(version, dcid)
	if err != nil {
		return nil, err
	}
	kb, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(kb)
	if err != nil {
		return nil, err
	}
	hb, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	return &quicKeys{aead: aead, iv: iv, hp: hb}, nil
}

// quicVarint 读一个 QUIC 变长整数，n=0 表示数据不够
func quicVarint(b []byte) (v uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	n = 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v = uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
}

func isQUICInitialType(version uint32, first byte) bool {
	typ := (first >> 4) & 3
	if version == quicVersion2 {
		return typ == 1
	}
	return typ == 0
}

// quicLongPacket 是数据报里的一个长包头包
type quicLongPacket struct {
	version  uint32
	initial  bool
	dcid     []byte
	pnOffset int // 包号在 raw 中的偏移
	raw      []byte
}

// splitQUICLong 从数据报开头切出一个长包头包，返回它和数据报剩余部分（合并的后续包）。
// 短包头或版本协商包没有长度字段，rest 为空。
func splitQUICLong(b []byte) (pkt *quicLongPacket, rest []byte, err error) {
	if len(b) < 7 || b[0]&0x80 == 0 {
		return nil, nil, errQUICNotInitial
	}
	version := binary.BigEndian.Uint32(b[1:5])
	if version == 0 {
		return nil, nil, errQUICNotInitial // 版本协商（只由服务端发出）
	}
	if version != quicVersion1 && version != quicVersion2 {
		return nil, nil, errQUICUnsupported
	}
	pos := 5
	dl := int(b[pos])
	pos++
	if dl > quicMaxCIDLen {
		return nil, nil, errQUICMalformed
	}
	if len(b) < pos+dl+1 {
		return nil, nil, errQUICTruncated
	}
	dcid := b[pos : pos+dl]
	pos += dl
	sl := int(b[pos])
	pos++
	if sl > quicMaxCIDLen {
		return nil, nil, errQUICMalformed
	}
	pos += sl
	initial := isQUICInitialType(version, b[0])
	typ := (b[0] >> 4) & 3
	retry := (version == quicVersion1 && typ == 3) || (version == quicVersion2 && typ == 0)
	if retry {
		return nil, nil, errQUICNotInitial // Retry 只由服务端发出，也没有长度字段
	}
	if pos > len(b) {
		return nil, nil, errQUICTruncated
	}
	if initial {
		tl, n := quicVarint(b[pos:])
		if n == 0 {
			return nil, nil, errQUICTruncated
		}
		pos += n
		if uint64(len(b)-pos) < tl {
			return nil, nil, errQUICTruncated
		}
		pos += int(tl)
	}
	length, n := quicVarint(b[pos:])
	if n == 0 {
		return nil, nil, errQUICTruncated
	}
	pos += n
	if uint64(len(b)-pos) < length {
		return nil, nil, errQUICTruncated
	}
	end := pos + int(length)
	return &quicLongPacket{version: version, initial: initial, dcid: dcid, pnOffset: pos, raw: b[:end]}, b[end:], nil
}

// open 去掉头部保护并解密，返回明文帧
func (p *quicLongPacket) open(k *quicKeys) ([]byte, error) {
	if len(p.raw) < p.pnOffset+4+16 {
		return nil, errQUICMalformed
	}
	sample := p.raw[p.pnOffset+4 : p.pnOffset+20]
	var mask [16]byte
	k.hp.Encrypt(mask[:], sample)
	hdr := make([]byte, p.pnOffset+4)
	copy(hdr, p.raw[:p.pnOffset+4])
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&0x03) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[p.pnOffset+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[p.pnOffset+i])
	}
	hdr = hdr[:p.pnOffset+pnLen]
	nonce := make([]byte, len(k.iv))
	copy(nonce, k.iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	plain, err := k.aead.Open(nil, nonce, p.raw[p.pnOffset+pnLen:], hdr)
	if err != nil {
		return nil, errQUICDecrypt
	}
	return plain, nil
}

// quicCryptoFrames 遍历客户端 Initial 明文中的帧，回调每个 CRYPTO 帧。
// 客户端 Initial 只允许 PADDING / PING / ACK / CRYPTO / CONNECTION_CLOSE（RFC 9000 §12.4）。
func quicCryptoFrames(p []byte, fn func(off uint64, data []byte)) error {
	for len(p) > 0 {
		typ, n := quicVarint(p)
		if n == 0 {
			return errQUICMalformed
		}
		p = p[n:]
		switch typ {
		case 0x00, 0x01: // PADDING、PING
		case 0x02, 0x03: // ACK
			var vals [4]uint64
			for i := range vals {
				if vals[i], n = quicVarint(p); n == 0 {
					return errQUICMalformed
				}
				p = p[n:]
			}
			ranges := vals[2] * 2 // range count 之后每段 gap + length
			if typ == 0x03 {
				ranges += 3 // ECN 计数
			}
			if ranges > uint64(len(p)) {
				return errQUICMalformed
			}
			for i := uint64(0); i < ranges; i++ {
				if _, n = quicVarint(p); n == 0 {
					return errQUICMalformed
				}
				p = p[n:]
			}
		case 0x06: // CRYPTO
			off, n1 := quicVarint(p)
			if n1 == 0 {
				return errQUICMalformed
			}
			l, n2 := quicVarint(p[n1:])
			if n2 == 0 || uint64(len(p)-n1-n2) < l {
				return errQUICMalformed
			}
			fn(off, p[n1+n2:n1+n2+int(l)])
			p = p[n1+n2+int(l):]
		case 0x1c: // CONNECTION_CLOSE
			for i := 0; i < 2; i++ {
				if _, n = quicVarint(p); n == 0 {
					return errQUICMalformed
				}
				p = p[n:]
			}
			rl, n := quicVarint(p)
			if n == 0 || uint64(len(p)-n) < rl {
				return errQUICMalformed
			}
			p = p[n+int(rl):]
		default:
			return errQUICMalformed
		}
	}
	return nil
}

// quicState 是一个 UDP 流里客户端 Initial 的解析状态
type quicState struct {
	keys      map[string]*quicKeys // 按 DCID 缓存（Retry 之后客户端会换 DCID）
	crypto    *reassembler         // CRYPTO 流（偏移 0 起）
	first     [][2]int             // 第一个数据报里 CRYPTO 帧覆盖的流区间
	datagrams int                  // 已处理的数据报数
	initials  int                  // 含有成功解密 Initial 的数据报数
	decrypted bool
	lastErr   error
}

func newQUICState() *quicState {
	// reassembler 以 isn+1 为第 0 字节；CRYPTO 偏移从 0 开始，所以 isn = 0xffffffff
	return &quicState{keys: map[string]*quicKeys{}, crypto: newReassembler(^uint32(0), quicCryptoLimit)}
}

// addDatagram 解析一个客户端数据报中的所有 Initial 包（含合并包）
func (s *quicState) addDatagram(b []byte, truncated bool) {
	first := s.datagrams == 0
	s.datagrams++
	got := false
	for len(b) > 0 {
		pkt, rest, err := splitQUICLong(b)
		if err != nil {
			if errors.Is(err, errQUICTruncated) && !truncated {
				err = errQUICMalformed
			}
			if !errors.Is(err, errQUICNotInitial) || !s.decrypted {
				s.lastErr = err
			}
			break
		}
		b = rest
		if !pkt.initial {
			continue
		}
		k := s.keys[string(pkt.dcid)]
		if k == nil {
			if k, err = newQUICKeys(pkt.version, pkt.dcid); err != nil {
				s.lastErr = err
				continue
			}
			s.keys[string(pkt.dcid)] = k
		}
		plain, err := pkt.open(k)
		if err != nil {
			s.lastErr = err
			continue
		}
		// 整个包的帧都合法后才放入 CRYPTO 流
		type frame struct {
			off  uint64
			data []byte
		}
		var frames []frame
		err = quicCryptoFrames(plain, func(off uint64, data []byte) { frames = append(frames, frame{off, data}) })
		if err != nil {
			s.lastErr = err
			continue
		}
		for _, f := range frames {
			if f.off > quicCryptoLimit {
				s.crypto.flags[reasmOverflow] = true
				continue
			}
			s.crypto.add(uint32(f.off), f.data, false)
			if first {
				s.first = append(s.first, [2]int{int(f.off), int(f.off) + len(f.data)})
			}
		}
		s.decrypted, got = true, true
	}
	if got {
		s.initials++
	}
	if truncated {
		s.crypto.flags[reasmTruncated] = true
	}
}

func (s *quicState) status() string {
	if s.decrypted {
		return QUICInitialOK
	}
	switch {
	case errors.Is(s.lastErr, errQUICUnsupported):
		return QUICInitialUnsupported
	case errors.Is(s.lastErr, errQUICDecrypt):
		return QUICInitialDecrypt
	case errors.Is(s.lastErr, errQUICTruncated):
		return QUICInitialTruncated
	case errors.Is(s.lastErr, errQUICMalformed):
		return QUICInitialMalformed
	}
	return QUICInitialNone
}

// sniCoverage 计算 [off, off+n) 有多少字节落在第一个数据报的 CRYPTO 区间里
func (s *quicState) sniCoverage(off, n int) string {
	covered := make([]bool, n)
	for _, r := range s.first {
		for i := max(r[0], off); i < min(r[1], off+n); i++ {
			covered[i-off] = true
		}
	}
	c := 0
	for _, v := range covered {
		if v {
			c++
		}
	}
	switch {
	case c == n:
		return QUICSNIFirstFull
	case c > 0:
		return QUICSNIFirstPartial
	}
	return QUICSNIFirstNone
}
