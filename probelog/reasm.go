package probelog

import (
	"bytes"
	"sort"
	"strings"
)

// 重组质量标记
const (
	reasmGap       = "gap"       // 前缀之后还有未补齐的缺口（结束时仍未填上）
	reasmConflict  = "conflict"  // 重叠段内容与已收到的字节不一致（保留先到的字节）
	reasmOverflow  = "overflow"  // 乱序队列或前缀达到上限
	reasmTruncated = "truncated" // 有数据段因捕获长度限制丢失了尾部
	reasmRetrans   = "retrans"   // 收到与已有内容一致的重复数据
)

const (
	maxPendingSegs  = 64
	maxPendingBytes = 64 * 1024
)

type pendingSeg struct {
	off  int
	data []byte
}

// reassembler 对一个方向的 TCP 字节流做有界的前缀重组。
//
// 只维护从初始序列号之后开始的连续前缀（最多 limit 字节）。乱序段暂存，补齐后接上；
// 截断的段只放入实际捕获到的字节，缺失部分留作缺口，后续数据不会被拼到缺口位置。
//
// 重叠策略是“先到达的字节优先”：每个字节位置一旦被某个段（无论是否已接入连续前缀）占用，
// 之后到达的段在该位置的字节只用来比较，不覆盖。内容不同打 conflict 标记并记下最早的冲突位置。
// 这是采集器的确定规则，不一定是服务端协议栈实际采用的字节（各操作系统的重叠处理不同）。
type reassembler struct {
	base         uint32 // 流中第 0 个字节的序列号（ISN+1）
	limit        int
	data         []byte
	pending      []pendingSeg // 按 off 排序，彼此不重叠，也不与 data 重叠
	pendingBytes int
	flags        map[string]bool
	conflictAt   int // 最早的冲突字节偏移，-1 表示没有冲突
}

func newReassembler(isn uint32, limit int) *reassembler {
	return &reassembler{base: isn + 1, limit: limit, flags: map[string]bool{}, conflictAt: -1}
}

// add 放入一个数据段。truncated 表示该段捕获不完整（payload 只是前一部分）。
func (r *reassembler) add(seq uint32, payload []byte, truncated bool) {
	if truncated {
		r.flags[reasmTruncated] = true
	}
	if len(payload) == 0 {
		return
	}
	// 用 int32 差值处理序列号回绕
	off := int(int32(seq - r.base))
	if off < 0 {
		if -off >= len(payload) {
			r.flags[reasmRetrans] = true
			return
		}
		payload = payload[-off:]
		off = 0
	}
	if off >= r.limit {
		r.flags[reasmOverflow] = true
		return
	}
	if end := off + len(payload); end > r.limit {
		payload = payload[:r.limit-off]
		r.flags[reasmOverflow] = true
	}
	// 与已占用区间（连续前缀 + 暂存段）比较，只保留尚未被占用的部分
	end := off + len(payload)
	cur := off
	var fresh []pendingSeg
	occupied := append([]pendingSeg{{off: 0, data: r.data}}, r.pending...)
	for _, o := range occupied {
		oEnd := o.off + len(o.data)
		if oEnd <= cur || o.off >= end {
			continue
		}
		if o.off > cur {
			fresh = append(fresh, pendingSeg{off: cur, data: payload[cur-off : o.off-off]})
		}
		lo, hi := max(cur, o.off), min(end, oEnd)
		r.compare(lo, o.data[lo-o.off:hi-o.off], payload[lo-off:hi-off])
		cur = hi
		if cur >= end {
			break
		}
	}
	if cur < end {
		fresh = append(fresh, pendingSeg{off: cur, data: payload[cur-off:]})
	}
	for _, s := range fresh {
		if s.off == len(r.data) {
			r.data = append(r.data, s.data...)
			r.drain()
			continue
		}
		if len(r.pending) >= maxPendingSegs || r.pendingBytes+len(s.data) > maxPendingBytes {
			r.flags[reasmOverflow] = true
			continue
		}
		r.pending = append(r.pending, pendingSeg{off: s.off, data: bytes.Clone(s.data)})
		r.pendingBytes += len(s.data)
		sort.Slice(r.pending, func(i, j int) bool { return r.pending[i].off < r.pending[j].off })
	}
}

// compare 比较同一位置上已有字节与新到字节，at 为该区间的流偏移
func (r *reassembler) compare(at int, have, got []byte) {
	if bytes.Equal(have, got) {
		r.flags[reasmRetrans] = true
		return
	}
	r.flags[reasmConflict] = true
	for i := range have {
		if have[i] != got[i] {
			if r.conflictAt < 0 || at+i < r.conflictAt {
				r.conflictAt = at + i
			}
			break
		}
	}
}

// drain 把已经与连续前缀相接的暂存段接上
func (r *reassembler) drain() {
	for len(r.pending) > 0 && r.pending[0].off == len(r.data) {
		r.data = append(r.data, r.pending[0].data...)
		r.pendingBytes -= len(r.pending[0].data)
		r.pending = r.pending[1:]
	}
}

// conflictBefore 表示前 n 个字节内有冲突
func (r *reassembler) conflictBefore(n int) bool {
	return r.conflictAt >= 0 && r.conflictAt < n
}

// prefix 返回目前连续的字节前缀
func (r *reassembler) prefix() []byte { return r.data }

// hasGap 表示前缀后面已经有数据到达但中间缺字节
func (r *reassembler) hasGap() bool { return len(r.pending) > 0 }

// flagString 输出稳定排序的质量标记；gap 只在调用时仍有未补齐段时给出
func (r *reassembler) flagString() string {
	var out []string
	for _, f := range []string{reasmGap, reasmConflict, reasmOverflow, reasmTruncated, reasmRetrans} {
		if f == reasmGap {
			if r.hasGap() {
				out = append(out, f)
			}
			continue
		}
		if r.flags[f] {
			out = append(out, f)
		}
	}
	return strings.Join(out, ",")
}

// clean 表示前缀可以当作“观察到的完整字节流前缀”使用
func (r *reassembler) clean() bool {
	return !r.flags[reasmConflict] && !r.flags[reasmTruncated] && !r.hasGap()
}
