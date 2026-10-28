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
// 重叠内容冲突时保留先到达的字节并打 conflict 标记——这不一定是服务端协议栈实际采用的字节。
type reassembler struct {
	base         uint32 // 流中第 0 个字节的序列号（ISN+1）
	limit        int
	data         []byte
	pending      []pendingSeg
	pendingBytes int
	flags        map[string]bool
}

func newReassembler(isn uint32, limit int) *reassembler {
	return &reassembler{base: isn + 1, limit: limit, flags: map[string]bool{}}
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
	if off <= len(r.data) {
		r.merge(off, payload)
		r.drain()
		return
	}
	if len(r.pending) >= maxPendingSegs || r.pendingBytes+len(payload) > maxPendingBytes {
		r.flags[reasmOverflow] = true
		return
	}
	r.pending = append(r.pending, pendingSeg{off: off, data: bytes.Clone(payload)})
	r.pendingBytes += len(payload)
}

// merge 把起点不超过当前前缀末尾的段接到前缀上，重叠部分逐字节比较
func (r *reassembler) merge(off int, payload []byte) {
	overlap := min(len(r.data)-off, len(payload))
	if overlap > 0 {
		if !bytes.Equal(r.data[off:off+overlap], payload[:overlap]) {
			r.flags[reasmConflict] = true
		} else {
			r.flags[reasmRetrans] = true
		}
	}
	if overlap < len(payload) {
		r.data = append(r.data, payload[overlap:]...)
	}
}

func (r *reassembler) drain() {
	for {
		progressed := false
		sort.Slice(r.pending, func(i, j int) bool { return r.pending[i].off < r.pending[j].off })
		kept := r.pending[:0]
		for _, s := range r.pending {
			if s.off <= len(r.data) {
				r.merge(s.off, s.data)
				r.pendingBytes -= len(s.data)
				progressed = true
			} else {
				kept = append(kept, s)
			}
		}
		r.pending = kept
		if !progressed {
			return
		}
	}
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
