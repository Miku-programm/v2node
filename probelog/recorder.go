// Package probelog 记录节点收到的扫描、探测与连接行为，并批量上传到 ClickHouse。
//
// 数据来源有三类：
//   - AF_PACKET 抓包（仅 Linux）：SYN 扫描；到监听端口的每个连接实例的 IP/TCP 指纹、首段特征、
//     重组后的客户端前缀与 TLS ClientHello；可选的节点→客户端方向控制包与首个响应
//   - xray 日志：access 接受/拒绝记录（有界关联到连接实例）以及 REALITY/fallback 等关键字日志
//   - 节点端口注册：区分节点端口、其他监听端口和关闭端口
//
// 这里输出的是“观察到了什么”，不对来源、意图或 GFW 归因下结论。
package probelog

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	mrand "math/rand/v2"
	"os"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wyx2685/v2node/conf"
)

// 观测模式
const (
	ObsInbound = "inbound" // 只抓入站包
	ObsControl = "control" // 另外抓节点发出的 SYN-ACK / FIN / RST（开销很小）
	ObsFull    = "full"    // 另外抓节点发出的数据包，记录首个响应时间、双向计数和响应 TLS record（开销与下行流量成正比）
)

type Recorder struct {
	cfg     conf.ProbeLogConfig
	node    string
	obsMode string
	sink    *sink
	geo     *geoTagger
	limit   *rateLimiter
	flows   *flowTable
	capture capturer
	stats   recorderStats
	done    chan struct{}
	wg      sync.WaitGroup

	emitHook func(*Event) // 仅测试使用：替代 sink
}

type recorderStats struct {
	emitted            atomic.Uint64
	rateDropped        atomic.Uint64
	sampledOut         atomic.Uint64
	packets            atomic.Uint64
	parseErrors        atomic.Uint64
	flowTableFull      atomic.Uint64
	midstreamFlows     atomic.Uint64
	tlsIncomplete      atomic.Uint64
	tlsMalformed       atomic.Uint64
	reasmConflict      atomic.Uint64
	reasmOverflow      atomic.Uint64
	capTruncated       atomic.Uint64
	assocUnmatched     atomic.Uint64
	assocAmbiguous     atomic.Uint64
	pendingLogsDropped atomic.Uint64
	pendingLogsExpired atomic.Uint64
	lateCorrections    atomic.Uint64
}

var (
	curMu sync.Mutex
	cur   atomic.Pointer[Recorder]
)

func normalizeObsMode(s string) string {
	switch s {
	case ObsInbound, ObsFull:
		return s
	}
	return ObsControl
}

// Start 根据配置启动记录器；重复调用会先停止旧实例
func Start(c *conf.ProbeLogConfig) error {
	curMu.Lock()
	defer curMu.Unlock()
	stopLocked()
	if c == nil || !c.Enable {
		return nil
	}
	r := &Recorder{
		cfg:     *c,
		node:    c.NodeName,
		obsMode: normalizeObsMode(c.Direction),
		done:    make(chan struct{}),
	}
	if r.node == "" {
		r.node, _ = os.Hostname()
	}
	r.limit = newRateLimiter(c.MaxEventsPerSec, c.MaxPerSourceSec)
	r.geo = newGeoTagger(c.GeoTags)
	s, err := newSink(&c.ClickHouse, c.LocalFile)
	if err != nil {
		return err
	}
	r.sink = s
	r.flows = newFlowTable(r, r.obsMode)
	if c.Capture {
		r.capture, err = newCapturer(r, c.Interface, c.ExtraPorts, r.obsMode)
		if err != nil {
			log.WithField("err", err).Warn("ProbeLog: packet capture unavailable, only xray events will be recorded")
			r.capture = nil
		}
	}
	r.wg.Add(1)
	go r.statsLoop()
	cur.Store(r)
	log.WithField("node", r.node).WithField("direction", r.obsMode).Info("ProbeLog started")
	return nil
}

// Stop 停止记录器并尽量把缓冲区里的事件发出去
func Stop() {
	curMu.Lock()
	defer curMu.Unlock()
	stopLocked()
}

func stopLocked() {
	r := cur.Swap(nil)
	if r == nil {
		return
	}
	close(r.done)
	if r.capture != nil {
		r.capture.Close()
	}
	r.flows.Close()
	r.wg.Wait()
	r.sink.Close()
}

func current() *Recorder {
	return cur.Load()
}

func randomID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// emit 补齐公共字段、限速后交给 sink。
// 限速按处理时间计算（事件时间可能早于处理时间，例如连接结束时才输出的汇总）；
// 已经输出过记录的连接的后续记录（revision>1）不受限速，避免只留下快照而丢失终态。
func (r *Recorder) emit(e *Event) {
	now := time.Now()
	if e.Time.IsZero() {
		e.Time = now
	}
	if e.Kind != KindStats && e.Revision <= 1 && !r.limit.allow(e.SrcIP, now) {
		r.stats.rateDropped.Add(1)
		return
	}
	e.SchemaVersion = SchemaVersion
	if e.EventID == "" {
		e.EventID = randomID()
	}
	e.TS = e.Time.UTC().Format("2006-01-02T15:04:05.000Z")
	e.EmittedAt = now.UTC().Format("2006-01-02T15:04:05.000Z")
	e.Node = r.node
	if e.SrcIP != "" && e.SrcGeo == "" {
		e.SrcGeo = r.geo.tag(e.SrcIP)
	}
	r.stats.emitted.Add(1)
	if r.emitHook != nil {
		r.emitHook(e)
		return
	}
	r.sink.push(e)
}

// sampleAuthed 对已认证的 access 记录按比例随机采样
func (r *Recorder) sampleAuthed() bool {
	rate := r.cfg.AuthedSampleRate
	if rate >= 1 || mrand.Float64() < rate {
		return true
	}
	r.stats.sampledOut.Add(1)
	return false
}

// sampleFlow 对已认证连接按 flow_id 稳定采样：同一连接的所有记录取舍一致
func (r *Recorder) sampleFlow(id string) bool {
	rate := r.cfg.AuthedSampleRate
	if rate >= 1 || flowSampleKey(id) < rate {
		return true
	}
	r.stats.sampledOut.Add(1)
	return false
}

func (r *Recorder) statsLoop() {
	defer r.wg.Done()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-t.C:
			s := &r.stats
			m := map[string]any{
				"direction":            r.obsMode,
				"emitted":              s.emitted.Load(),
				"rate_dropped":         s.rateDropped.Load(),
				"sampled_out":          s.sampledOut.Load(),
				"packets":              s.packets.Load(),
				"parse_errors":         s.parseErrors.Load(),
				"flows":                r.flows.Len(),
				"capture":              r.capture != nil,
				"flow_table_full":      s.flowTableFull.Load(),
				"midstream_flows":      s.midstreamFlows.Load(),
				"tls_incomplete":       s.tlsIncomplete.Load(),
				"tls_malformed":        s.tlsMalformed.Load(),
				"reasm_conflict":       s.reasmConflict.Load(),
				"reasm_overflow":       s.reasmOverflow.Load(),
				"cap_truncated":        s.capTruncated.Load(),
				"assoc_unmatched":      s.assocUnmatched.Load(),
				"assoc_ambiguous":      s.assocAmbiguous.Load(),
				"pending_logs_dropped": s.pendingLogsDropped.Load(),
				"pending_logs_expired": s.pendingLogsExpired.Load(),
				"late_corrections":     s.lateCorrections.Load(),
			}
			if r.capture != nil {
				for k, v := range r.capture.Stats() {
					m[k] = v
				}
			} else {
				m["kernel_drops"] = "unavailable"
			}
			for k, v := range r.sink.Stats() {
				m[k] = v
			}
			b, _ := json.Marshal(m)
			r.emit(&Event{Kind: KindStats, Message: string(b)})
		}
	}
}

// rateLimiter 每秒窗口内的全局与单源事件上限，防止大规模扫描把 sink 打满
type rateLimiter struct {
	mu     sync.Mutex
	sec    int64
	total  int
	perSrc map[string]int
	max    int
	maxSrc int
}

func newRateLimiter(max, maxSrc int) *rateLimiter {
	return &rateLimiter{perSrc: make(map[string]int), max: max, maxSrc: maxSrc}
}

func (l *rateLimiter) allow(src string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s := now.Unix(); s != l.sec {
		l.sec = s
		l.total = 0
		clear(l.perSrc)
	}
	if l.max > 0 && l.total >= l.max {
		return false
	}
	if src != "" && l.maxSrc > 0 {
		if l.perSrc[src] >= l.maxSrc {
			return false
		}
		l.perSrc[src]++
	}
	l.total++
	return true
}
