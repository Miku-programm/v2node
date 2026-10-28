// Package probelog 记录节点收到的扫描、探测与连接行为，并批量上传到 ClickHouse。
//
// 数据来源有三类：
//   - AF_PACKET 抓包（仅 Linux）：SYN 扫描、到节点端口的每条流的 IP/TCP 指纹、首包特征和 TLS ClientHello
//   - xray 日志：access 接受/拒绝记录（用于给流打上 accepted/rejected 标签）以及 REALITY/fallback 等日志
//   - 节点端口注册：区分节点端口、其他监听端口和关闭端口
package probelog

import (
	"encoding/json"
	"math/rand/v2"
	"os"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wyx2685/v2node/conf"
)

type Recorder struct {
	cfg     conf.ProbeLogConfig
	node    string
	sink    *sink
	geo     *geoTagger
	limit   *rateLimiter
	flows   *flowTable
	capture capturer
	stats   recorderStats
	done    chan struct{}
	wg      sync.WaitGroup
}

type recorderStats struct {
	emitted     atomic.Uint64
	rateDropped atomic.Uint64
	sampledOut  atomic.Uint64
	packets     atomic.Uint64
	parseErrors atomic.Uint64
}

var (
	curMu sync.Mutex
	cur   atomic.Pointer[Recorder]
)

// Start 根据配置启动记录器；重复调用会先停止旧实例
func Start(c *conf.ProbeLogConfig) error {
	curMu.Lock()
	defer curMu.Unlock()
	stopLocked()
	if c == nil || !c.Enable {
		return nil
	}
	r := &Recorder{
		cfg:  *c,
		node: c.NodeName,
		done: make(chan struct{}),
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
	r.flows = newFlowTable(r)
	if c.Capture {
		r.capture, err = newCapturer(r, c.Interface, c.ExtraPorts)
		if err != nil {
			log.WithField("err", err).Warn("ProbeLog: packet capture unavailable, only xray events will be recorded")
			r.capture = nil
		}
	}
	r.wg.Add(1)
	go r.statsLoop()
	cur.Store(r)
	log.WithField("node", r.node).Info("ProbeLog started")
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

// emit 补齐公共字段、限速后交给 sink
func (r *Recorder) emit(e *Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if e.Kind != KindStats && !r.limit.allow(e.SrcIP, e.Time) {
		r.stats.rateDropped.Add(1)
		return
	}
	e.TS = e.Time.UTC().Format("2006-01-02T15:04:05.000Z")
	e.Node = r.node
	if e.SrcIP != "" && e.SrcGeo == "" {
		e.SrcGeo = r.geo.tag(e.SrcIP)
	}
	r.stats.emitted.Add(1)
	r.sink.push(e)
}

// sampleAuthed 对已认证的正常流按比例采样，减少数据量
func (r *Recorder) sampleAuthed() bool {
	rate := r.cfg.AuthedSampleRate
	if rate >= 1 {
		return true
	}
	if rand.Float64() < rate {
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
			m := map[string]any{
				"emitted":      r.stats.emitted.Load(),
				"rate_dropped": r.stats.rateDropped.Load(),
				"sampled_out":  r.stats.sampledOut.Load(),
				"packets":      r.stats.packets.Load(),
				"parse_errors": r.stats.parseErrors.Load(),
				"flows":        r.flows.Len(),
				"capture":      r.capture != nil,
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
