package probelog

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wyx2685/v2node/conf"
)

type batch struct {
	data  []byte
	count int
}

// sink 把事件攒成 JSONEachRow 批次，写本地文件并上传 ClickHouse；上传失败时保留在内存里重试
type sink struct {
	cfg      conf.ClickHouseConfig
	in       chan *Event
	file     *os.File
	client   *http.Client
	endpoint string

	mu           sync.Mutex
	pending      []batch
	pendingCount int
	wake         chan struct{}

	done      chan struct{}
	batcherWG sync.WaitGroup
	senderWG  sync.WaitGroup

	chanDropped   atomic.Uint64
	bufferDropped atomic.Uint64
	sent          atomic.Uint64
	sendErrors    atomic.Uint64
	lastError     atomic.Value
	schemaStatus  atomic.Value
}

func newSink(c *conf.ClickHouseConfig, localFile string) (*sink, error) {
	s := &sink{
		cfg:    *c,
		in:     make(chan *Event, 20000),
		wake:   make(chan struct{}, 1),
		done:   make(chan struct{}),
		client: &http.Client{Timeout: time.Duration(max(c.Timeout, 1)) * time.Second},
	}
	if s.cfg.BatchSize <= 0 {
		s.cfg.BatchSize = 2000
	}
	if s.cfg.FlushInterval <= 0 {
		s.cfg.FlushInterval = 5
	}
	if localFile != "" {
		f, err := os.OpenFile(localFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return nil, fmt.Errorf("open probe log file: %w", err)
		}
		s.file = f
	}
	if c.URL != "" {
		q := fmt.Sprintf("INSERT INTO `%s`.`%s` FORMAT JSONEachRow", c.Database, c.Table)
		v := url.Values{}
		v.Set("query", q)
		v.Set("date_time_input_format", "best_effort")
		// 显式关闭跳过未知字段（新版 ClickHouse 默认开启）：表结构落后于事件模型时让写入明确失败，而不是静默丢掉新字段
		v.Set("input_format_skip_unknown_fields", "0")
		s.endpoint = strings.TrimRight(c.URL, "/") + "/?" + v.Encode()
		s.senderWG.Add(1)
		go s.sendLoop()
		go s.checkSchema()
	}
	s.batcherWG.Add(1)
	go s.batchLoop()
	return s, nil
}

func (s *sink) push(e *Event) {
	select {
	case s.in <- e:
	default:
		s.chanDropped.Add(1)
	}
}

func (s *sink) Stats() map[string]any {
	s.mu.Lock()
	pending := s.pendingCount
	s.mu.Unlock()
	m := map[string]any{
		"sink_chan_dropped":   s.chanDropped.Load(),
		"sink_buffer_dropped": s.bufferDropped.Load(),
		"sink_sent":           s.sent.Load(),
		"sink_send_errors":    s.sendErrors.Load(),
		"sink_pending":        pending,
	}
	if e, ok := s.lastError.Load().(string); ok && e != "" {
		m["sink_last_error"] = e
	}
	if e, ok := s.schemaStatus.Load().(string); ok && e != "" {
		m["sink_schema"] = e
	}
	return m
}

// eventColumns 返回事件模型中的所有列名
func eventColumns() []string {
	var cols []string
	t := reflect.TypeOf(Event{})
	for i := 0; i < t.NumField(); i++ {
		tag := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if tag != "" && tag != "-" {
			cols = append(cols, tag)
		}
	}
	return cols
}

// checkSchema 启动时检查目标表是否包含事件模型的全部列。写入账号无权读 system.columns 时只记录无法检查。
func (s *sink) checkSchema() {
	q := "SELECT name FROM system.columns WHERE database = {db:String} AND table = {t:String} FORMAT TabSeparated"
	v := url.Values{}
	v.Set("param_db", s.cfg.Database)
	v.Set("param_t", s.cfg.Table)
	ctx, cancel := context.WithTimeout(context.Background(), s.client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(s.cfg.URL, "/")+"/?"+v.Encode(), strings.NewReader(q))
	if err != nil {
		return
	}
	if s.cfg.Username != "" {
		req.Header.Set("X-ClickHouse-User", s.cfg.Username)
		req.Header.Set("X-ClickHouse-Key", s.cfg.Password)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		s.schemaStatus.Store("unchecked: " + err.Error())
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		s.schemaStatus.Store("unchecked: http " + strconv.Itoa(resp.StatusCode))
		return
	}
	have := map[string]bool{}
	for _, l := range strings.Split(string(body), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			have[l] = true
		}
	}
	if len(have) == 0 {
		s.schemaStatus.Store("table not found or not visible")
		log.Error("ProbeLog: ClickHouse table not found or not visible to this user; run probelog/schema.sql")
		return
	}
	var missing []string
	for _, c := range eventColumns() {
		if !have[c] {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		s.schemaStatus.Store("missing columns: " + strings.Join(missing, ","))
		log.WithField("missing", missing).Error("ProbeLog: ClickHouse table is older than the event model, inserts will fail; apply probelog/migrations")
		return
	}
	s.schemaStatus.Store("ok")
}

func (s *sink) Close() {
	close(s.done)
	s.batcherWG.Wait()
	if s.endpoint != "" {
		s.senderWG.Wait()
		// 退出前最后尝试一次
		s.flushPending(context.Background())
	}
	if s.file != nil {
		s.file.Close()
	}
}

func (s *sink) batchLoop() {
	defer s.batcherWG.Done()
	t := time.NewTicker(time.Duration(s.cfg.FlushInterval) * time.Second)
	defer t.Stop()
	var buf bytes.Buffer
	count := 0
	enc := json.NewEncoder(&buf)
	flush := func() {
		if count == 0 {
			return
		}
		data := bytes.Clone(buf.Bytes())
		buf.Reset()
		n := count
		count = 0
		if s.file != nil {
			if _, err := s.file.Write(data); err != nil {
				log.WithField("err", err).Warn("ProbeLog: write local file failed")
			}
		}
		if s.endpoint != "" {
			s.enqueue(batch{data: data, count: n})
		}
	}
	for {
		select {
		case e := <-s.in:
			if err := enc.Encode(e); err == nil {
				count++
			}
			if count >= s.cfg.BatchSize {
				flush()
			}
		case <-t.C:
			flush()
		case <-s.done:
			for {
				select {
				case e := <-s.in:
					if enc.Encode(e) == nil {
						count++
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

func (s *sink) enqueue(b batch) {
	s.mu.Lock()
	s.pending = append(s.pending, b)
	s.pendingCount += b.count
	// 超出内存上限时丢弃最旧的批次
	for s.cfg.BufferSize > 0 && s.pendingCount > s.cfg.BufferSize && len(s.pending) > 1 {
		s.pendingCount -= s.pending[0].count
		s.bufferDropped.Add(uint64(s.pending[0].count))
		s.pending = s.pending[1:]
	}
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *sink) sendLoop() {
	defer s.senderWG.Done()
	backoff := time.Second
	for {
		select {
		case <-s.done:
			return
		case <-s.wake:
		case <-time.After(backoff):
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-s.done:
				cancel()
			case <-ctx.Done():
			}
		}()
		ok := s.flushPending(ctx)
		cancel()
		if ok {
			backoff = time.Second
		} else {
			backoff = min(backoff*2, time.Minute)
		}
	}
}

// flushPending 依次发送待发批次，遇到错误停止并返回 false
func (s *sink) flushPending(ctx context.Context) bool {
	for {
		s.mu.Lock()
		if len(s.pending) == 0 {
			s.mu.Unlock()
			return true
		}
		b := s.pending[0]
		s.mu.Unlock()
		if err := s.post(ctx, b.data); err != nil {
			s.sendErrors.Add(1)
			s.lastError.Store(err.Error())
			log.WithField("err", err).Warn("ProbeLog: upload to ClickHouse failed")
			return false
		}
		s.sent.Add(uint64(b.count))
		s.mu.Lock()
		// 发送期间可能因超限丢掉了队首，只在队首仍是本批次时出队
		if len(s.pending) > 0 && &s.pending[0].data[0] == &b.data[0] {
			s.pending = s.pending[1:]
			s.pendingCount -= b.count
		}
		s.mu.Unlock()
	}
}

func (s *sink) post(ctx context.Context, data []byte) error {
	var body bytes.Buffer
	zw := gzip.NewWriter(&body)
	zw.Write(data)
	zw.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Type", "application/x-ndjson")
	if s.cfg.Username != "" {
		req.Header.Set("X-ClickHouse-User", s.cfg.Username)
		req.Header.Set("X-ClickHouse-Key", s.cfg.Password)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("clickhouse http %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}
