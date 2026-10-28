package probelog

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyx2685/v2node/conf"
)

func TestClickHouseSink(t *testing.T) {
	var mu sync.Mutex
	var rows []map[string]any
	var fails atomic.Int32
	fails.Store(1) // 第一次请求返回错误，验证重试
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fails.Add(-1) >= 0 {
			http.Error(w, "Code: 999. temporary", http.StatusServiceUnavailable)
			return
		}
		if r.Header.Get("X-ClickHouse-User") != "writer" || r.Header.Get("X-ClickHouse-Key") != "pw" {
			t.Errorf("auth headers: %v", r.Header)
		}
		if q := r.URL.Query().Get("query"); q != "INSERT INTO `v2node`.`probe_events` FORMAT JSONEachRow" {
			t.Errorf("query = %q", q)
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		sc := bufio.NewScanner(zr)
		mu.Lock()
		for sc.Scan() {
			var m map[string]any
			if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
				t.Error(err)
			}
			rows = append(rows, m)
		}
		mu.Unlock()
	}))
	defer srv.Close()

	c := conf.New().ProbeLogConfig.ClickHouse
	c.URL = srv.URL
	c.Username = "writer"
	c.Password = "pw"
	c.BatchSize = 2
	c.FlushInterval = 1
	s, err := newSink(&c, "")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		s.push(&Event{TS: "2026-10-28T19:39:00.000Z", Kind: KindSyn, SrcIP: "1.2.3.4", DstPort: uint16(i)})
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(rows)
		mu.Unlock()
		if n == 5 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.Close()
	if len(rows) != 5 {
		t.Fatalf("got %d rows, stats %v", len(rows), s.Stats())
	}
	if rows[0]["kind"] != "syn" || rows[0]["ts"] != "2026-10-28T19:39:00.000Z" {
		t.Fatalf("row: %v", rows[0])
	}
	if _, ok := rows[0]["tls_sni"]; ok {
		t.Fatal("empty fields should be omitted")
	}
	if s.sendErrors.Load() != 1 {
		t.Fatalf("send errors = %d", s.sendErrors.Load())
	}
}
