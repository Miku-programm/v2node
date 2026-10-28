package probelog

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
		if r.URL.Query().Get("query") == "" {
			// 启动时的表结构检查：返回完整列表
			io.WriteString(w, strings.Join(eventColumns(), "\n"))
			return
		}
		if r.URL.Query().Get("input_format_skip_unknown_fields") != "0" {
			t.Error("sink must not skip unknown fields")
		}
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
	if st := s.Stats()["sink_schema"]; st != "ok" {
		t.Fatalf("schema check = %v", st)
	}
}

// 旧表缺列时，启动检查要报告缺少的列
func TestSinkSchemaCheckMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ts\nnode\nkind\n")
	}))
	defer srv.Close()
	c := conf.New().ProbeLogConfig.ClickHouse
	c.URL = srv.URL
	s, err := newSink(&c, "")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, _ := s.Stats()["sink_schema"].(string); st != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	s.Close()
	st, _ := s.Stats()["sink_schema"].(string)
	if !strings.HasPrefix(st, "missing columns:") || !strings.Contains(st, "flow_id") {
		t.Fatalf("schema status = %q", st)
	}
}

// 迁移脚本必须补齐 v1 表没有的所有列
func TestMigrationCoversNewColumns(t *testing.T) {
	v1 := strings.Fields(`ts node kind proto src_ip src_port dst_ip dst_port src_geo port_state node_tag node_type
		ttl ip_id ip_df tcp_flags tcp_win tcp_opts mss ts_val ts_ecr syn_retrans payload_len payload_head payload_hash
		entropy printable first_data_ms tls_ver tls_sni tls_alpn ja3 ja4 tls_sid_len tls_ch_len quic_ver icmp_type icmp_code
		flow_ms flow_pkts flow_bytes flow_end auth xray_status xray_email xray_target xray_reason xray_detour severity message`)
	old := map[string]bool{}
	for _, c := range v1 {
		old[c] = true
	}
	mig, err := os.ReadFile("migrations/002_v2.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range eventColumns() {
		if !old[c] && !strings.Contains(string(mig), "ADD COLUMN IF NOT EXISTS "+c+" ") {
			t.Errorf("migration missing column %s", c)
		}
	}
}
