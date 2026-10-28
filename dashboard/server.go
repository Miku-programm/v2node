// Package dashboard 提供探测日志分析面板：内嵌静态前端，并把命名查询转发给 ClickHouse。
// ClickHouse 账号只保存在服务端，浏览器拿不到。
package dashboard

import (
	"context"
	"crypto/subtle"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

//go:embed static
var staticFiles embed.FS

type Config struct {
	Listen       string
	CHURL        string
	CHDatabase   string
	CHTable      string
	CHUser       string
	CHPassword   string
	AuthUser     string
	AuthPassword string
	AllowRawSQL  bool
}

type Server struct {
	cfg    Config
	table  string
	client *http.Client
}

var identRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

func New(cfg Config) (*Server, error) {
	if cfg.CHURL == "" {
		return nil, fmt.Errorf("clickhouse url is required")
	}
	if !identRe.MatchString(cfg.CHDatabase) || !identRe.MatchString(cfg.CHTable) {
		return nil, fmt.Errorf("invalid database or table name")
	}
	return &Server{
		cfg:    cfg,
		table:  fmt.Sprintf("`%s`.`%s`", cfg.CHDatabase, cfg.CHTable),
		client: &http.Client{Timeout: 60 * time.Second},
	}, nil
}

func (s *Server) Run() error {
	sub, _ := fs.Sub(staticFiles, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(sub))
	mux.HandleFunc("GET /api/q/{name}", s.handleNamed)
	mux.HandleFunc("POST /api/sql", s.handleRaw)
	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"raw_sql":%t}`, s.cfg.AllowRawSQL)
	})
	if s.cfg.AuthUser == "" {
		log.Warn("Dashboard: no basic auth configured, anyone who can reach the listen address can query the data")
	}
	log.Infof("Dashboard listening on http://%s", s.cfg.Listen)
	srv := &http.Server{Addr: s.cfg.Listen, Handler: s.auth(mux), ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}

func (s *Server) auth(next http.Handler) http.Handler {
	if s.cfg.AuthUser == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(s.cfg.AuthUser)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(s.cfg.AuthPassword)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="v2node probe dashboard"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bucketFor 根据时间范围选择时间线粒度（秒）
func bucketFor(hours int) int {
	switch {
	case hours <= 3:
		return 60
	case hours <= 24:
		return 300
	case hours <= 72:
		return 900
	case hours <= 168:
		return 3600
	}
	return 4 * 3600
}

func (s *Server) handleNamed(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	q, ok := queries[name]
	if !ok {
		http.Error(w, "unknown query", http.StatusNotFound)
		return
	}
	qs := r.URL.Query()
	hours, _ := strconv.Atoi(qs.Get("hours"))
	hours = min(max(hours, 1), 24*90)
	limit, _ := strconv.Atoi(qs.Get("limit"))
	if limit <= 0 {
		limit = 200
	}
	limit = min(limit, 5000)
	params := url.Values{}
	params.Set("param_hours", strconv.Itoa(hours))
	params.Set("param_node", qs.Get("node"))
	params.Set("param_limit", strconv.Itoa(limit))
	params.Set("param_bucket", strconv.Itoa(bucketFor(hours)))
	params.Set("param_ip", qs.Get("ip"))
	where := "ts >= now64(3) - toIntervalHour({hours:UInt32}) AND ({node:String} = '' OR node = {node:String})"
	q = strings.ReplaceAll(q, "{T}", s.table)
	q = strings.ReplaceAll(q, "{W}", where)
	s.query(r.Context(), w, q+"\nFORMAT JSON", params)
}

func (s *Server) handleRaw(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.AllowRawSQL {
		http.Error(w, "raw sql disabled", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	q := strings.TrimRight(strings.TrimSpace(string(body)), ";")
	params := url.Values{}
	params.Set("readonly", "2")
	params.Set("max_result_rows", "10000")
	params.Set("result_overflow_mode", "break")
	s.query(r.Context(), w, q+"\nFORMAT JSON", params)
}

func (s *Server) query(ctx context.Context, w http.ResponseWriter, q string, params url.Values) {
	params.Set("database", s.cfg.CHDatabase)
	params.Set("max_execution_time", "30")
	params.Set("output_format_json_quote_64bit_integers", "0")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(s.cfg.CHURL, "/")+"/?"+params.Encode(), strings.NewReader(q))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if s.cfg.CHUser != "" {
		req.Header.Set("X-ClickHouse-User", s.cfg.CHUser)
		req.Header.Set("X-ClickHouse-Key", s.cfg.CHPassword)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		http.Error(w, strings.TrimSpace(string(msg)), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	io.Copy(w, resp.Body)
}
