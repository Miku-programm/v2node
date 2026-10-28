package dashboard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestNamedQueryForwarding(t *testing.T) {
	var gotQuery string
	var gotParams map[string][]string
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotQuery = string(b)
		gotParams = r.URL.Query()
		if r.Header.Get("X-ClickHouse-User") != "reader" {
			t.Errorf("missing auth header")
		}
		io.WriteString(w, `{"meta":[],"data":[{"x":1}],"rows":1}`)
	}))
	defer ch.Close()

	s, err := New(Config{CHURL: ch.URL, CHDatabase: "v2node", CHTable: "probe_events", CHUser: "reader", AuthUser: "a", AuthPassword: "b"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/q/{name}", s.handleNamed)
	h := s.auth(mux)

	req := httptest.NewRequest("GET", "/api/q/probes?hours=6&node=hk1&limit=50", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", rec.Code)
	}

	req.SetBasicAuth("a", "b")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"x":1`) {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(gotQuery, "FROM `v2node`.`probe_events`") || !strings.HasSuffix(gotQuery, "FORMAT JSON") || strings.Contains(gotQuery, "{T}") || strings.Contains(gotQuery, "{W}") {
		t.Fatalf("query: %s", gotQuery)
	}
	if gotParams["param_hours"][0] != "6" || gotParams["param_node"][0] != "hk1" || gotParams["param_limit"][0] != "50" {
		t.Fatalf("params: %v", gotParams)
	}
}

// 每个命名查询里的参数都必须由 handleNamed 提供
func TestQueryParamsProvided(t *testing.T) {
	re := regexp.MustCompile(`\{([a-z_]+):[A-Za-z0-9]+\}`)
	provided := map[string]bool{"hours": true, "node": true, "limit": true, "bucket": true, "ip": true}
	for name, q := range queries {
		for _, m := range re.FindAllStringSubmatch(q, -1) {
			if !provided[m[1]] {
				t.Errorf("query %s uses unknown param %s", name, m[1])
			}
		}
	}
}

func TestStaticEmbedded(t *testing.T) {
	for _, f := range []string{"static/index.html", "static/app.js", "static/style.css"} {
		if _, err := staticFiles.ReadFile(f); err != nil {
			t.Fatal(err)
		}
	}
}
