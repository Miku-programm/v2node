package probelog

import (
	"net"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/geodata"
)

// geoTagger 用 xray 的 geoip.dat 给来源 IP 打国家标签（只匹配配置里列出的国家）
type geoTagger struct {
	tags     []string
	matchers []geodata.IPMatcher
	mu       sync.Mutex
	cache    map[string]string
}

func newGeoTagger(tags []string) *geoTagger {
	g := &geoTagger{cache: make(map[string]string)}
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		rules, err := geodata.ParseIPRules([]string{"geoip:" + t})
		if err == nil {
			var m geodata.IPMatcher
			if m, err = geodata.IPReg.BuildIPMatcher(rules); err == nil {
				g.tags = append(g.tags, t)
				g.matchers = append(g.matchers, m)
				continue
			}
		}
		log.WithField("err", err).Warnf("ProbeLog: load geoip:%s failed", t)
	}
	return g
}

func (g *geoTagger) tag(ip string) string {
	if len(g.matchers) == 0 {
		return ""
	}
	g.mu.Lock()
	if v, ok := g.cache[ip]; ok {
		g.mu.Unlock()
		return v
	}
	g.mu.Unlock()
	res := "other"
	if parsed := net.ParseIP(ip); parsed != nil {
		for i, m := range g.matchers {
			if m.Match(parsed) {
				res = g.tags[i]
				break
			}
		}
	}
	g.mu.Lock()
	if len(g.cache) > 100000 {
		clear(g.cache)
	}
	g.cache[ip] = res
	g.mu.Unlock()
	return res
}
