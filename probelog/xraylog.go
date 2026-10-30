package probelog

import (
	"net"
	"strconv"
	"strings"
	"time"

	applog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
)

// 与探测相关的 xray 日志关键字（小写匹配）
var xrayLogKeywords = []string{
	"reality",
	"fallback",
	"invalid",
	"reject",
	"failed to read request",
	"firstlen",
	"handshake",
	"unexpected",
	"bad request",
	"auth",
}

// teeHandler 包住 xray 原本的日志 handler，原样转发的同时复制一份给 probelog
type teeHandler struct {
	inner    log.Handler
	severity log.Severity
}

func (h *teeHandler) Handle(msg log.Message) {
	if h.inner != nil {
		h.inner.Handle(msg)
	}
	r := current()
	if r == nil {
		return
	}
	// xray v26.7.28 不在生成日志前按级别过滤，所有日志都会送到 handler，由各 handler 自己过滤。
	// 原 handler 仍按自己的级别输出，屏幕/文件日志不受影响；这里按 XrayLogLevel 决定采集哪些普通日志。
	if m, ok := msg.(*log.GeneralMessage); ok && m.Severity > h.severity {
		return
	}
	r.onXrayMessage(msg)
}

// HookXrayLog 在 xray 实例启动后调用，接管日志 handler。记录器未启用时不做任何改动。
func HookXrayLog(server *core.Instance) {
	r := current()
	if r == nil || server == nil {
		return
	}
	var inner log.Handler
	if f := server.GetFeature((*applog.Instance)(nil)); f != nil {
		if h, ok := f.(log.Handler); ok {
			inner = h
		}
	}
	log.RegisterHandler(&teeHandler{inner: inner, severity: parseSeverity(r.cfg.XrayLogLevel)})
}

func parseSeverity(s string) log.Severity {
	switch strings.ToLower(s) {
	case "debug":
		return log.Severity_Debug
	case "info":
		return log.Severity_Info
	case "warn", "warning":
		return log.Severity_Warning
	case "error":
		return log.Severity_Error
	}
	return log.Severity_Unknown
}

func (r *Recorder) onXrayMessage(msg log.Message) {
	switch m := msg.(type) {
	case *log.AccessMessage:
		r.onAccess(m)
	case *log.GeneralMessage:
		content := serial.ToString(m.Content)
		lower := strings.ToLower(content)
		for _, k := range xrayLogKeywords {
			if strings.Contains(lower, k) {
				r.emit(&Event{
					Kind:     KindXrayLog,
					Severity: strings.ToLower(m.Severity.String()),
					Message:  truncate(content, 1024),
				})
				return
			}
		}
	}
}

func (r *Recorder) onAccess(m *log.AccessMessage) {
	proto, ip, port := parseXrayAddr(m.From)
	status := string(m.Status)
	if ip != "" {
		for _, c := range r.flows.onAccess(proto == "udp", ip, port, status, time.Now()) {
			r.emit(c)
		}
	}
	if m.Status == log.AccessAccepted && !r.sampleAuthed() {
		return
	}
	e := &Event{
		Kind:       KindXrayAccess,
		Proto:      proto,
		SrcIP:      ip,
		SrcPort:    port,
		XrayStatus: status,
		XrayEmail:  m.Email,
		XrayTarget: truncate(serial.ToString(m.To), 256),
		XrayDetour: m.Detour,
	}
	if m.Reason != nil {
		e.XrayReason = truncate(serial.ToString(m.Reason), 512)
	}
	r.emit(e)
}

// parseXrayAddr 解析 xray 的来源地址：net.Addr（1.2.3.4:5）或 Destination 字符串（tcp:1.2.3.4:5）
func parseXrayAddr(v any) (proto, ip string, port uint16) {
	s := serial.ToString(v)
	proto = "tcp"
	if a, ok := v.(net.Addr); ok && strings.HasPrefix(a.Network(), "udp") {
		proto = "udp"
	}
	if i := strings.Index(s, ":"); i > 0 && (s[:i] == "tcp" || s[:i] == "udp") {
		proto = s[:i]
		s = s[i+1:]
	}
	host, p, err := net.SplitHostPort(s)
	if err != nil {
		return proto, "", 0
	}
	n, _ := strconv.ParseUint(p, 10, 16)
	if parsed := net.ParseIP(host); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			parsed = v4
		}
		host = parsed.String()
	}
	return proto, host, uint16(n)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
