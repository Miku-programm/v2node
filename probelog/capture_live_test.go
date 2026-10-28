//go:build linux

package probelog

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/wyx2685/v2node/conf"
)

// TestCaptureLive 需要 root，并且要从另一台机器向本机发流量：
//
//	PROBELOG_LIVE=30 PROBELOG_PORT=18443 go test -run TestCaptureLive ./probelog/
//
// 运行期间在 PROBELOG_PORT 上开一个只读不回的 TCP 监听并注册为节点端口，结束后打印采集到的事件。
func TestCaptureLive(t *testing.T) {
	secs, _ := strconv.Atoi(os.Getenv("PROBELOG_LIVE"))
	if secs <= 0 {
		t.Skip("set PROBELOG_LIVE=<seconds> to run")
	}
	port, _ := strconv.Atoi(os.Getenv("PROBELOG_PORT"))
	if port == 0 {
		port = 18443
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 4096)
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				if n, _ := c.Read(buf); n > 0 {
					// 回一段 TLS record 形状的响应，供 full 模式记录 resp_records
					c.Write([]byte{22, 3, 3, 0, 4, 2, 0, 0, 0, 20, 3, 3, 0, 1, 1, 23, 3, 3, 0, 3, 9, 9, 9})
				}
				c.Close()
			}()
		}
	}()

	file := filepath.Join(t.TempDir(), "events.jsonl")
	c := conf.New().ProbeLogConfig
	c.Enable = true
	c.GeoTags = nil
	c.NodeName = "live"
	c.LocalFile = file
	if d := os.Getenv("PROBELOG_DIRECTION"); d != "" {
		c.Direction = d
	}
	RegisterNode(NodePort{Tag: "live", Type: "vless", Security: "reality", Port: uint16(port)})
	defer UnregisterNode("live")
	if err := Start(&c); err != nil {
		t.Fatal(err)
	}
	if current().capture == nil {
		Stop()
		t.Fatal("capture not running (need root / CAP_NET_RAW)")
	}
	fmt.Printf("READY port=%d\n", port)
	time.Sleep(time.Duration(secs) * time.Second)
	Stop()
	data, _ := os.ReadFile(file)
	fmt.Print(string(data))
}
