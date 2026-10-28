package probelog

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
)

// NodePort 描述一个节点端口
type NodePort struct {
	Tag      string
	Type     string
	Security string
	UDP      bool
	Port     uint16
}

// 节点端口注册表，与记录器生命周期无关，core 增删节点时维护
var nodePorts = struct {
	sync.RWMutex
	tcp     map[uint16]NodePort
	udp     map[uint16]NodePort
	version uint64
}{tcp: map[uint16]NodePort{}, udp: map[uint16]NodePort{}}

// RegisterNode 登记节点监听端口，供抓包时区分节点端口与其他端口
func RegisterNode(p NodePort) {
	nodePorts.Lock()
	if p.UDP {
		nodePorts.udp[p.Port] = p
	} else {
		nodePorts.tcp[p.Port] = p
	}
	nodePorts.version++
	nodePorts.Unlock()
}

// UnregisterNode 删除某个 tag 的所有端口
func UnregisterNode(tag string) {
	nodePorts.Lock()
	for k, v := range nodePorts.tcp {
		if v.Tag == tag {
			delete(nodePorts.tcp, k)
		}
	}
	for k, v := range nodePorts.udp {
		if v.Tag == tag {
			delete(nodePorts.udp, k)
		}
	}
	nodePorts.version++
	nodePorts.Unlock()
}

func lookupNodePort(udp bool, port uint16) (NodePort, bool) {
	nodePorts.RLock()
	defer nodePorts.RUnlock()
	if udp {
		p, ok := nodePorts.udp[port]
		return p, ok
	}
	p, ok := nodePorts.tcp[port]
	return p, ok
}

func nodePortSnapshot() (tcp, udp []uint16, version uint64) {
	nodePorts.RLock()
	defer nodePorts.RUnlock()
	for p := range nodePorts.tcp {
		tcp = append(tcp, p)
	}
	for p := range nodePorts.udp {
		udp = append(udp, p)
	}
	return tcp, udp, nodePorts.version
}

// readListenPorts 从 /proc/net 读取本机监听中的端口：TCP 取 LISTEN 状态，UDP 取未连接的绑定端口
func readListenPorts() (tcp, udp map[uint16]bool) {
	tcp = map[uint16]bool{}
	udp = map[uint16]bool{}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		parseProcNet(f, "0A", tcp)
	}
	for _, f := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		parseProcNet(f, "07", udp)
	}
	return tcp, udp
}

func parseProcNet(path, state string, out map[uint16]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // 表头
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[3] != state {
			continue
		}
		// local_address 形如 0100007F:0016
		local := fields[1]
		i := strings.LastIndexByte(local, ':')
		if i < 0 {
			continue
		}
		// UDP 只关心监听在通配地址上的端口，避免把出站临时端口当成服务端口
		if state == "07" && strings.Trim(local[:i], "0") != "" {
			continue
		}
		if port, err := strconv.ParseUint(local[i+1:], 16, 16); err == nil {
			out[uint16(port)] = true
		}
	}
}
