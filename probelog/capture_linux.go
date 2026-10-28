//go:build linux

package probelog

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const portWatchInterval = 5 * time.Second

type capturer interface {
	Close()
	Stats() map[string]any
}

// afPacketCapture 用 AF_PACKET(SOCK_DGRAM) 抓包，过滤器随监听端口变化重建。需要 CAP_NET_RAW。
type afPacketCapture struct {
	r        *Recorder
	fd       int
	mode     string
	loopback map[int]bool
	extra    []uint16
	curTCP   []uint16
	curUDP   []uint16
	done     chan struct{}
	wg       sync.WaitGroup

	kernelPackets atomic.Uint64
	kernelDrops   atomic.Uint64
	statsErr      atomic.Bool
}

func htons(v uint16) uint16 {
	return binary.BigEndian.Uint16(binary.NativeEndian.AppendUint16(nil, v))
}

func newCapturer(r *Recorder, iface string, extra []int, mode string) (capturer, error) {
	c := &afPacketCapture{r: r, mode: mode, loopback: map[int]bool{}, done: make(chan struct{})}
	for _, p := range extra {
		if p > 0 && p < 65536 {
			c.extra = append(c.extra, uint16(p))
		}
	}
	ifindex := 0
	if iface != "" {
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			return nil, fmt.Errorf("interface %s: %w", iface, err)
		}
		ifindex = ifi.Index
	}
	if ifs, err := net.Interfaces(); err == nil {
		for _, ifi := range ifs {
			if ifi.Flags&net.FlagLoopback != 0 {
				c.loopback[ifi.Index] = true
			}
		}
	}
	// 协议号先传 0：在挂上过滤器之前不接收任何包，避免启动瞬间被未过滤的流量淹没
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open AF_PACKET socket: %w", err)
	}
	c.fd = fd
	tcp, udp := c.watchedPorts()
	if err := c.attach(tcp, udp); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 8<<20); err != nil {
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 8<<20)
	}
	tv := unix.NsecToTimeval(int64(500 * time.Millisecond))
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifindex}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind AF_PACKET socket: %w", err)
	}
	c.wg.Add(2)
	go c.readLoop()
	go c.watchLoop()
	log.WithField("tcp_ports", c.curTCP).WithField("udp_ports", c.curUDP).Info("ProbeLog: packet capture started")
	return c, nil
}

func (c *afPacketCapture) Close() {
	close(c.done)
	c.wg.Wait()
	unix.Close(c.fd)
}

// watchedPorts 计算需要看数据包的端口：节点端口 + 本机 TCP 监听端口 + 额外端口
func (c *afPacketCapture) watchedPorts() (tcp, udp []uint16) {
	nodeTCP, nodeUDP, _ := nodePortSnapshot()
	set := map[uint16]bool{}
	for _, p := range nodeTCP {
		set[p] = true
	}
	if m := c.r.flows.listenTCP.Load(); m != nil {
		for p := range *m {
			set[p] = true
		}
	}
	for _, p := range c.extra {
		set[p] = true
	}
	for p := range set {
		tcp = append(tcp, p)
	}
	set = map[uint16]bool{}
	for _, p := range nodeUDP {
		set[p] = true
	}
	for _, p := range c.extra {
		set[p] = true
	}
	for p := range set {
		if p >= udpScanPortLimit {
			udp = append(udp, p)
		}
	}
	// 节点端口优先，超出 BPF 端口上限时保留它们
	isNode := func(p uint16, udp bool) bool { _, ok := lookupNodePort(udp, p); return ok }
	sortPorts := func(ps []uint16, udp bool) {
		slices.SortFunc(ps, func(a, b uint16) int {
			na, nb := isNode(a, udp), isNode(b, udp)
			if na != nb {
				if na {
					return -1
				}
				return 1
			}
			return int(a) - int(b)
		})
	}
	sortPorts(tcp, false)
	sortPorts(udp, true)
	return tcp, udp
}

func (c *afPacketCapture) attach(tcp, udp []uint16) error {
	raw, err := buildFilter(tcp, udp, c.mode)
	if err != nil {
		return err
	}
	prog := unix.SockFprog{
		Len:    uint16(len(raw)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&raw[0])),
	}
	if err := unix.SetsockoptSockFprog(c.fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		return fmt.Errorf("attach bpf: %w", err)
	}
	c.curTCP, c.curUDP = tcp, udp
	return nil
}

func (c *afPacketCapture) watchLoop() {
	defer c.wg.Done()
	t := time.NewTicker(portWatchInterval)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			tcp, udp := c.watchedPorts()
			if slices.Equal(tcp, c.curTCP) && slices.Equal(udp, c.curUDP) {
				continue
			}
			if err := c.attach(tcp, udp); err != nil {
				log.WithField("err", err).Warn("ProbeLog: update capture filter failed")
				continue
			}
			log.WithField("tcp_ports", tcp).WithField("udp_ports", udp).Debug("ProbeLog: capture filter updated")
		}
	}
}

func (c *afPacketCapture) readLoop() {
	defer c.wg.Done()
	buf := make([]byte, 4096)
	for {
		select {
		case <-c.done:
			return
		default:
		}
		// MSG_TRUNC：返回值是原始包长度（可能大于捕获到的字节数）
		n, from, err := unix.Recvfrom(c.fd, buf, unix.MSG_TRUNC)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			log.WithField("err", err).Warn("ProbeLog: capture read failed")
			time.Sleep(time.Second)
			continue
		}
		sll, ok := from.(*unix.SockaddrLinklayer)
		if !ok || c.loopback[sll.Ifindex] {
			continue
		}
		outgoing := sll.Pkttype == packetOutgoing
		if !outgoing && sll.Pkttype != unix.PACKET_HOST {
			continue
		}
		c.r.stats.packets.Add(1)
		captured := min(n, len(buf))
		p, err := parsePacket(buf[:captured], htons(sll.Protocol), n)
		if err != nil {
			c.r.stats.parseErrors.Add(1)
			continue
		}
		p.outgoing = outgoing
		if p.src.IsLoopback() || p.dst.IsLoopback() {
			continue
		}
		c.r.flows.handle(p, time.Now())
	}
}

// Stats 读取内核 PACKET_STATISTICS（每次读取后内核清零，这里累加）。
// 拿不到时明确报告不可用，而不是报 0。
func (c *afPacketCapture) Stats() map[string]any {
	st, err := unix.GetsockoptTpacketStats(c.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil {
		c.statsErr.Store(true)
		return map[string]any{"kernel_drops": "unavailable", "kernel_stats_error": err.Error()}
	}
	c.kernelPackets.Add(uint64(st.Packets))
	c.kernelDrops.Add(uint64(st.Drops))
	return map[string]any{
		"kernel_packets": c.kernelPackets.Load(),
		"kernel_drops":   c.kernelDrops.Load(),
	}
}
