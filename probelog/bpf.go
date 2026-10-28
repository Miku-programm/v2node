package probelog

import (
	"fmt"

	"golang.org/x/net/bpf"
)

const (
	snapHeader  = 160 // SYN/FIN/RST：IPv6 + 最长 TCP 头
	snapICMP    = 96
	snapPayload = 2048 // 带数据的包：要拼 ClientHello、看 QUIC Initial
	maxBPFPorts = 250
	// 入站 UDP 目的端口低于此值的视为可能的扫描/服务端口；Linux 默认临时端口从 32768 开始，
	// 出站连接的回包落在临时端口上，不需要抓
	udpScanPortLimit = 32768
)

// bpfAsm 是带标签的小汇编器：跳转写成"条件成立则跳到标签"，最终解析为相对偏移
type bpfAsm struct {
	ins    []bpf.Instruction
	labels map[string]int
	fixups []fixup
}

type fixup struct {
	idx   int
	label string
}

func newBPFAsm() *bpfAsm { return &bpfAsm{labels: map[string]int{}} }

func (a *bpfAsm) emit(i ...bpf.Instruction) { a.ins = append(a.ins, i...) }

func (a *bpfAsm) label(name string) { a.labels[name] = len(a.ins) }

// jmp 无条件跳转（32 位偏移，不受 255 限制）
func (a *bpfAsm) jmp(label string) {
	a.fixups = append(a.fixups, fixup{len(a.ins), label})
	a.emit(bpf.Jump{})
}

// jif 条件成立时跳到标签：条件跳转只跨过下一条 ja，远距离跳转交给 ja
func (a *bpfAsm) jif(cond bpf.JumpTest, val uint32, label string) {
	a.emit(bpf.JumpIf{Cond: cond, Val: val, SkipTrue: 0, SkipFalse: 1})
	a.jmp(label)
}

func (a *bpfAsm) assemble() ([]bpf.RawInstruction, error) {
	for _, f := range a.fixups {
		target, ok := a.labels[f.label]
		if !ok {
			return nil, fmt.Errorf("bpf: undefined label %s", f.label)
		}
		if target <= f.idx {
			return nil, fmt.Errorf("bpf: backward jump to %s", f.label)
		}
		a.ins[f.idx] = bpf.Jump{Skip: uint32(target - f.idx - 1)}
	}
	return bpf.Assemble(a.ins)
}

// buildFilter 生成入站过滤器：
//   - 所有端口的纯 SYN（扫端口）
//   - 发往 tcpPorts 的 FIN/RST 与带数据的包
//   - 发往 udpPorts 或低于 udpScanPortLimit 端口的 UDP
//   - 所有 ICMP / ICMPv6
//
// 只接收 PACKET_HOST（发给本机的包），不处理分片。
func buildFilter(tcpPorts, udpPorts []uint16) ([]bpf.RawInstruction, error) {
	if len(tcpPorts) > maxBPFPorts {
		tcpPorts = tcpPorts[:maxBPFPorts]
	}
	if len(udpPorts) > maxBPFPorts {
		udpPorts = udpPorts[:maxBPFPorts]
	}
	a := newBPFAsm()
	a.emit(bpf.LoadExtension{Num: bpf.ExtType})
	a.jif(bpf.JumpNotEqual, 0, "drop") // PACKET_HOST
	a.emit(bpf.LoadExtension{Num: bpf.ExtProto})
	a.jif(bpf.JumpEqual, ethPIPv4, "v4")
	a.jif(bpf.JumpEqual, ethPIPv6, "v6")
	a.jmp("drop")

	// IPv4
	a.label("v4")
	a.emit(bpf.LoadAbsolute{Off: 6, Size: 2})
	a.jif(bpf.JumpBitsSet, 0x1fff, "drop") // 分片
	a.emit(bpf.LoadAbsolute{Off: 9, Size: 1})
	a.jif(bpf.JumpEqual, ipProtoTCP, "t4")
	a.jif(bpf.JumpEqual, ipProtoUDP, "u4")
	a.jif(bpf.JumpEqual, ipProtoICMP, "icmp")
	a.jmp("drop")

	a.label("t4")
	a.emit(bpf.LoadMemShift{Off: 0}) // X = IP 头长度
	a.emit(bpf.LoadIndirect{Off: 13, Size: 1}, bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: tcpSYN | tcpACK})
	a.jif(bpf.JumpEqual, tcpSYN, "syn")
	a.emit(bpf.LoadIndirect{Off: 13, Size: 1})
	a.jif(bpf.JumpBitsSet, tcpFIN|tcpRST, "t4port")
	// 负载长度 = IP 总长 - IP 头长 - TCP 头长
	a.emit(
		bpf.LoadAbsolute{Off: 2, Size: 2},
		bpf.ALUOpX{Op: bpf.ALUOpSub},
		bpf.StoreScratch{Src: bpf.RegA, N: 0},
		bpf.LoadIndirect{Off: 12, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 4},
		bpf.ALUOpConstant{Op: bpf.ALUOpShiftLeft, Val: 2},
		bpf.TAX{},
		bpf.LoadScratch{Dst: bpf.RegA, N: 0},
		bpf.ALUOpX{Op: bpf.ALUOpSub},
	)
	a.jif(bpf.JumpEqual, 0, "drop")
	a.emit(bpf.LoadMemShift{Off: 0})
	a.label("t4port")
	a.emit(bpf.LoadIndirect{Off: 2, Size: 2})
	a.jmp("tports")

	a.label("u4")
	a.emit(bpf.LoadMemShift{Off: 0}, bpf.LoadIndirect{Off: 2, Size: 2})
	a.jmp("uports")

	// IPv6（只认固定头后直接跟 TCP/UDP/ICMPv6 的包）
	a.label("v6")
	a.emit(bpf.LoadAbsolute{Off: 6, Size: 1})
	a.jif(bpf.JumpEqual, ipProtoTCP, "t6")
	a.jif(bpf.JumpEqual, ipProtoUDP, "u6")
	a.jif(bpf.JumpEqual, ipProtoICMPv6, "icmp")
	a.jmp("drop")

	a.label("t6")
	a.emit(bpf.LoadConstant{Dst: bpf.RegX, Val: 40})
	a.emit(bpf.LoadIndirect{Off: 13, Size: 1}, bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: tcpSYN | tcpACK})
	a.jif(bpf.JumpEqual, tcpSYN, "syn")
	a.emit(bpf.LoadIndirect{Off: 13, Size: 1})
	a.jif(bpf.JumpBitsSet, tcpFIN|tcpRST, "t6port")
	a.emit(
		bpf.LoadAbsolute{Off: 4, Size: 2}, // IPv6 负载长度
		bpf.StoreScratch{Src: bpf.RegA, N: 0},
		bpf.LoadIndirect{Off: 12, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 4},
		bpf.ALUOpConstant{Op: bpf.ALUOpShiftLeft, Val: 2},
		bpf.TAX{},
		bpf.LoadScratch{Dst: bpf.RegA, N: 0},
		bpf.ALUOpX{Op: bpf.ALUOpSub},
	)
	a.jif(bpf.JumpEqual, 0, "drop")
	a.emit(bpf.LoadConstant{Dst: bpf.RegX, Val: 40})
	a.label("t6port")
	a.emit(bpf.LoadIndirect{Off: 2, Size: 2})
	a.jmp("tports")

	a.label("u6")
	a.emit(bpf.LoadConstant{Dst: bpf.RegX, Val: 40}, bpf.LoadIndirect{Off: 2, Size: 2})
	a.jmp("uports")

	// A = 目的端口
	a.label("tports")
	for _, p := range tcpPorts {
		a.jif(bpf.JumpEqual, uint32(p), "payload")
	}
	a.jmp("drop")

	a.label("uports")
	for _, p := range udpPorts {
		a.jif(bpf.JumpEqual, uint32(p), "payload")
	}
	a.jif(bpf.JumpLessThan, udpScanPortLimit, "payload")
	a.jmp("drop")

	a.label("syn")
	a.emit(bpf.RetConstant{Val: snapHeader})
	a.label("icmp")
	a.emit(bpf.RetConstant{Val: snapICMP})
	a.label("payload")
	a.emit(bpf.RetConstant{Val: snapPayload})
	a.label("drop")
	a.emit(bpf.RetConstant{Val: 0})
	return a.assemble()
}
