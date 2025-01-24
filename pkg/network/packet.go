package network

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Packet struct {
	RawData []byte
	Ci      gopacket.CaptureInfo
	Eth     *layers.Ethernet
	Ip4     *layers.IPv4
	Ip6     *layers.IPv6
	Tcp     *layers.TCP
	Udp     *layers.UDP
	Dns     *layers.DNS
	TLS     *layers.TLS
	Payload *gopacket.Payload
	TStamp  int64
	IsIPv4  bool
	IsIPv6  bool
	SrcIP   string
	DstIP   string
	IsTCP   bool
	IsUDP   bool
	SrcPort uint16
	DstPort uint16
	IsDNS   bool
	IsTLS   bool
	OutBuf  gopacket.SerializeBuffer
}

func NewPacket() *Packet {
	packet := &Packet{}
	packet.Eth = new(layers.Ethernet)
	packet.Ip4 = new(layers.IPv4)
	packet.Ip6 = new(layers.IPv6)
	packet.Tcp = new(layers.TCP)
	packet.Udp = new(layers.UDP)
	packet.Dns = new(layers.DNS)
	packet.TLS = new(layers.TLS)
	packet.Payload = new(gopacket.Payload)
	return packet
}

func (packet *Packet) Clear() {
	packet.Ci = gopacket.CaptureInfo{}
	packet.TStamp = 0
	packet.IsIPv4 = false
	packet.IsIPv6 = false
	packet.SrcIP = ""
	packet.DstIP = ""
	packet.IsTCP = false
	packet.IsUDP = false
	packet.SrcPort = 0
	packet.DstPort = 0
	packet.IsDNS = false
	packet.IsTLS = false
}

func (packet *Packet) ClearBool() {
	packet.IsIPv4 = false
	packet.IsIPv6 = false
	packet.IsTCP = false
	packet.IsUDP = false
	packet.IsDNS = false
	packet.IsTLS = false
}
