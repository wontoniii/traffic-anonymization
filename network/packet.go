package network

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Packet struct {
	RawData    []byte
	Ci         gopacket.CaptureInfo
	Eth        *layers.Ethernet
	Ip4        *layers.IPv4
	Ip6        *layers.IPv6
	Tcp        *layers.TCP
	Udp        *layers.UDP
	Dns        *layers.DNS
	Payload    *gopacket.Payload
	TStamp     int64
	HwAddr     string
	IsIPv4     bool
	IsLocal    bool
	Length     int64
	SrcIP      string
	DstIP      string
	IsTCP      bool
	DataLength int64
	SrcPort    uint16
	DstPort    uint16
	SeqNumber  uint32
	IsDNS      bool
}

func NewPacket() *Packet {
	packet := &Packet{}
	packet.Eth = new(layers.Ethernet)
	packet.Ip4 = new(layers.IPv4)
	packet.Ip6 = new(layers.IPv6)
	packet.Tcp = new(layers.TCP)
	packet.Udp = new(layers.UDP)
	packet.Payload = new(gopacket.Payload)
	return packet
}

func (packet *Packet) Clear() {
	packet.Ci = gopacket.CaptureInfo{}
	packet.TStamp = 0
	packet.HwAddr = ""
	packet.IsIPv4 = false
	packet.IsLocal = false
	packet.Length = 0
	packet.SrcIP = ""
	packet.DstIP = ""
	packet.IsTCP = false
	packet.DataLength = 0
	packet.SrcPort = 0
	packet.DstPort = 0
	packet.SeqNumber = 0
	packet.IsDNS = false
}
