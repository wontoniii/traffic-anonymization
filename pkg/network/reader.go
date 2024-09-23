package network

import (
	"io"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
)

type Reader struct {
	netif           *NetworkInterface
	packetProcessor PacketProcessor
}

func NewReader(netif *NetworkInterface, packetProcessor PacketProcessor) *Reader {
	r := &Reader{}
	r.netif = netif
	r.packetProcessor = packetProcessor
	return r
}

func (tp *Reader) parseUdpLayer(udp *layers.UDP) (int64, uint16, uint16, error) {
	srcPort := udp.SrcPort
	dstPort := udp.DstPort
	return int64(udp.Length - 8), uint16(srcPort), uint16(dstPort), nil
}

func (tp *Reader) parseTcpLayer(tcp *layers.TCP, ipDataLen int64) (int64, uint16, uint16, uint32, error) {
	srcPort := tcp.SrcPort
	dstPort := tcp.DstPort
	seq := tcp.Seq
	return ipDataLen - 4*int64(tcp.DataOffset), uint16(srcPort), uint16(dstPort), seq, nil
}

func (tp *Reader) parseIpV4Layer(ip *layers.IPv4) (int64, string, string, bool, error) {
	var isLocal bool
	var ipDataLen int64
	var srcIp, dstIp string

	ipDataLen = int64(ip.Length - 4*uint16(ip.IHL))
	srcIp = ip.SrcIP.String()
	dstIp = ip.DstIP.String()

	return ipDataLen, srcIp, dstIp, isLocal, nil
}

func (tp *Reader) parseIpV6Layer(ip *layers.IPv6) (int64, string, string, bool, error) {
	var isLocal bool
	var ipDataLen int64
	var srcIp, dstIp string

	ipDataLen = int64(ip.Length)
	srcIp = ip.SrcIP.String()
	dstIp = ip.DstIP.String()

	return ipDataLen, srcIp, dstIp, isLocal, nil
}

func (tp *Reader) parseEthLayer(eth *layers.Ethernet) (string, error) {
	return eth.SrcMAC.String(), nil
}

// TrafficParser is the worker function for parsing network traffic. Each worker reads directly from the ring that is passed
// The waitgroup is used to cleanly shut down. Each worker listen on the stop chan to know when to stop processing
func (tp *Reader) Parse(wg *sync.WaitGroup, stop chan struct{}) {
	// We use decodinglayerparser, so we set up variables for the layers we intend to parse
	pkt := NewPacket()
	var vlantag *layers.Dot1Q
	vlantag = new(layers.Dot1Q)

	// We use Flows to access the network and transport endpoints when building the 4-tuple flow
	// var netFlow, tranFlow gopacket.Flow
	// isValid is a flag used to tell the worker whether or not to process the information in a packet
	var isValid bool
	var parsingErr error

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, pkt.Eth, vlantag, pkt.Ip4, pkt.Ip6, pkt.Tcp, pkt.Udp, pkt.Payload)
	decoded := []gopacket.LayerType{}
	if wg != nil {
		defer wg.Done()
	}
loop:
	for {
		pkt.Clear()
		select {
		// signal from main.go has been caught (user shutting down daemon)
		case <-stop:
			break loop
		// process data from ring
		default:
			// Read raw bytes from ring - NOT a gopacket.packet
			data, ci, err := tp.netif.ReadPacketData()
			pkt.TStamp = ci.Timestamp.UnixNano()
			pkt.Ci = ci
			pkt.RawData = data

			// reset variables
			isValid = false

			if err == io.EOF {
				break
			} else if err != nil {
				continue
			}

			err = parser.DecodeLayers(data, &decoded)

			//TODO handle the fact that there are case of errors even when it should not be interrupted
			if err != nil {
				log.Debugln(err)
			}

			for _, typ := range decoded {
				switch typ {
				case layers.LayerTypeEthernet:
					pkt.HwAddr, parsingErr = tp.parseEthLayer(pkt.Eth)
				case layers.LayerTypeIPv4:
					pkt.Length, pkt.SrcIP, pkt.DstIP, pkt.IsLocal, parsingErr = tp.parseIpV4Layer(pkt.Ip4)
					pkt.IsIPv4 = true
				case layers.LayerTypeTCP:
					pkt.DataLength, pkt.SrcPort, pkt.DstPort, pkt.SeqNumber, parsingErr = tp.parseTcpLayer(pkt.Tcp, pkt.Length)
					pkt.IsTCP = true
					isValid = true
				case layers.LayerTypeUDP:
					pkt.DataLength, pkt.SrcPort, pkt.DstPort, parsingErr = tp.parseUdpLayer(pkt.Udp)
					pkt.IsTCP = false
					isValid = true
				case layers.LayerTypeIPv6:
					pkt.Length, pkt.SrcIP, pkt.DstIP, pkt.IsLocal, parsingErr = tp.parseIpV6Layer(pkt.Ip6)
					pkt.IsIPv4 = false
				}
			}

			if parsingErr != nil {
				log.Warnln(err)
				continue
			}
			if !isValid {
				log.Debugf("Read packet without required layers or with wrong direction")
				continue
			}

			tp.packetProcessor.ProcessPacket(pkt)
		}
	}
}
