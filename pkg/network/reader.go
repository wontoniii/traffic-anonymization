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

func (tp *Reader) parseUdpLayer(udp *layers.UDP) (uint16, uint16, error) {
	srcPort := udp.SrcPort
	dstPort := udp.DstPort
	return uint16(srcPort), uint16(dstPort), nil
}

func (tp *Reader) parseTcpLayer(tcp *layers.TCP) (uint16, uint16, error) {
	srcPort := tcp.SrcPort
	dstPort := tcp.DstPort
	return uint16(srcPort), uint16(dstPort), nil
}

func (tp *Reader) parseIpV4Layer(ip *layers.IPv4) (string, string, error) {
	var srcIp, dstIp string
	srcIp = ip.SrcIP.String()
	dstIp = ip.DstIP.String()

	return srcIp, dstIp, nil
}

func (tp *Reader) parseIpV6Layer(ip *layers.IPv6) (string, string, error) {
	var srcIp, dstIp string
	srcIp = ip.SrcIP.String()
	dstIp = ip.DstIP.String()

	return srcIp, dstIp, nil
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

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, pkt.Eth, vlantag, pkt.Ip4, pkt.Ip6, pkt.Tcp, pkt.Udp, pkt.Dns, pkt.Payload)
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

				case layers.LayerTypeIPv4:
					pkt.SrcIP, pkt.DstIP, parsingErr = tp.parseIpV4Layer(pkt.Ip4)
					pkt.IsIPv4 = true
				case layers.LayerTypeIPv6:
					pkt.SrcIP, pkt.DstIP, parsingErr = tp.parseIpV6Layer(pkt.Ip6)
					pkt.IsIPv6 = true
				case layers.LayerTypeTCP:
					pkt.SrcPort, pkt.DstPort, parsingErr = tp.parseTcpLayer(pkt.Tcp)
					pkt.IsTCP = true
					isValid = true
				case layers.LayerTypeUDP:
					pkt.SrcPort, pkt.DstPort, parsingErr = tp.parseUdpLayer(pkt.Udp)
					pkt.IsUDP = true
					isValid = true
				case layers.LayerTypeTLS:
					pkt.IsTLS = true
				case layers.LayerTypeDNS:
					pkt.IsDNS = true
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
