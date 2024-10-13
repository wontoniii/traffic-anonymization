package anonymization

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"github.com/wontoniii/traffic-anonymization/pkg/network"
)

// AModule
type AModule struct {
	// Whether to anonymize IP addresses or not
	anonymize bool
	// Loop time for the anonymization module
	loopTime time.Duration
	// Whether to anonymize private networks or not
	privateNets bool
	// Local network to anonymize
	localNet string
	// Destination to encapsulate
	encapsulateDst string

	// Local variable to store the packet processor
	packetProcessor network.PacketProcessor

	// Local variable to store the Cryptopan context
	ctx *Cryptopan
	// Local variable to know whether to anonymize local networks or not
	hasLocalNet bool
	// Local variable to know whether to encapsulate the destination or not
	hasEncapsulateDst bool
	// Private network variables
	privateNetsCIDR []*net.IPNet
	// Local network variable
	localNetCIDR *net.IPNet
	// Time ticker
	ticker *time.Ticker
}

// NewAModule
func NewAModule(key string, anonymize bool, privateNets bool, localNet string, loopTime time.Duration, packetProcessor network.PacketProcessor) *AModule {
	ret := &AModule{}

	ret.anonymize = anonymize
	if ret.anonymize {
		var testKey = []byte{45, 148, 31, 183, 121, 99, 98, 199, 103, 48, 199, 151, 176, 128, 82, 175, 33, 228, 17, 204, 122, 199, 124, 65, 130, 80, 120, 210, 81, 207, 169, 48}
		ret.ctx, _ = NewCryptoPAn(testKey)

		ret.loopTime = loopTime
		// Check if need to active loop to change anonymization key

		ret.privateNets = privateNets
		if ret.privateNets {
			ret.privateNetsCIDR = network.CIDRAllInit()
		}

		ret.localNet = localNet
		if ret.localNet != "" {
			_, ret.localNetCIDR, _ = network.ParseIP(ret.localNet)
			ret.hasLocalNet = true
		}

	}

	ret.loopTime = loopTime
	// TODO: Implement loop time
	if ret.loopTime != 0 {
		go func() {
			ret.ticker = time.NewTicker(loopTime)
			for {
				select {
				case <-ret.ticker.C:
					//Change the key
				}
			}
		}()
	}

	ret.packetProcessor = packetProcessor

	log.Debugln("AModule initialized correctly")
	return ret
}

// ProcessPacket processes incoming packets.
func (am *AModule) ProcessPacket(pkt *network.Packet) error {
	if am.anonymize {
		is_src_local := am.localNetCIDR.Contains(net.ParseIP(pkt.SrcIP))
		is_dst_local := am.localNetCIDR.Contains(net.ParseIP(pkt.DstIP))
		if is_src_local && is_dst_local && am.hasLocalNet {
			log.Debugf("Both source and destination are private, dropping packet")
			return nil
		}

		pkt.OutBuf = gopacket.NewSerializeBufferExpectedSize(len(pkt.RawData), 0)

		if am.privateNets && network.IsPrivateIP(am.privateNetsCIDR, net.ParseIP(pkt.SrcIP)) || am.hasLocalNet && is_src_local {
			pkt.SrcIP = am.ctx.Anonymize(net.ParseIP(pkt.SrcIP)).String()
		}
		if am.privateNets && network.IsPrivateIP(am.privateNetsCIDR, net.ParseIP(pkt.DstIP)) || am.hasLocalNet && is_dst_local {
			pkt.DstIP = am.ctx.Anonymize(net.ParseIP(pkt.DstIP)).String()
		}

		options := gopacket.SerializeOptions{}
		if pkt.IsDNS {
			err := pkt.Dns.SerializeTo(pkt.OutBuf, options)
			if err != nil {
				panic(err)
			}
			log.Debugf("Added dns %d", len(pkt.OutBuf.Bytes()))
		}
		if pkt.IsTLS {
			err := pkt.TLS.SerializeTo(pkt.OutBuf, options)
			if err != nil {
				panic(err)
			}
			log.Debugf("Added tls %d", len(pkt.OutBuf.Bytes()))
		}
		if pkt.IsTCP {
			err := pkt.Tcp.SerializeTo(pkt.OutBuf, options)
			if err != nil {
				panic(err)
			}
			log.Debugf("Added tcp %d", len(pkt.OutBuf.Bytes()))
		}
		if pkt.IsUDP {
			err := pkt.Udp.SerializeTo(pkt.OutBuf, options)
			if err != nil {
				panic(err)
			}
			log.Debugf("Added udp %d", len(pkt.OutBuf.Bytes()))
		}
		if pkt.IsIPv4 {
			pkt.Ip4.SrcIP = net.ParseIP(pkt.SrcIP)
			pkt.Ip4.DstIP = net.ParseIP(pkt.DstIP)
			err := pkt.Ip4.SerializeTo(pkt.OutBuf, options)
			if err != nil {
				panic(err)
			}
			log.Debugf("Added ip4 %d", len(pkt.OutBuf.Bytes()))
		}
		if pkt.IsIPv6 {
			pkt.Ip6.SrcIP = net.ParseIP(pkt.SrcIP)
			pkt.Ip6.DstIP = net.ParseIP(pkt.DstIP)
			err := pkt.Ip6.SerializeTo(pkt.OutBuf, options)
			if err != nil {
				panic(err)
			}
			log.Debugf("Added ip6 %d", len(pkt.OutBuf.Bytes()))
		}
		// Brutal anonymization of ethernet
		// TODO use unused MAC addresses to put timestamp
		// var err error
		// pkt.Eth.SrcMAC, err = net.ParseMAC("00:00:00:00:00:00")
		// if err != nil {
		// 	panic(err)
		// }
		// pkt.Eth.DstMAC, err = net.ParseMAC("00:00:00:00:00:00")
		// if err != nil {
		// 	panic(err)
		// }
		// pkt.Eth.SerializeTo(pkt.OutBuf, options)

		ethernetLayer := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0xff, 0xaa, 0xfa, 0xaa, 0xff, 0xaa},
			DstMAC:       net.HardwareAddr{0xbd, 0xbd, 0xbd, 0xbd, 0xbd, 0xbd},
			EthernetType: layers.EthernetTypeIPv4,
		}

		if pkt.IsIPv6 {
			ethernetLayer.EthernetType = layers.EthernetTypeIPv6
		}

		ethernetLayer.SerializeTo(pkt.OutBuf, options)

		log.Debugf("Added eth %d", len(pkt.OutBuf.Bytes()))
		if pkt.Ci.Length < len(pkt.OutBuf.Bytes()) {
			log.Errorf("The packet length is smaller than the produced data len, src %s, dst %s", pkt.SrcIP, pkt.DstIP)
			pkt.Ci.Length = len(pkt.OutBuf.Bytes())
			// return nil
		} else {
			log.Debugf("And the produced data len is %d", len(pkt.OutBuf.Bytes()))
		}
	}
	am.packetProcessor.ProcessPacket(pkt)

	return nil

}
