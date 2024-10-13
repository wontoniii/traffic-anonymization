package anonymization

import (
	"net"
	"time"

	"github.com/google/gopacket"
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
		buffer := gopacket.NewSerializeBufferExpectedSize(len(pkt.RawData), 0)
		//TODO Add check on whether it's internal address or not
		if am.privateNets && network.IsPrivateIP(am.privateNetsCIDR, net.ParseIP(pkt.SrcIP)) || am.hasLocalNet && am.localNetCIDR.Contains(net.ParseIP(pkt.SrcIP)) {
			pkt.SrcIP = am.ctx.Anonymize(net.ParseIP(pkt.SrcIP)).String()
		}
		if am.privateNets && network.IsPrivateIP(am.privateNetsCIDR, net.ParseIP(pkt.DstIP)) || am.hasLocalNet && am.localNetCIDR.Contains(net.ParseIP(pkt.DstIP)) {
			pkt.DstIP = am.ctx.Anonymize(net.ParseIP(pkt.DstIP)).String()
		}
		options := gopacket.SerializeOptions{}
		// Truncated packet
		// pkt.Payload.SerializeTo(buffer, options)
		// Non truncated packet
		gopacket.Payload(pkt.RawData[(int64(len(pkt.RawData))-pkt.DataLength):]).SerializeTo(buffer, options)

		if pkt.IsTCP {
			pkt.Tcp.SerializeTo(buffer, options)
			log.Debugf("Added tcp %d", len(buffer.Bytes()))
		} else {
			pkt.Udp.SerializeTo(buffer, options)
			log.Debugf("Added udp %d", len(buffer.Bytes()))
		}
		if pkt.IsIPv4 {
			pkt.Ip4.SrcIP = net.ParseIP(pkt.SrcIP)
			pkt.Ip4.DstIP = net.ParseIP(pkt.DstIP)
			pkt.Ip4.SerializeTo(buffer, options)
			log.Debugf("Added ip4 %d", len(buffer.Bytes()))
		} else {
			pkt.Ip6.SrcIP = net.ParseIP(pkt.SrcIP)
			pkt.Ip6.DstIP = net.ParseIP(pkt.DstIP)
			pkt.Ip6.SerializeTo(buffer, options)
			log.Debugf("Added ip6 %d", len(buffer.Bytes()))
		}
		// Brutal anonymization of ethernet
		var err error
		pkt.Eth.SrcMAC, err = net.ParseMAC("00:00:00:00:00:00")
		if err != nil {
			panic(err)
		}
		pkt.Eth.DstMAC, err = net.ParseMAC("00:00:00:00:00:00")
		if err != nil {
			panic(err)
		}
		pkt.Eth.SerializeTo(buffer, options)
		log.Debugf("Added eth %d", len(buffer.Bytes()))

		if len(pkt.RawData) < 60 {
			no_padded_len := len(pkt.RawData)
			pkt.RawData = buffer.Bytes()[:no_padded_len]
		} else {
			pkt.RawData = buffer.Bytes()
		}

		log.Debugf("And the produced data len is %d", len(pkt.RawData))
	}
	am.packetProcessor.ProcessPacket(pkt)

	return nil

}
