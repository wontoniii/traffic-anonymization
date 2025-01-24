package anonymization

import (
	"net"
	"sync"
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
	// Time of the day when to create a new key
	loopTime int
	// Whether to anonymize private networks or not
	privateNets bool
	// Local network to anonymize
	localNet string

	// Local variable to store the packet processor
	packetProcessor network.PacketProcessor

	// Local variable to store the Cryptopan context
	ctx *Cryptopan
	// Local variable to know whether to anonymize local networks or not
	hasLocalNet bool
	// Private network variables
	privateNetsCIDR []*net.IPNet
	// Local network variable
	localNetCIDR *net.IPNet
	// Stop channel
	stopChan chan struct{}
	// Mutex to access cryptopan
	mu sync.Mutex
}

// NewAModule
func NewAModule(key string, anonymize bool, privateNets bool, localNet string, loopTime int, packetProcessor network.PacketProcessor) *AModule {
	ret := &AModule{}

	var err error

	ret.anonymize = anonymize
	if ret.anonymize {
		ret.ctx, err = NewCryptoPAn(CreateRandomKey())
		if err != nil {
			log.Fatal("Error initializing crypto module", err)
		}

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

		ret.stopChan = make(chan struct{})
		go func() {
			for {
				now := time.Now()
				nextTicker := time.Date(
					now.Year(),
					now.Month(),
					now.Day(),
					ret.loopTime, 0, 0, 0, now.Location(),
				)

				if now.After(nextTicker) {
					nextTicker = nextTicker.Add(24 * time.Hour)
				}

				// Calculate the duration until the next 2 AM
				durationTillTicker := time.Until(nextTicker)

				select {
				case <-time.After(durationTillTicker):
					// Replace key after ticker
					ret.mu.Lock()
					ret.ctx, err = NewCryptoPAn(CreateRandomKey())
					if err != nil {
						log.Fatal("Error initializing crypto module", err)
					}
					ret.mu.Unlock()
				case <-ret.stopChan:
					// Exit the loop if stopChan is closed
					return
				}
			}
		}()

	}

	ret.packetProcessor = packetProcessor

	log.Debugln("AModule initialized correctly")
	return ret
}

func (am *AModule) Stop() error {
	close(am.stopChan)
	return nil
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

		am.mu.Lock()
		if am.privateNets && network.IsPrivateIP(am.privateNetsCIDR, net.ParseIP(pkt.SrcIP)) || am.hasLocalNet && is_src_local {
			pkt.SrcIP = am.ctx.Anonymize(net.ParseIP(pkt.SrcIP)).String()
		}
		if am.privateNets && network.IsPrivateIP(am.privateNetsCIDR, net.ParseIP(pkt.DstIP)) || am.hasLocalNet && is_dst_local {
			pkt.DstIP = am.ctx.Anonymize(net.ParseIP(pkt.DstIP)).String()
		}
		am.mu.Unlock()

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

		ethernetLayer := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
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
