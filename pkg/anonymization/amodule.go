package anonymization

import (
	"bytes"
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
	localNets []string

	// Local variable to store the Cryptopan context
	ctx *Cryptopan
	// Local variable to know whether to anonymize local networks or not
	hasLocalNet bool
	// Private network variables
	privateNetsCIDR []*net.IPNet
	// Local network variable
	localNetCIDRs []*net.IPNet
	// Stop channel
	stopChan chan struct{}
	// Mutex to access cryptopan
	mu sync.RWMutex
}

// NewAModule
func NewAModule(key string, anonymize bool, privateNets bool, localNets []string, loopTime int) *AModule {
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

		ret.localNets = localNets
		if len(ret.localNets) > 0 {
			ret.hasLocalNet = true
			ret.localNetCIDRs = network.ToNets(ret.localNets)
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

	log.Debugln("AModule initialized correctly")
	return ret
}

func (am *AModule) Stop() error {
	close(am.stopChan)
	return nil
}

// isTLSHandshake examines a packet to determine if it contains a TLS handshake message
func isTLSHandshake(tcp *layers.TCP) bool {
	bp := tcp.LayerPayload()
	// Not enough data for TLS header
	if len(bp) < 5 {
		log.Debugf("Not enough data for TLS header")
		return false
	}

	// Check if this is a TLS record
	// TLS Record format:
	// Byte 0: Content Type (22 = Handshake)
	// Bytes 1-2: Version (0x0301 = TLS 1.0, 0x0302 = TLS 1.1, 0x0303 = TLS 1.2/1.3)
	// Bytes 3-4: Length

	// Check for TLS Content Type: Handshake (22)
	if bp[0] == 22 {
		log.Debugf("TLS Content Type detected: %x", bp[0])
		// Common TLS versions
		isVersion := (bp[1] == 3) &&
			(bp[2] == 1 || // TLS 1.0
				bp[2] == 2 || // TLS 1.1
				bp[2] == 3 || // TLS 1.2 or 1.3
				bp[2] == 4) // TLS 1.3 draft versions

		if isVersion {
			log.Debugf("TLS version detected: %x %x", bp[1], bp[2])
			// If we want to dig deeper, we can check the handshake type at payload[5]
			// 1: ClientHello, 2: ServerHello, etc.
			if len(bp) > 5 {
				handshakeType := bp[5]
				// Only interested in the main handshake messages (ClientHello, ServerHello, etc.)
				return handshakeType >= 1 && handshakeType <= 4
			}
			return true
		}
	}
	log.Debugf("Not a TLS handshake")

	return false
}

// isQUICHandshake examines a packet to determine if it contains a QUIC handshake message
func isQUICHandshake(udp *layers.UDP) bool {
	bp := udp.LayerPayload()

	// Not enough data for QUIC header
	if len(bp) < 5 {
		return false
	}

	// Check for QUIC version 1 long header format
	// First byte:
	// Bits 0-3: Header Form (1 for long header)
	// Bits 4-5: Fixed Bits (always 0 in v1)
	// Bits 6-7: Packet Type (0 for Initial)
	headerByte := bp[0]

	// Check if it's a long header packet (most significant bit is 1)
	isLongHeader := (headerByte & 0x80) != 0
	if !isLongHeader {
		return false // Short header packets aren't handshakes
	}

	// Extract packet type from bits 4-5 of first byte (for QUIC v1)
	// In QUIC v1: 0=Initial, 1=0-RTT, 2=Handshake, 3=Retry
	packetType := (headerByte & 0x30) >> 4

	// Version field is bytes 1-4
	versionBytes := bp[1:5]

	// Check for version negotiation packet (special case)
	if versionBytes[0] == 0 && versionBytes[1] == 0 && versionBytes[2] == 0 && versionBytes[3] == 0 {
		return true // Version Negotiation packets are part of handshake process
	}

	// Check for QUIC v1 (0x00000001)
	isQUICv1 := versionBytes[0] == 0 && versionBytes[1] == 0 &&
		versionBytes[2] == 0 && versionBytes[3] == 1

	// Check for draft versions (0xff000000 to 0xffffffff)
	isDraft := versionBytes[0] == 0xff

	// Google's Q050 and Q051 (older but still in use)
	isGoogleQUIC := bytes.Equal(versionBytes, []byte("Q050")) ||
		bytes.Equal(versionBytes, []byte("Q051"))

	if !(isQUICv1 || isDraft || isGoogleQUIC) {
		return false // Unknown version
	}

	// In QUIC v1 and most drafts, packet types 0 (Initial) and 2 (Handshake)
	// are handshake packets
	if isQUICv1 && (packetType == 0 || packetType == 2) {
		return true
	}

	// For draft versions we're a bit more permissive
	if isDraft && packetType <= 2 {
		return true
	}

	return false
}

// Anonymize processes incoming packets.
func (am *AModule) Anonymize(pkt *network.Packet) error {
	if am.anonymize {
		is_src_local := network.IsPrivateIP(am.localNetCIDRs, net.ParseIP(pkt.SrcIP))
		is_dst_local := network.IsPrivateIP(am.localNetCIDRs, net.ParseIP(pkt.DstIP))
		if is_src_local && is_dst_local && am.hasLocalNet {
			log.Debugf("Both source and destination are private, dropping packet")
			return nil
		}

		pkt.OutBuf = gopacket.NewSerializeBufferExpectedSize(len(pkt.RawData), 0)

		am.mu.RLock()
		if am.privateNets && network.IsPrivateIP(am.privateNetsCIDR, net.ParseIP(pkt.SrcIP)) || am.hasLocalNet && is_src_local {
			log.Debugf("Source is private, anonymize")
			pkt.SrcIP = am.ctx.Anonymize(net.ParseIP(pkt.SrcIP)).String()
		}
		if am.privateNets && network.IsPrivateIP(am.privateNetsCIDR, net.ParseIP(pkt.DstIP)) || am.hasLocalNet && is_dst_local {
			log.Debugf("Destination is private, anonymize")
			pkt.DstIP = am.ctx.Anonymize(net.ParseIP(pkt.DstIP)).String()
		}
		am.mu.RUnlock()

		options := gopacket.SerializeOptions{}
		if pkt.IsDNS {
			err := pkt.Dns.SerializeTo(pkt.OutBuf, options)
			if err != nil {
				log.Error(err)
				return nil
			}
			log.Debugf("Added dns %d", len(pkt.OutBuf.Bytes()))
		}

		if pkt.IsTCP {
			// Check if the payload is a TLS handshake
			if isTLSHandshake(pkt.Tcp) {
				log.Debugf("TLS handshake detected")
				err := gopacket.Payload(pkt.Tcp.LayerPayload()).SerializeTo(pkt.OutBuf, options)
				if err != nil {
					log.Error(err)
					return nil
				}
			}
			err := pkt.Tcp.SerializeTo(pkt.OutBuf, options)
			if err != nil {
				log.Error(err)
				return nil
			}
			log.Debugf("Added tcp %d", len(pkt.OutBuf.Bytes()))

		}
		if pkt.IsUDP {
			// Check if the payload is a TLS handshake
			if !pkt.IsDNS && isQUICHandshake(pkt.Udp) {
				log.Debugf("QUIC handshake detected")
				err := gopacket.Payload(pkt.Udp.LayerPayload()).SerializeTo(pkt.OutBuf, options)
				if err != nil {
					log.Error(err)
					return nil
				}
			}
			err := pkt.Udp.SerializeTo(pkt.OutBuf, options)
			if err != nil {
				log.Error(err)
				return nil
			}
			log.Debugf("Added udp %d", len(pkt.OutBuf.Bytes()))

		}
		if pkt.IsIPv4 {
			pkt.Ip4.SrcIP = net.ParseIP(pkt.SrcIP)
			pkt.Ip4.DstIP = net.ParseIP(pkt.DstIP)
			err := pkt.Ip4.SerializeTo(pkt.OutBuf, options)
			if err != nil {
				log.Error(err)
			}
			log.Debugf("Added ip4 %d", len(pkt.OutBuf.Bytes()))
		}
		if pkt.IsIPv6 {
			pkt.Ip6.SrcIP = net.ParseIP(pkt.SrcIP)
			pkt.Ip6.DstIP = net.ParseIP(pkt.DstIP)
			err := pkt.Ip6.SerializeTo(pkt.OutBuf, options)
			if err != nil {
				log.Error(err)
				return nil
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
			log.Debugf("The packet length is smaller than the produced data len, src %s, dst %s", pkt.SrcIP, pkt.DstIP)
			pkt.Ci.Length = len(pkt.OutBuf.Bytes())
			// return nil
		} else {
			log.Debugf("And the produced data len is %d", len(pkt.OutBuf.Bytes()))
		}
	} else {
		log.Fatal("No support of passthrough at the moment")
	}

	return nil

}
