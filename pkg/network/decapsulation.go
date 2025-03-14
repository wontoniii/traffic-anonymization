package network

import (
	"time"

	"github.com/google/gopacket"
	log "github.com/sirupsen/logrus"
)

// AModule
type DecapsulateModule struct {

	// Local variable to store the packet processor
	packetProcessor PacketProcessor
}

// NewAModule
func NewDecapsulateModule(packetProcessor PacketProcessor) *DecapsulateModule {
	ret := &DecapsulateModule{}
	ret.packetProcessor = packetProcessor
	log.Debugln("StripeModule initialized correctly")
	return ret
}

func (am *DecapsulateModule) Stop() error {
	return nil
}

// ProcessPacket processes incoming packets.
func (am *DecapsulateModule) ProcessPacket(pkt *Packet) error {
	var err error
	var timestamp time.Time

	options := gopacket.SerializeOptions{}
	payload := pkt.Payload.Payload()[8:]
	pkt.OutBuf = gopacket.NewSerializeBufferExpectedSize(len(payload), 0)
	gopacket.Payload(payload).SerializeTo(pkt.OutBuf, options)

	timestamp, err = bytesToTime(pkt.Payload.Payload()[:8])

	if err != nil {
		log.Errorf("Could not convert timestamp back")
	} else {
		pkt.Ci.Timestamp = timestamp
	}

	if pkt.Ci.Length != len(pkt.OutBuf.Bytes()) {
		pkt.Ci.Length = len(pkt.OutBuf.Bytes())
	} else {
		log.Debugf("And the produced data len is %d", len(pkt.OutBuf.Bytes()))
	}

	am.packetProcessor.ProcessPacket(pkt)

	return nil

}
