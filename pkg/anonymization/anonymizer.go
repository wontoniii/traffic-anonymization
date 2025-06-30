package anonymization

import (
	"github.com/wontoniii/traffic-anonymization/pkg/network"
)

// AModule
type Anonymizer struct {
	am *AModule

	// Local variable to store the packet processor
	packetProcessor network.PacketProcessor
}

// NewAnonymizer
func NewAnonymizer(am *AModule, packetProcessor network.PacketProcessor) *Anonymizer {
	ret := &Anonymizer{}
	ret.am = am
	ret.packetProcessor = packetProcessor
	return ret
}

// ProcessPacket processes incoming packets.
func (an *Anonymizer) ProcessPacket(pkt *network.Packet) error {

	if err := an.am.Anonymize(pkt); err != nil {
		return err
	}
	// Pass the packet to the packet processor
	an.packetProcessor.ProcessPacket(pkt)

	return nil

}
