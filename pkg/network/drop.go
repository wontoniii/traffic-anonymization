package network

import (
	"github.com/google/gopacket"
	log "github.com/sirupsen/logrus"
)

type DropHandle struct {
}

func (h *DropHandle) NewDropInterface() {
	log.Debugf("This is just a drop interface")
}

func (h *DropHandle) Init(conf *HandleConfig) error {
	return nil
}

func (h *DropHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	log.Fatal("Not implemented")
	return nil, gopacket.CaptureInfo{}, nil
}

func (h *DropHandle) WritePacketData(pkt *Packet) error {
	log.Debugf("Doing nothing with the packet")
	return nil
}

func (h *DropHandle) Stats() IfStats {
	return IfStats{
		PktRecv: 0,
		PktDrop: 0,
	}
}

func (h *DropHandle) Close() error {
	return nil
}
