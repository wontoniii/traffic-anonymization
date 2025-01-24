package network

import (
	"github.com/google/gopacket"
	log "github.com/sirupsen/logrus"
)

type CopySenderHandle struct {
	sh         *SocketHandle
	bufferChan chan PacketCopyBuffer
}

func (h *CopySenderHandle) Init(conf *HandleConfig) error {
	h.sh.Init(conf)
	h.bufferChan = make(chan PacketCopyBuffer, 32768)
	return nil
}

func (h *CopySenderHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	log.Fatal("CopyWriterHandle does not support reading")
	return nil, gopacket.CaptureInfo{}, nil
}

func (h *CopySenderHandle) receiver() error {
	// This sends out the data
	pkt := Packet{}
	for {
		copiedData := <-h.bufferChan
		pkt.Ci = copiedData.ci
		pkt.OutBuf = copiedData.buf
		h.sh.WritePacketData(&pkt)
	}
}

func (h *CopySenderHandle) WritePacketData(pkt *Packet) error {
	log.Debugf("Preparing to pass the packet to the other thread")
	// Write packet to file
	buf := PacketCopyBuffer{
		ci:  pkt.Ci,
		buf: pkt.OutBuf,
	}
	h.bufferChan <- buf
	return nil
}

func (h *CopySenderHandle) Stats() IfStats {
	return IfStats{
		PktRecv: 0,
		PktDrop: 0,
	}
}

func (h *CopySenderHandle) Close() error {
	//TODO close the channel
	h.sh.Close()
	return nil
}
