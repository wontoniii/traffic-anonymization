package network

import (
	"github.com/google/gopacket"
	log "github.com/sirupsen/logrus"
)

type PacketPointer struct {
	ci  gopacket.CaptureInfo
	buf *gopacket.SerializeBuffer
}

type CopySenderHandle struct {
	sh         *SocketHandle
	bufferChan chan PacketPointer
}

func (h *CopySenderHandle) Init(conf *HandleConfig) error {
	h.sh = &SocketHandle{}
	h.sh.Init(conf)
	h.bufferChan = make(chan PacketPointer, 32768)
	go h.receiver()
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
		pkt.OutBuf = *copiedData.buf
		h.sh.WritePacketData(&pkt)
	}
}

func (h *CopySenderHandle) WritePacketData(pkt *Packet) error {
	log.Debugf("Preparing to pass the packet to the other thread")
	// Write packet to file
	buf := PacketPointer{
		ci:  pkt.Ci,
		buf: &pkt.OutBuf,
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
