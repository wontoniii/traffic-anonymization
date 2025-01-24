package network

import (
	"github.com/google/gopacket"
	log "github.com/sirupsen/logrus"
)

type CopyWriterHandle struct {
	fh         *FileHandle
	bufferChan chan PacketCopyBuffer
}

type PacketCopyBuffer struct {
	ci  gopacket.CaptureInfo
	buf gopacket.SerializeBuffer
}

func (h *CopyWriterHandle) Init(conf *HandleConfig) error {
	h.fh.Init(conf)
	h.bufferChan = make(chan PacketCopyBuffer, 32768)
	return nil
}

func (h *CopyWriterHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	log.Fatal("CopyWriterHandle does not support reading")
	return nil, gopacket.CaptureInfo{}, nil
}

func (h *CopyWriterHandle) receiver() error {
	// This sends out the data
	// TODO Rotate write out file
	pkt := Packet{}
	for {
		copiedData := <-h.bufferChan
		pkt.Ci = copiedData.ci
		pkt.OutBuf = copiedData.buf
		h.fh.WritePacketData(&pkt)
	}
}

func (h *CopyWriterHandle) WritePacketData(pkt *Packet) error {
	log.Debugf("Preparing to pass the packet to the other thread")
	// Write packet to file
	buf := PacketCopyBuffer{
		ci:  pkt.Ci,
		buf: pkt.OutBuf,
	}
	h.bufferChan <- buf
	return nil
}

func (h *CopyWriterHandle) Stats() IfStats {
	return IfStats{
		PktRecv: 0,
		PktDrop: 0,
	}
}

func (h *CopyWriterHandle) Close() error {
	//TODO close the channel
	h.fh.Close()
	return nil
}
