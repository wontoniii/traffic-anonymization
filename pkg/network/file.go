package network

import (
	"errors"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	log "github.com/sirupsen/logrus"
)

type FileHandle struct {
	Name      string
	Filter    string
	SnapLen   uint32
	ZeroCopy  bool
	Clustered bool
	ClusterID int
	FanOut    bool
	W         bool
	F         *os.File
	FHandleR  *pcapgo.NgReader
	FHandleW  *pcapgo.NgWriter
}

func (h *FileHandle) NewFileInterface() {
	var err error
	if h.W {
		h.F, err = os.Create(h.Name)
		if err != nil {
			panic(err)
		}

		h.FHandleW, err = pcapgo.NewNgWriter(h.F, layers.LinkTypeEthernet)
		if err != nil {
			panic(err)
		}
	} else {
		h.F, err = os.Open(h.Name)
		if err != nil {
			panic(err)
		}

		h.FHandleR, err = pcapgo.NewNgReader(h.F, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			panic(err)
		}
	}

}

func (h *FileHandle) Init(conf *HandleConfig) error {
	h.Name = conf.Name
	h.SnapLen = conf.SnapLen
	h.Filter = conf.Filter
	h.W = conf.W
	h.NewFileInterface()
	return nil
}

func (h *FileHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if h.ZeroCopy {
		log.Fatal("You can not read zero copy from pcap")
		return nil, gopacket.CaptureInfo{}, errors.New("You can not read zero copy from pcap")
	} else {
		return h.FHandleR.ReadPacketData()
	}
}

func (h *FileHandle) WritePacketData(pkt *Packet) error {
	log.Debugf("Preparing to write packet to file")
	// Write packet to file
	pkt.Ci.InterfaceIndex = 0
	pkt.Ci.CaptureLength = len(pkt.OutBuf.Bytes())
	err := h.FHandleW.WritePacket(pkt.Ci, pkt.OutBuf.Bytes())
	if err != nil {
		log.Fatalf("Could not write the packet, error: %s", err)
		panic(err)
	}
	return nil
}

func (h *FileHandle) Stats() IfStats {
	return IfStats{
		PktRecv: 0,
		PktDrop: 0,
	}
}

func (h *FileHandle) Close() error {
	if h.W {
		h.FHandleW.Flush()
	}
	h.F.Close()
	return nil
}
