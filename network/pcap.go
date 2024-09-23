package network

import (
	"errors"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
)

type PcapHandle struct {
	Name      string
	Filter    string
	SnapLen   uint32
	ZeroCopy  bool
	Clustered bool
	ClusterID int
	FanOut    bool
	W         bool
	PHandle   *pcap.Handle
}

func (h *PcapHandle) NewPcapInterface() {

	if h.W {
		handle, err := pcap.OpenLive(h.Name, int32(h.SnapLen), true, 30*time.Second)
		if err != nil {
			log.Fatal(err)
			panic(err)
		}
		h.PHandle = handle
	} else {
		inactiveHandle, err := pcap.NewInactiveHandle(h.Name)
		if err != nil {
			log.Fatal(err)
			panic(err)
		}

		inactiveHandle.SetSnapLen(int(h.SnapLen))
		inactiveHandle.SetPromisc(true)
		inactiveHandle.SetTimeout(pcap.BlockForever)
		// inactiveHandle.SetBufferSize(1000000 * ph.BufferMb)

		h.PHandle, err = inactiveHandle.Activate()
		if err != nil {
			log.Fatal(err)
			panic(err)
		}

		if h.Filter != "" {
			f, err := LoadFilter(h.Filter)
			if err != nil {
				log.Fatal(err)
				panic(err)
			}
			log.Debugf("Using filter on interface %s: %s", h.Name, f.Flt)
			err = h.PHandle.SetBPFFilter(f.Flt)
			if err != nil {
				log.Fatal(err)
				panic(err)
			}
		}

	}

}

func (h *PcapHandle) Init(conf *HandleConfig) error {
	h.Name = conf.Name
	h.SnapLen = conf.SnapLen
	h.Filter = conf.Filter
	h.W = conf.W
	h.NewPcapInterface()
	return nil
}

func (h *PcapHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if h.ZeroCopy {
		log.Fatal("You can not read zero copy from pcap")
		return nil, gopacket.CaptureInfo{}, errors.New("You can not read zero copy from pcap")
	} else {
		log.Debugf("Preparing to read packet from pcap interface")
		return h.PHandle.ReadPacketData()
	}
}

func (h *PcapHandle) WritePacketData(pkt *Packet) error {
	err := h.PHandle.WritePacketData(pkt.RawData)
	if err != nil {
		log.Fatal(err)
	}
	return err
}

func (h *PcapHandle) Stats() IfStats {
	s, _ := h.PHandle.Stats()
	return IfStats{
		PktRecv: uint64(s.PacketsReceived),
		PktDrop: uint64(s.PacketsDropped),
	}
}

func (h *PcapHandle) Close() error {
	h.PHandle.Close()
	return nil
}
