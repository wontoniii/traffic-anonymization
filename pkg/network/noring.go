//go:build !pfring
// +build !pfring

package network

import "github.com/google/gopacket"

type RingHandle struct {
}

func (h *RingHandle) Init(conf *HandleConfig) error {
	panic("No pfring package available")
}

func (h *RingHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	panic("No pfring package available")
}

func (h *RingHandle) WritePacketData(pkt *Packet) error {
	panic("Not implemented")
}

func (h *RingHandle) Stats() IfStats {
	panic("No afpacket package available")
}

func (h *RingHandle) Close() error {
	panic("No afpacket package available")
}
