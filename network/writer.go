package network

type Writer struct {
	netif *NetworkInterface
}

func NewWriter(netif *NetworkInterface) *Writer {
	w := &Writer{}
	w.netif = netif
	return w
}

func (w *Writer) ProcessPacket(pkt *Packet) error {
	w.netif.IfHandle.WritePacketData(pkt)
	return nil

}
