package network

import (
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	log "github.com/sirupsen/logrus"
)

type SocketHandle struct {
	Name      string
	Filter    string
	SnapLen   uint32
	ZeroCopy  bool
	Clustered bool
	ClusterID int
	FanOut    bool
	W         bool
	conn      *net.UDPConn
	dest      *net.UDPAddr
}

func (h *SocketHandle) NewSocketInterface() {
	var err error
	ip := strings.Split(h.Name, ":")[0]
	port, _ := strconv.Atoi(strings.Split(h.Name, ":")[1])
	h.dest = &net.UDPAddr{
		Port: port,
		IP:   net.ParseIP(ip),
	}
	h.conn, err = net.DialUDP("udp", nil, h.dest)
	if err != nil {
		log.Fatalf("Could not create the socket, error: %s", err)
	}
}

func (h *SocketHandle) Init(conf *HandleConfig) error {
	h.Name = conf.Name
	h.W = conf.W
	h.NewSocketInterface()
	return nil
}

func (h *SocketHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	log.Fatal("Not implemented yet")
	return nil, gopacket.CaptureInfo{}, nil
}

func (h *SocketHandle) WritePacketData(pkt *Packet) error {
	log.Debugf("Preparing to write packet to file")
	// Write packet to socket
	c, err := h.conn.WriteToUDP(pkt.RawData, h.dest)
	if err != nil {
		log.Fatalf("Could not write the packet, error: %s", err)
	} else {
		log.Debugf("Wrote %d bytes to the socket", c)
	}
	return nil
}

func (h *SocketHandle) Stats() IfStats {
	return IfStats{
		PktRecv: 0,
		PktDrop: 0,
	}
}

func (h *SocketHandle) Close() error {
	h.conn.Close()
	return nil
}
