package network

import (
	"errors"
	"net"

	"github.com/google/gopacket"
)

const (
	HandleTypePFRingRead          = 0
	HandleTypePcapRead            = 1
	HandleTypeAFPacketRead        = 2
	HandleTypeFileRead            = 3
	HandleTypePFRingWrite         = 4
	HandleTypePcapWrite           = 5
	HandleTypeAFPacketWrite       = 6
	HandleTypeFileWrite           = 7
	HandleTypeSocketRead          = 8
	HandleTypeSocketWrite         = 9
	HandleTypeSocketBufferedWrite = 10
	HandleTypeFileBufferedWrite   = 11
)

// BPF Filter for capturing DNS traffic only
const DNSFilter = "udp and port 53"

// BPF Filter for capturing DNS all traffic but DNS
// const NotDNSFilter = "tcp or (udp and not port 53)"
const NotDNSFilter = "tcp or (udp and not port 53)"

// NetworkInterfaceConfiguration is a support structure used to configure an interface
type NetworkInterfaceConfiguration struct {
	// name, filter, mode string, snaplen uint32
	Driver    string
	Name      string
	Filter    string
	SnapLen   uint32
	Clustered bool
	ClusterID int
	ZeroCopy  bool
	FanOut    bool
}

// NetworkInterface is a structure that carries information on the interface it maps to
// and pointers to the underlying packet processing tool (PFRing or Pcap)
type NetworkInterface struct {
	Mode       string
	Name       string
	HwAddr     net.HardwareAddr
	LocalNetv4 net.IPNet
	LocalNetv6 net.IPNet
	HandleType uint8
	IfHandle   Handle
}

func getMacFromName(name string) (net.HardwareAddr, net.IPNet, net.IPNet) {
	var hardwareAddr net.HardwareAddr
	var localNetv4, localNetv6 net.IPNet
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	// handle err
	for _, i := range ifaces {
		if i.Name == name {
			addrs, _ := i.Addrs()
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					if v.IP.IsGlobalUnicast() && v.IP.To4() != nil {
						localNetv4 = *v
					} else if v.IP.IsGlobalUnicast() && v.IP.To16() != nil {
						localNetv6 = *v
					}
				}
			}

			hardwareAddr = i.HardwareAddr
			break
		}
	}
	return hardwareAddr, localNetv4, localNetv6
}

func (ni *NetworkInterface) NewNetworkInterface(conf NetworkInterfaceConfiguration) {
	ni.Name = conf.Name

	// Get MAC address of interface in use
	ni.HwAddr, ni.LocalNetv4, ni.LocalNetv6 = getMacFromName(ni.Name)

	hc := HandleConfig{
		Name:      conf.Name,
		Filter:    conf.Filter,
		SnapLen:   conf.SnapLen,
		Clustered: conf.Clustered,
		ClusterID: conf.ClusterID,
		ZeroCopy:  conf.ZeroCopy,
		FanOut:    conf.FanOut,
	}

	// Initiate the interface based on type
	if conf.Driver == "pcapread" {
		ni.HandleType = HandleTypePcapRead
		ni.IfHandle = &PcapHandle{}
		hc.W = false
	} else if conf.Driver == "ringread" {
		ni.HandleType = HandleTypePFRingRead
		ni.IfHandle = &RingHandle{}
		hc.W = false
	} else if conf.Driver == "afpacketread" {
		ni.HandleType = HandleTypeAFPacketRead
		ni.IfHandle = &AFHandle{}
		hc.W = false
	} else if conf.Driver == "pcapwrite" {
		ni.HandleType = HandleTypePcapWrite
		ni.IfHandle = &PcapHandle{}
		hc.W = true
	} else if conf.Driver == "ringwrite" {
		ni.HandleType = HandleTypePFRingWrite
		ni.IfHandle = &RingHandle{}
		hc.W = true
	} else if conf.Driver == "afpacketwrite" {
		ni.HandleType = HandleTypeAFPacketWrite
		ni.IfHandle = &AFHandle{}
		hc.W = true
	} else if conf.Driver == "fileread" {
		ni.HandleType = HandleTypeFileRead
		ni.IfHandle = &FileHandle{}
		hc.W = false
	} else if conf.Driver == "filewrite" {
		ni.HandleType = HandleTypeFileWrite
		ni.IfHandle = &FileHandle{}
		hc.W = true
	} else if conf.Driver == "socketread" {
		ni.HandleType = HandleTypeSocketRead
		hc.W = false
	} else if conf.Driver == "socketwrite" {
		ni.HandleType = HandleTypeSocketWrite
		ni.IfHandle = &SocketHandle{}
		hc.W = true
	} else if conf.Driver == "socketbufferedwrite" {
		ni.HandleType = HandleTypeSocketBufferedWrite
		ni.IfHandle = &CopySenderHandle{}
		hc.W = true
	} else if conf.Driver == "filebufferedwrite" {
		ni.HandleType = HandleTypeFileBufferedWrite
		ni.IfHandle = &CopyWriterHandle{}
		hc.W = true
	} else {
		panic(errors.New("wrong interface driver type"))
	}
	ni.IfHandle.Init(&hc)

}

func (ni *NetworkInterface) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return ni.IfHandle.ReadPacketData()
}
