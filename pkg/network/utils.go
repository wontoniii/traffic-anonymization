package network

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
	// log "github.com/sirupsen/logrus"
)

func ParseIP(ip string) (net.IP, *net.IPNet, error) {
	return net.ParseCIDR(ip)
}

// CIDRinit fills privateIPBlocks with the CIDR ranges for RFC1918 and loopback checking
func CIDRAllInit() []*net.IPNet {
	var privateIPBlocks []*net.IPNet
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
	return privateIPBlocks
}

func CIDRIPv4Init() []*net.IPNet {
	var privateIPBlocks []*net.IPNet
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
	return privateIPBlocks
}

// isPrivateIP checks whether a net.IP is within the ranges in privateIPBlocks
func IsPrivateIP(privateIPBlocks []*net.IPNet, ip net.IP) bool {
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

var RFC1918 = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

func ToNets(strNets []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, n := range strNets {
		if _, net, err := net.ParseCIDR(n); err == nil {
			nets = append(nets, net)
		}
	}
	return nets
}

var RFC1918Nets []*net.IPNet = ToNets(RFC1918)

func IsRFC1918(ip net.IP) bool {
	for _, net := range RFC1918Nets {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

func GetFirstInterface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	iface := net.Interface{Index: -1}
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if v.IP.IsGlobalUnicast() && v.IP.To4() != nil && v.IP.String() != "1.2.3.4" {
					iface = i
				}
			}
		}
	}

	if iface.Index == -1 {
		return "", errors.New("No interface found")
	}
	return iface.Name, nil
}

func bytesToTime(data []byte) (time.Time, error) {
	if len(data) != 8 {
		return time.Time{}, fmt.Errorf("expected 8 bytes for timestamp, got %d", len(data))
	}

	nanoseconds := binary.BigEndian.Uint64(data)
	seconds := nanoseconds / 1000000000
	remainingNanos := nanoseconds % 1000000000

	return time.Unix(int64(seconds), int64(remainingNanos)), nil
}
