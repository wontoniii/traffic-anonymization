package network

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	log "github.com/sirupsen/logrus"
)

const CYCLE_TIME time.Duration = time.Second * 60

type CopyWriterHandle struct {
	// fh1        *FileHandle
	// fh2        *FileHandle
	basename    string
	configCopy  HandleConfig
	current     int
	bufferChans []chan PacketCopyBuffer
	stopChans   []chan bool
	swapChans   []chan bool
	wg          sync.WaitGroup
	deadline    time.Time
}

type PacketCopyBuffer struct {
	ci  gopacket.CaptureInfo
	buf gopacket.SerializeBuffer
}

func (h *CopyWriterHandle) Init(conf *HandleConfig) error {
	h.configCopy = *conf
	h.basename = strings.Split(conf.Name, ".")[0]
	h.wg.Add(2)
	h.stopChans = make([]chan bool, 2)
	h.stopChans[0] = make(chan bool)
	h.stopChans[1] = make(chan bool)
	h.swapChans = make([]chan bool, 2)
	h.swapChans[0] = make(chan bool)
	h.swapChans[1] = make(chan bool)
	h.bufferChans = make([]chan PacketCopyBuffer, 2)
	h.bufferChans[0] = make(chan PacketCopyBuffer, 32768)
	h.bufferChans[1] = make(chan PacketCopyBuffer, 32768)
	h.current = 0
	h.deadline = time.Now().Add(CYCLE_TIME)
	go h.receiver(0, 0)
	go h.receiver(1, CYCLE_TIME)
	return nil
}

func (h *CopyWriterHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	log.Fatal("CopyWriterHandle does not support reading")
	return nil, gopacket.CaptureInfo{}, nil
}

func (h *CopyWriterHandle) receiver(id, delay time.Duration) error {
	// This sends out the data
	// TODO Rotate write out file every hour
	defer h.wg.Done()
	pkt := Packet{}
	now := time.Now()
	now = now.Add(delay)
	config := h.configCopy
	config.Name = h.basename + "_" + now.Format("2006-01-02_15:04:05")
	fh := &FileHandle{}
	fh.Init(&config)
	for {
		select {
		case <-h.stopChans[id]:
			for {
				select {
				case copiedData, ok := <-h.bufferChans[id]:
					if !ok {
						// Channel is closed
						log.Panicf("Unexpected close channel for receiver")
					}
					// Process the value if needed
					log.Debugf("Read packet, write out")
					pkt.Ci = copiedData.ci
					pkt.OutBuf = copiedData.buf
					fh.WritePacketData(&pkt)
				default:
					// Channel is empty, get ready for new packets
					fh.Close()
					return nil
				}
			}
		case <-h.swapChans[id]:
			// Drain the packets in the channel
			for {
				select {
				case copiedData, ok := <-h.bufferChans[id]:
					if !ok {
						// Channel is closed
						log.Panic("Unexpected close channel for receiver")
					}
					// Process the value if needed
					log.Debugf("Read packet, write out")
					pkt.Ci = copiedData.ci
					pkt.OutBuf = copiedData.buf
					fh.WritePacketData(&pkt)
				default:
					// Channel is empty, prepare new pcap file for the future
					fh.Close()
					err := os.Rename(config.Name, config.Name+".pcap")
					if err != nil {
						log.Panic("Error renaming file:", err)
					}
					now := time.Now()
					now = now.Add(delay)
					config.Name = h.basename + "_" + now.Format("2006-01-02_15:04:05")
					fh := &FileHandle{}
					fh.Init(&config)
					break
				}
			}

		// New packet received
		case copiedData := <-h.bufferChans[id]:
			log.Debugf("Read packet, write out")
			pkt.Ci = copiedData.ci
			pkt.OutBuf = copiedData.buf
			fh.WritePacketData(&pkt)
		}

	}
}

func (h *CopyWriterHandle) WritePacketData(pkt *Packet) error {
	log.Debugf("Preparing to pass the packet to the other thread")
	//TODO Handle timer to swap where to write
	now := time.Now()
	if now.After(h.deadline) {
		h.swapChans[h.current] <- true
		h.current = (h.current + 1) % 2
		h.deadline = now.Add(CYCLE_TIME)
	}
	// Write packet to file
	buf := PacketCopyBuffer{
		ci:  pkt.Ci,
		buf: pkt.OutBuf,
	}
	h.bufferChans[h.current] <- buf
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
	h.stopChans[0] <- true
	h.stopChans[1] <- true
	return nil
}
