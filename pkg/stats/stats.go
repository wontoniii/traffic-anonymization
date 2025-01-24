package stats

import (
	"encoding/json"
	"io/ioutil"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wontoniii/traffic-anonymization/pkg/network"
)

type IfStatsPrinter struct {
	Interface *network.NetworkInterface
	lastTime  int64
	end       chan bool
}

type ParserStats struct {
	Name    string
	PktRecv uint64
	PktDrop uint64
}

type OutJson struct {
	Version string
	Conf    string
	Type    string
	TsStart int64
	TsEnd   int64
	Data    json.RawMessage
}

func NewIfStatsPrinter(inter *network.NetworkInterface) *IfStatsPrinter {
	cp := new(IfStatsPrinter)
	cp.Interface = inter
	return cp
}

func (cp *IfStatsPrinter) Type() string {
	return "IfStatsPrinter"
}

func (cp *IfStatsPrinter) Init() error {
	cp.lastTime = time.Now().Unix()
	return nil
}

func (cp *IfStatsPrinter) Generate() []byte {
	endTime := time.Now().Unix()
	s := cp.Interface.IfHandle.Stats()

	parsersData, _ := json.Marshal(ParserStats{
		Name:    cp.Interface.Name,
		PktRecv: s.PktRecv,
		PktDrop: s.PktDrop,
	})

	outJson := OutJson{
		Version: "0.1",
		Conf:    "--",
		Type:    cp.Type(),
		TsStart: cp.lastTime,
		TsEnd:   endTime,
		Data:    parsersData,
	}

	cp.lastTime = endTime

	b, _ := json.Marshal(outJson)
	return b
}

func (cp *IfStatsPrinter) Run() {
	cp.end = make(chan bool, 1)
	ticker := time.NewTicker(time.Duration(1 * time.Minute))
	for {
		select {
		case <-cp.end:
			return
		case <-ticker.C:
			s := cp.Generate()
			err := ioutil.WriteFile("/tmp/ta_ifstats.out", s, 0644)
			if err != nil {
				log.Fatalf("Something went wrong writing statistics: %", err)
			}
		}
	}
}

func (cp *IfStatsPrinter) Stop() {
	cp.end <- true
}
