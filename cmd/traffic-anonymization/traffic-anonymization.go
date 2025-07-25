package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/wontoniii/traffic-anonymization/pkg/anonymization"
	"github.com/wontoniii/traffic-anonymization/pkg/config"
	"github.com/wontoniii/traffic-anonymization/pkg/network"
	"github.com/wontoniii/traffic-anonymization/pkg/stats"
)

const (
	// Version is the version number of the system
	Version = "0.1"
)

func loadConfig() config.SysConfig {
	fname := flag.String("conf", "config.json", "Configuration file to load. If none is provided it looks for config.json in /opt/traffic-anonymization/config/")
	debug := flag.Bool("debug", false, "Log at debug level")
	info := flag.Bool("info", false, "Log at info level")
	warn := flag.Bool("warn", false, "Log at warn level")
	err := flag.Bool("error", false, "Log at error level")
	fatal := flag.Bool("fatal", false, "Log at fatal level")
	flag.Parse()

	formatter := &log.TextFormatter{
		FullTimestamp: true,
	}
	log.SetFormatter(formatter)

	conf := config.SysConfig{}

	conf.ImportConfigFromFile(*fname)

	if strings.ToLower(conf.Misc.LogLevel) == "debug" {
		log.SetLevel(log.DebugLevel)
	} else if strings.ToLower(conf.Misc.LogLevel) == "info" {
		log.SetLevel(log.InfoLevel)
	} else if strings.ToLower(conf.Misc.LogLevel) == "warn" {
		log.SetLevel(log.WarnLevel)
	} else if strings.ToLower(conf.Misc.LogLevel) == "error" {
		log.SetLevel(log.ErrorLevel)
	} else if strings.ToLower(conf.Misc.LogLevel) == "fatal" {
		log.SetLevel(log.FatalLevel)
	} else {
		log.SetLevel(log.FatalLevel)
	}

	if *debug {
		log.SetLevel(log.DebugLevel)
	} else if *info {
		log.SetLevel(log.InfoLevel)
	} else if *warn {
		log.SetLevel(log.WarnLevel)
	} else if *err {
		log.SetLevel(log.ErrorLevel)
	} else if *fatal {
		log.SetLevel(log.FatalLevel)
	}

	return conf
}

func main() {
	conf := loadConfig()

	outb, _ := json.Marshal(conf)
	log.Infof("Running with configuration:\n%s\n", outb)

	amodule := anonymization.NewAModule("", conf.Misc.Anonymize, conf.Misc.PrivateNets, conf.Misc.LocalNets, conf.Misc.LoopTime)

	var numInstances int = 0

	inifConfs := []config.InterfaceConfig{}

	for _, inif := range conf.InIf {
		if inif.Clustered && inif.ClusterN > 1 && inif.Driver == "ringread" {
			for i := 0; i < inif.ClusterN; i++ {
				inifConfs = append(inifConfs, config.InterfaceConfig{
					Driver:    inif.Driver,
					Clustered: inif.Clustered,
					ClusterID: inif.ClusterID,
					ClusterN:  inif.ClusterN,
					ZeroCopy:  inif.ZeroCopy,
					FanOut:    inif.FanOut,
					Ifname:    inif.Ifname,
					Filter:    inif.Filter,
				})
				numInstances++
			}
		} else {
			inifConfs = append(inifConfs, config.InterfaceConfig{
				Driver:    inif.Driver,
				Clustered: inif.Clustered,
				ClusterID: inif.ClusterID,
				ClusterN:  inif.ClusterN,
				ZeroCopy:  inif.ZeroCopy,
				FanOut:    inif.FanOut,
				Ifname:    inif.Ifname,
				Filter:    inif.Filter,
			})
			numInstances++
		}
	}

	stops := make([]chan struct{}, numInstances)
	outnis := make([]*network.NetworkInterface, numInstances)
	writers := make([]*network.Writer, numInstances)
	anonymizers := make([]*anonymization.Anonymizer, numInstances)
	innis := make([]*network.NetworkInterface, numInstances)
	readers := make([]*network.Reader, numInstances)
	statsWriters := make([]*stats.IfStatsPrinter, numInstances)

	log.Infof("Starting with %d input interface instances", numInstances)

	// Initialize each instance
	for i := 0; i < numInstances; i++ {
		outnis[i] = new(network.NetworkInterface)
		ifconf := network.NetworkInterfaceConfiguration{
			Driver:    conf.OutIf.Driver,
			Name:      conf.OutIf.Ifname,
			Filter:    conf.OutIf.Filter,
			SnapLen:   1600,
			Clustered: conf.OutIf.Clustered,
			ClusterID: conf.OutIf.ClusterID,
			ZeroCopy:  conf.OutIf.ZeroCopy,
			FanOut:    conf.OutIf.FanOut,
		}
		outnis[i].NewNetworkInterface(ifconf)

		writers[i] = network.NewWriter(outnis[i])

		anonymizers[i] = anonymization.NewAnonymizer(amodule, writers[i])

		innis[i] = new(network.NetworkInterface)

		ifconf = network.NetworkInterfaceConfiguration{
			Driver:    inifConfs[i].Driver,
			Name:      inifConfs[i].Ifname, // Make names unique
			Filter:    inifConfs[i].Filter,
			SnapLen:   1600,
			Clustered: inifConfs[i].Clustered,
			ClusterID: inifConfs[i].ClusterID,
			ZeroCopy:  inifConfs[i].ZeroCopy,
			FanOut:    inifConfs[i].FanOut,
		}

		innis[i].NewNetworkInterface(ifconf)
		readers[i] = network.NewReader(innis[i], anonymizers[i])
		statsWriters[i] = stats.NewIfStatsPrinter(innis[i], fmt.Sprintf("inif_%s_%d", ifconf.Name, i))
		statsWriters[i].Init()

		stops[i] = make(chan struct{})
		go readers[i].Parse(nil, stops[i])
		go statsWriters[i].Run()
	}

	c := make(chan os.Signal, 5)
	signal.Notify(c, os.Interrupt, syscall.SIGINT)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	log.Infof("System running")
	<-c
	for i := 0; i < numInstances; i++ {
		stops[i] <- struct{}{}
		innis[i].IfHandle.Close()
		statsWriters[i].Stop()
		outnis[i].IfHandle.Close()
	}
}
