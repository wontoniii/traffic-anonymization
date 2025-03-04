package main

import (
	"encoding/json"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"

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

	inni := new(network.NetworkInterface)
	ifconf := network.NetworkInterfaceConfiguration{
		Driver:    conf.InIf.Driver,
		Name:      conf.InIf.Ifname,
		Filter:    conf.InIf.Filter,
		SnapLen:   1600,
		Clustered: conf.InIf.Clustered,
		ClusterID: conf.InIf.ClusterID,
		ZeroCopy:  conf.InIf.ZeroCopy,
		FanOut:    conf.InIf.FanOut,
	}
	inni.NewNetworkInterface(ifconf)

	outni := new(network.NetworkInterface)
	ifconf = network.NetworkInterfaceConfiguration{
		Driver:    conf.OutIf.Driver,
		Name:      conf.OutIf.Ifname,
		Filter:    conf.OutIf.Filter,
		SnapLen:   1600,
		Clustered: conf.OutIf.Clustered,
		ClusterID: conf.OutIf.ClusterID,
		ZeroCopy:  conf.OutIf.ZeroCopy,
		FanOut:    conf.OutIf.FanOut,
	}
	outni.NewNetworkInterface(ifconf)

	writer := network.NewWriter(outni)
	anonymizer := network.NewDecapsulateModule(writer)

	reader := network.NewReader(inni, anonymizer)
	statsWriter := stats.NewIfStatsPrinter(inni, "inif")
	statsWriter.Init()

	stop := make(chan struct{})
	go reader.Parse(nil, stop)
	go statsWriter.Run()

	c := make(chan os.Signal, 5)
	signal.Notify(c, os.Interrupt, syscall.SIGINT)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	log.Infof("System running")
	<-c
	stop <- struct{}{}
	inni.IfHandle.Close()
	outni.IfHandle.Close()
	statsWriter.Stop()
}
