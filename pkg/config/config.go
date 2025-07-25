// Package config is used to configure traffic refinery
package config

import (
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

type InterfaceConfig struct {
	// Driver type. Either "ring" (PF_RING) or "pcap" (PCAP) or "afpacket (AF Packet)"
	Driver string
	// Whether to use PF_RING clustering for load balancing across threads
	Clustered bool
	// ID of the cluster to use
	ClusterID int
	// How many threads to use for the interface
	ClusterN int
	// Whether to use PF_RING in Zero Copy mode. Not available if Clustered is true
	ZeroCopy bool
	// Whether to use AFPacket Fanout
	FanOut bool
	// Name of the interface to use
	Ifname string
	// Filter
	Filter string
}

type MiscConfig struct {
	Anonymize   bool
	LoopTime    int
	PrivateNets bool
	LocalNets   []string
	LogLevel    string
}

type SysConfig struct {
	InIf  []InterfaceConfig
	OutIf InterfaceConfig
	Misc  MiscConfig
}

// ImportConfigFromFile uses a conventional file named path/configName" to load the configuration
func (conf *SysConfig) ImportConfigFromFile(fileName string) {
	path, name := filepath.Split(fileName)
	if path == "" {
		path = "/opt/traffic-anonymization/config/"
	}
	extensionType := strings.TrimPrefix(filepath.Ext(fileName), ".")
	viper.SetConfigName(name)          // name of config file (without extension)
	viper.AddConfigPath(path)          // optionally look for config in the working directory
	viper.SetConfigType(extensionType) // type of configuration file based on the extension
	err := viper.ReadInConfig()        // Find and read the config file
	if err != nil {                    // Handle errors reading the config file
		panic(err)
	}
	conf.loadInterfacesConfig()
}

// loadInterfacesConfig loads the configuration from viper.
func (conf *SysConfig) loadInterfacesConfig() {
	if err := viper.UnmarshalKey("InInterfaces", &conf.InIf); err != nil {
		panic(err)
	}
	conf.OutIf.Driver = viper.GetString("OutInterface.Driver")
	conf.OutIf.Clustered = viper.GetBool("OutInterface.Clustered")
	conf.OutIf.ClusterID = viper.GetInt("OutInterface.ClusterID")
	conf.OutIf.ZeroCopy = viper.GetBool("OutInterface.ZeroCopy")
	conf.OutIf.Ifname = viper.GetString("OutInterface.Ifname")
	conf.OutIf.Filter = viper.GetString("OutInterface.Filter")
	conf.Misc.Anonymize = viper.GetBool("Misc.Anonymize")
	conf.Misc.LoopTime = viper.GetInt("Misc.LoopTime")
	conf.Misc.PrivateNets = viper.GetBool("Misc.PrivateNets")
	conf.Misc.LocalNets = viper.GetStringSlice("Misc.LocalNets")
	conf.Misc.LogLevel = viper.GetString("Misc.LogLevel")
}
