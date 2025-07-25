package config

import (
	"encoding/json"
	"testing"

	"github.com/wontoniii/traffic-anonymization/pkg/utils"
)

func TestDefaultConfig(t *testing.T) {
	conf := SysConfig{}
	t.Logf("Loading config %s", utils.GetRepoPath()+"/config/config_nonan.json")
	conf.ImportConfigFromFile(utils.GetRepoPath() + "/config/config_nonan.json")
	out, _ := json.Marshal(conf)
	t.Logf("Loaded config: %s", out)
}

func TestEnsConfig(t *testing.T) {
	conf := SysConfig{}
	t.Logf("Loading config %s", utils.GetRepoPath()+"/config/config_an_ens_if1.json")
	conf.ImportConfigFromFile(utils.GetRepoPath() + "/config/config_an_ens_if1.json")
	out, _ := json.Marshal(conf)
	t.Logf("Loaded config: %s", out)
}
