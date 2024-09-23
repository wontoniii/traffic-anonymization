package config

import (
	"encoding/json"
	"testing"

	"github.com/wontoniii/traffic-anonymization/pkg/utils"
)

func TestDefaultConfig(t *testing.T) {
	conf := SysConfig{}
	t.Logf("Loading config %s", utils.GetRepoPath()+"/config/config.json")
	conf.ImportConfigFromFile(utils.GetRepoPath() + "/config/config.json")
	out, _ := json.Marshal(conf)
	t.Logf("Loaded config: %s", out)
}
