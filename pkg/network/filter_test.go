package network

import (
	"testing"

	"github.com/wontoniii/traffic-anonymization/pkg/utils"
)

func TestDefaultFilter(t *testing.T) {
	t.Logf("Loading config %s", utils.GetRepoPath()+"/config/zoom_bpf")
	f, _ := LoadFilter(utils.GetRepoPath() + "/config/zoom_bpf")
	t.Logf("Loaded filter: %s", f.Flt)
}
