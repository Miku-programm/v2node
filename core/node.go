package core

import (
	"fmt"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/probelog"
)

func (v *V2Core) AddNode(tag string, info *panel.NodeInfo) error {
	inBoundConfig, err := buildInbound(info, tag)
	if err != nil {
		return fmt.Errorf("build inbound error: %s", err)
	}
	err = v.addInbound(inBoundConfig)
	if err != nil {
		return fmt.Errorf("add inbound error: %s", err)
	}
	security := "none"
	switch info.Security {
	case panel.Tls:
		security = "tls"
	case panel.Reality:
		security = "reality"
	}
	probelog.RegisterNode(probelog.NodePort{
		Tag:      tag,
		Type:     info.Type,
		Security: security,
		UDP:      info.Type == "hysteria2" || info.Type == "tuic",
		Port:     uint16(info.Common.ServerPort),
	})
	return nil
}

func (v *V2Core) DelNode(tag string) error {
	probelog.UnregisterNode(tag)
	err := v.removeInbound(tag)
	if err != nil {
		return fmt.Errorf("remove in error: %s", err)
	}
	return nil
}
