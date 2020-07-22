package convert

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/containernetworking/cni/libcni"
)

// loadCNI loads CNI config into the components for all other handlers to use.
// No verification is done here beyond checking for valid json.
func loadCNI(c *components) error {
	cniConfig, err := c.node.getEnv(ctx, c.client, containerInstallCNI, "CNI_NETWORK_CONFIG")
	if err != nil {
		if IsContainerNotFound(err) {
			// It is valid to not have an install-cni container in the cases
			// of non Calico CNI so nothing more to do in that case.
			log.Print("no install-cni container detected on node")
			return nil
		}
		return err
	}
	if cniConfig == nil {
		log.Print("no CNI_NETWORK_CONFIG detected on node")
		return nil
	}

	conflist, err := unmarshalCNIConfList(*cniConfig)
	if err != nil {
		return fmt.Errorf("failed to parse CNI config: %w", err)
	}

	// convert to a map for simpler checks
	plugins := map[string]*libcni.NetworkConfig{}
	for _, plugin := range conflist.Plugins {
		if plugin.Network.Type == "calico" {
			if err := json.Unmarshal(plugin.Bytes, &c.calicoCNIConfig); err != nil {
				return fmt.Errorf("failed to parse calico cni config: %w", err)
			}
		} else {
			plugins[plugin.Network.Type] = plugin
		}
	}

	return nil
}

func unmarshalCNIConfList(cniConfig string) (*libcni.NetworkConfigList, error) {
	// unrendered CNI_NETWORK_CONFIG is often technically invalid json because it uses
	// __CNI_MTU__ as an integer, e.g. { "mtu": __CNI_MTU__ }
	// in such cases, replace it with a placeholder, so that we can json load it, and still
	// know that it should be substituted later during validation.
	if strings.Contains(cniConfig, "__CNI_MTU__") {
		cniConfig = strings.Replace(cniConfig, "__CNI_MTU__", "-1", -1)
	}

	confList, err := libcni.ConfListFromBytes([]byte(cniConfig))
	if err == nil {
		return confList, nil
	}

	// if an error occured, try parsing it as a single item
	conf, err := libcni.ConfFromBytes([]byte(cniConfig))
	if err != nil {
		return nil, err
	}

	return libcni.ConfListFromConf(conf)
}
