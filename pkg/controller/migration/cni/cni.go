package cni

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/pkg/types"
	calicocni "github.com/projectcalico/cni-plugin/pkg/types"
)

type NetworkComponents struct {
	ConfigName          string
	CalicoConfig        *calicocni.NetConf
	HostLocalIPAMConfig *HostLocalIPAMConfig

	// other CNI plugins in the conflist.
	Plugins map[string]*libcni.NetworkConfig
}

// IPAMConfig represents the IP related network configuration.
// This nests Range because we initially only supported a single
// range directly, and wish to preserve backwards compatability
type HostLocalIPAMConfig struct {
	*Range
	Name       string
	Type       string         `json:"type"`
	Routes     []*types.Route `json:"routes"`
	DataDir    string         `json:"dataDir"`
	ResolvConf string         `json:"resolvConf"`
	Ranges     []RangeSet     `json:"ranges"`
	IPArgs     []net.IP       `json:"-"` // Requested IPs from CNI_ARGS and args
}

type RangeSet []Range

type Range struct {
	RangeStart string `json:"rangeStart,omitempty"` // The first ip, inclusive
	RangeEnd   string `json:"rangeEnd,omitempty"`   // The last ip, inclusive
	Subnet     string `json:"subnet"`
	Gateway    net.IP `json:"gateway,omitempty"`
}

// Parse loads CNI config into the components for all other handlers to use.
// No verification is done here beyond checking for valid json.
// Calico CNI is parsed into the special Calico CNI data type.
// All other CNI types
func Parse(cniConfig string) (NetworkComponents, error) {
	c := NetworkComponents{}

	conflist, err := unmarshalCNIConfList(cniConfig)
	if err != nil {
		return c, fmt.Errorf("failed to parse CNI config: %w", err)
	}

	c.ConfigName = conflist.Name

	// convert to a map for simpler checks
	plugins := map[string]*libcni.NetworkConfig{}
	for _, plugin := range conflist.Plugins {
		if plugin.Network.Type == "calico" {
			if err := json.Unmarshal(plugin.Bytes, &c.CalicoConfig); err != nil {
				return c, fmt.Errorf("failed to parse calico cni config: %w", err)
			}
			if plugin.Network.IPAM.Type == "host-local" {
				// First load the IPAM json section so we can Unmarshal it below.
				// We load the IPAM as raw json so we can isolate it from the rest of the
				// CNI config.
				var raw struct {
					IPAM json.RawMessage `json:"ipam"`
				}
				if err := json.Unmarshal(plugin.Bytes, &raw); err != nil {
					return c, fmt.Errorf("failed to parse cni config for raw IPAM: %w", err)
				}

				// Use a Decoder so we can set DisallowUnknownFields so if there are
				// any unknown fields we will detect that.
				x := HostLocalIPAMConfig{}
				dec := json.NewDecoder(bytes.NewReader(raw.IPAM))
				dec.DisallowUnknownFields()
				if err := dec.Decode(&x); err != nil && err != io.EOF {
					return c, fmt.Errorf("failed to parse HostLocal IPAM config: %w", err)
				}
				c.HostLocalIPAMConfig = &x
			}
		} else {
			plugins[plugin.Network.Type] = plugin
		}
	}
	c.Plugins = plugins

	return c, nil
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
