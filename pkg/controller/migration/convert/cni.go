package convert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

// Used to parse the IPAM section out of the full CNI configuration
type CNIHostLocalIPAM struct {
	IPAM json.RawMessage `json:"ipam"`
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

// loadCNI loads CNI config into the components for all other handlers to use.
// No verification is done here beyond checking for valid json.
func loadCNI(c *components) error {

	cntnr := getContainer(c.node.Spec.Template.Spec, containerInstallCNI)
	if cntnr == nil {
		// It is valid to not have an install-cni container in the cases
		// of non Calico CNI so nothing more to do in that case.
		log.Info("no install-cni container detected on node")
		return nil
	}

	cniConfig, err := c.node.getEnv(ctx, c.client, containerInstallCNI, "CNI_NETWORK_CONFIG")
	if err != nil {
		return err
	}
	if cniConfig == nil {
		log.Info("no CNI_NETWORK_CONFIG detected on node")
		return nil
	}

	conflist, err := unmarshalCNIConfList(*cniConfig)
	if err != nil {
		return fmt.Errorf("failed to parse CNI config: %w", err)
	}

	c.cniConfigName = conflist.Name

	// convert to a map for simpler checks
	plugins := map[string]*libcni.NetworkConfig{}
	for _, plugin := range conflist.Plugins {
		if plugin.Network.Type == "calico" {
			if err := json.Unmarshal(plugin.Bytes, &c.calicoCNIConfig); err != nil {
				return fmt.Errorf("failed to parse calico cni config: %w", err)
			}
			if plugin.Network.IPAM.Type == "host-local" {
				// First load the IPAM json section so we can Unmarshal it below.
				// We load the IPAM as raw json so we can isolate it from the rest of the
				// CNI config.
				raw := CNIHostLocalIPAM{}
				if err := json.Unmarshal(plugin.Bytes, &raw); err != nil {
					return fmt.Errorf("failed to parse cni config for raw IPAM: %w", err)
				}

				// Use a Decoder so we can set DisallowUnknownFields so if there are
				// any unknown fields we will detect that.
				x := HostLocalIPAMConfig{}
				dec := json.NewDecoder(bytes.NewReader(raw.IPAM))
				dec.DisallowUnknownFields()
				if err := dec.Decode(&x); err != nil && err != io.EOF {
					return fmt.Errorf("failed to parse HostLocal IPAM config: %w", err)
				}
				c.hostLocalIPAMConfig = &x
			}
		} else {
			plugins[plugin.Network.Type] = plugin
		}
	}
	c.pluginCNIConfig = plugins
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

func JSONBytesEqual(a, b []byte) (bool, error) {
	var j, j2 interface{}
	if err := json.Unmarshal(a, &j); err != nil {
		return false, err
	}
	if err := json.Unmarshal(b, &j2); err != nil {
		return false, err
	}
	return reflect.DeepEqual(j2, j), nil
}
