package convert

import (
	"errors"
	"fmt"
	"strings"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	v1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	containerCalicoNode = "calico-node"
	containerInstallCNI = "install-cni"
)

func handleNetwork(c *components, install *Installation) error {
	// TODO: be more elegant about creation of this spec field if it already exists
	if install.Spec.CalicoNetwork == nil {
		install.Spec.CalicoNetwork = &operatorv1.CalicoNetworkSpec{}
	}

	// CALICO_NETWORKING_BACKEND
	netBackend, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "CALICO_NETWORKING_BACKEND")
	if err != nil {
		return err
	}
	if netBackend != nil && *netBackend != "" && *netBackend != "bird" {
		return ErrIncompatibleCluster{"only CALICO_NETWORKING_BACKEND=bird is supported at this time"}
	}

	// Calico CNI
	if c.calicoCNIConfig == nil {
		return fmt.Errorf("no 'calico' cni conf found in CNI_NETWORK_CONFIG on install-cni")
	}

	// FELIX_DEFAULTENDPOINTTOHOSTACTION
	defaultWepAction, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "FELIX_DEFAULTENDPOINTTOHOSTACTION")
	if err != nil {
		return err
	}
	if defaultWepAction != nil && strings.ToLower(*defaultWepAction) != "accept" {
		return ErrIncompatibleCluster{
			fmt.Sprintf("unexpected FELIX_DEFAULTENDPOINTTOHOSTACTION: '%s'. Only 'accept' is supported.", *defaultWepAction),
		}
	}

	// IP
	ipMethod, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "IP")
	if err != nil {
		return err
	}
	if ipMethod != nil && strings.ToLower(*ipMethod) != "autodetect" {
		return ErrIncompatibleCluster{
			fmt.Sprintf("unexpected IP value: '%s'. Only 'autodetect' is supported.", *ipMethod),
		}
	}

	// IP_AUTODETECTION_METHOD
	am, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "IP_AUTODETECTION_METHOD")
	if err != nil {
		return err
	}
	if am != nil {
		tam, err := getAutoDetection(*am)
		if err != nil {
			return ErrIncompatibleCluster{"error parsing IP_AUTODETECTION_METHOD: " + err.Error()}
		}
		install.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = &tam
	}

	// CNI portmap plugin
	if _, ok := c.pluginCNIConfig["portmap"]; ok {
		hp := v1.HostPortsEnabled
		install.Spec.CalicoNetwork.HostPorts = &hp
	} else {
		hp := v1.HostPortsDisabled
		install.Spec.CalicoNetwork.HostPorts = &hp
	}

	if c.calicoCNIConfig == nil {
		// TODO: don't return an error once we support this, instead just returning nil.
		return ErrIncompatibleCluster{"operator does not yet support running without calico CNI"}
	}

	if c.calicoCNIConfig.MTU == -1 {
		// if MTU is -1, we assume it was us who replaced it when doing initial CNI
		// config loading. We need to pull it from the correct source
		mtu, err := c.node.getEnv(ctx, c.client, containerInstallCNI, "CNI_MTU")
		if err != nil {
			return err
		}
		if mtu != nil {
			i := intstr.FromString(*mtu)
			iv := int32(i.IntValue())
			install.Spec.CalicoNetwork.MTU = &iv
		}
	} else {
		// user must have hardcoded their CNI instead of using our cni templating engine.
		// use the hardcoded value.
		mtu := int32(c.calicoCNIConfig.MTU)
		install.Spec.CalicoNetwork.MTU = &mtu
	}

	// CNI IPAM pools
	if len(c.calicoCNIConfig.IPAM.IPv4Pools) != 0 {
		return ErrIncompatibleCluster{"specifying ipv4_pools in cni config is not supported."}
	}

	// Other CNI features
	if c.calicoCNIConfig.FeatureControl.FloatingIPs {
		return ErrIncompatibleCluster{"floating IPs not supported"}
	}
	if c.calicoCNIConfig.FeatureControl.IPAddrsNoIpam {
		return ErrIncompatibleCluster{"IpAddrsNoIpam not supported"}
	}

	return nil
}

// getAutoDetection auto-detects the IP and Network using the requested
// detection method.
func getAutoDetection(method string) (operatorv1.NodeAddressAutodetection, error) {
	const (
		AUTODETECTION_METHOD_FIRST          = "first-found"
		AUTODETECTION_METHOD_CAN_REACH      = "can-reach="
		AUTODETECTION_METHOD_INTERFACE      = "interface="
		AUTODETECTION_METHOD_SKIP_INTERFACE = "skip-interface="
	)

	// first-found
	if method == "" || method == AUTODETECTION_METHOD_FIRST {
		var t = true
		return operatorv1.NodeAddressAutodetection{FirstFound: &t}, nil
	}

	// interface
	if strings.HasPrefix(method, AUTODETECTION_METHOD_INTERFACE) {
		ifStr := strings.TrimPrefix(method, AUTODETECTION_METHOD_INTERFACE)
		return operatorv1.NodeAddressAutodetection{Interface: ifStr}, nil
	}

	// can-reach
	if strings.HasPrefix(method, AUTODETECTION_METHOD_CAN_REACH) {
		dest := strings.TrimPrefix(method, AUTODETECTION_METHOD_CAN_REACH)
		return operatorv1.NodeAddressAutodetection{CanReach: dest}, nil
	}

	// skip-interface
	if strings.HasPrefix(method, AUTODETECTION_METHOD_SKIP_INTERFACE) {
		ifStr := strings.TrimPrefix(method, AUTODETECTION_METHOD_SKIP_INTERFACE)
		return operatorv1.NodeAddressAutodetection{SkipInterface: ifStr}, nil
	}

	return operatorv1.NodeAddressAutodetection{}, errors.New("unrecognized method: " + method)
}
