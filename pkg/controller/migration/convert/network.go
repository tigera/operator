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

	// Verify FELIX_DEFAULTENDPOINTTOHOSTACTION is set to Accept because that is what the operator sets it to.
	defaultWepAction, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "FELIX_DEFAULTENDPOINTTOHOSTACTION")
	if err != nil {
		return err
	}
	if defaultWepAction != nil && strings.ToLower(*defaultWepAction) != "accept" {
		return ErrIncompatibleCluster{
			fmt.Sprintf("unexpected FELIX_DEFAULTENDPOINTTOHOSTACTION: '%s'. Only 'accept' is supported.", *defaultWepAction),
		}
	}

	return nil
}

func handleCalicoCNI(c *components, install *Installation) error {
	plugin, err := getCNIPlugin(c)
	if err != nil {
		return err
	}
	if plugin != operatorv1.PluginCalico {
		return nil
	}

	errCtx := fmt.Sprintf("detected %s CNI plugin", plugin)

	// CALICO_NETWORKING_BACKEND
	netBackend, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "CALICO_NETWORKING_BACKEND")
	if err != nil {
		return err
	}

	if netBackend != nil && *netBackend != "" && *netBackend != "bird" {
		return ErrIncompatibleCluster{fmt.Sprintf("%s, only CALICO_NETWORKING_BACKEND=bird is supported at this time", errCtx)}
	}

	// Calico CNI
	if c.calicoCNIConfig == nil {
		return ErrIncompatibleCluster{fmt.Sprintf("%s, required cni config was not found ", errCtx)}
	}

	if install.Spec.CNI == nil {
		install.Spec.CNI = &operatorv1.CNISpec{}
	}
	install.Spec.CNI.Type = plugin

	if install.Spec.CalicoNetwork == nil {
		install.Spec.CalicoNetwork = &operatorv1.CalicoNetworkSpec{}
	}

	// IP
	ipMethod, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "IP")
	if err != nil {
		return err
	}
	if ipMethod != nil && strings.ToLower(*ipMethod) != "autodetect" {
		return ErrIncompatibleCluster{
			fmt.Sprintf("%s, unexpected IP value: '%s'. Only 'autodetect' is supported.", errCtx, *ipMethod),
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
			return ErrIncompatibleCluster{fmt.Sprintf("%s, error parsing IP_AUTODETECTION_METHOD: %s", errCtx, err.Error())}
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

func handleNonCalicoCNI(c *components, install *Installation) error {
	plugin, err := getCNIPlugin(c)
	if err != nil {
		return err
	}
	if plugin == operatorv1.PluginCalico {
		return nil
	}

	errCtx := fmt.Sprintf("detected %s CNI plugin", plugin)

	icc := getContainer(c.node.Spec.Template.Spec, containerInstallCNI)
	if icc != nil {
		return ErrIncompatibleCluster{
			fmt.Sprintf("%s, %s container is not supported in the node daemonset", errCtx, containerInstallCNI),
		}
	}

	// CALICO_NETWORKING_BACKEND
	netBackend, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "CALICO_NETWORKING_BACKEND")
	if err != nil {
		return err
	}
	if netBackend == nil || *netBackend != "none" {
		return ErrIncompatibleCluster{fmt.Sprintf("%s, CALICO_NETWORKING_BACKEND=none is expected", errCtx)}
	}

	if install.Spec.CNI == nil {
		install.Spec.CNI = &operatorv1.CNISpec{}
	}

	switch plugin {
	case operatorv1.PluginAmazonVPC:
		install.Spec.CNI.Type = plugin
		// Verify FELIX_IPTABLESMANGLEALLOWACTION is set to Return because the operator will set it to Return
		// when configured with PluginAmazonVPC. The value is also expected to be necessary for Calico policy
		// to correctly function with the AmazonVPC plugin.
		mangleAllow, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "FELIX_IPTABLESMANGLEALLOWACTION")
		if err != nil {
			return err
		}
		if mangleAllow == nil {
			return ErrIncompatibleCluster{fmt.Sprintf("%s, FELIX_IPTABLESMANGLEALLOWACTION was unset, expected it to be 'Return'.", errCtx)}
		} else if *mangleAllow != "Return" {
			return ErrIncompatibleCluster{fmt.Sprintf("%s, FELIX_IPTABLESMANGLEALLOWACTION was %s, expected it to be 'Return'.", errCtx, *mangleAllow)}
		}
	case operatorv1.PluginAzureVNET:
		install.Spec.CNI.Type = plugin
	case operatorv1.PluginGKE:
		install.Spec.CNI.Type = plugin
		// Verify FELIX_IPTABLESMANGLEALLOWACTION is set to Return because the operator will set it to Return
		// when configured with PluginGKE. The value is also expected to be necessary for Calico policy
		// to correctly function with the GKE plugin.
		mangleAllow, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "FELIX_IPTABLESMANGLEALLOWACTION")
		if err != nil {
			return err
		}
		if mangleAllow == nil {
			return ErrIncompatibleCluster{fmt.Sprintf("%s, FELIX_IPTABLESMANGLEALLOWACTION was unset, expected it to be 'Return'.", errCtx)}
		} else if *mangleAllow != "Return" {
			return ErrIncompatibleCluster{fmt.Sprintf("%s, FELIX_IPTABLESMANGLEALLOWACTION was %s, expected it to be 'Return'.", errCtx, *mangleAllow)}
		}

		// Verify FELIX_IPTABLESFILTERALLOWACTION is set to Return because the operator will set it to Return
		// when configured with PluginGKE. The value is also expected to be necessary for Calico policy
		// to correctly function with the GKE plugin.
		filterAllow, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "FELIX_IPTABLESFILTERALLOWACTION")
		if err != nil {
			return err
		}
		if filterAllow == nil {
			return ErrIncompatibleCluster{fmt.Sprintf("%s, FELIX_IPTABLESFILTERALLOWACTION was unset, expected it to be 'Return'.", errCtx)}
		} else if *filterAllow != "Return" {
			return ErrIncompatibleCluster{fmt.Sprintf("%s, FELIX_IPTABLESFILTERALLOWACTION was set to %s, expected it to be 'Return'.", errCtx, *filterAllow)}
		}
	default:
		return ErrIncompatibleCluster{
			fmt.Sprintf("unable to migrate plugin '%s': unsupported.", plugin),
		}
	}

	// TODO: Handle configuration with IPs and Pools specified.
	// We need to relax the restriction on CalicoNetwork and non-Calico CNI to do this.

	ip, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "IP")
	if err != nil {
		return err
	}
	if ip != nil && *ip != "" {
		return ErrIncompatibleCluster{fmt.Sprintf("%s, IP was set to %s, it is only supported as empty or unset with non-Calico CNI.", errCtx, *ip)}
	}

	dp, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "NO_DEFAULT_POOLS")
	if err != nil {
		return err
	}
	if dp != nil && *dp != "true" {
		return ErrIncompatibleCluster{fmt.Sprintf("%s, expected NO_DEFAULT_POOLS to be set 'true' with non-Calico CNI.", errCtx)}
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

func getCNIPlugin(c *components) (operatorv1.CNIPluginType, error) {
	prefix, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "FELIX_INTERFACEPREFIX")
	if err != nil {
		return "", err
	}

	if prefix == nil {
		return operatorv1.PluginCalico, nil
	}
	switch *prefix {
	case "eni":
		return operatorv1.PluginAmazonVPC, nil
	case "avz":
		return operatorv1.PluginAzureVNET, nil
	case "gke":
		return operatorv1.PluginGKE, nil
	case "cali":
		return operatorv1.PluginCalico, nil
	default:
		return "", ErrIncompatibleCluster{
			fmt.Sprintf("unexpected FELIX_INTERFACEPREFIX value: '%s'. Only 'eni, avz, gke, cali' are supported.", *prefix),
		}
	}
}
