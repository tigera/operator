package convert

import (
	"errors"
	"fmt"
	"strings"

	calicocni "github.com/projectcalico/cni-plugin/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	v1 "github.com/tigera/operator/pkg/apis/operator/v1"
)

const (
	containerCalicoNode      = "calico-node"
	containerInstallCNI      = "install-cni"
	containerKubeControllers = "calico-kube-controllers"
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

	if c.calicoCNIConfig == nil {
		return ErrIncompatibleCluster{fmt.Sprintf("%s, required Calico cni config was not found ", errCtx)}
	}

	if install.Spec.CNI == nil {
		install.Spec.CNI = &operatorv1.CNISpec{}
	}
	install.Spec.CNI.Type = plugin

	if install.Spec.CNI.IPAM == nil {
		install.Spec.CNI.IPAM = &operatorv1.IPAMSpec{}
	}

	if install.Spec.CalicoNetwork == nil {
		install.Spec.CalicoNetwork = &operatorv1.CalicoNetworkSpec{}
	}

	netBackend, err := getNetworkingBackend(c.node, c.client)
	if err != nil {
		return err
	}

	switch c.calicoCNIConfig.IPAM.Type {
	case "calico-ipam":
		install.Spec.CNI.IPAM.Type = operatorv1.IPAMPluginCalico

		if err := subhandleCalicoIPAM(netBackend, *c.calicoCNIConfig, install); err != nil {
			return ErrIncompatibleCluster{fmt.Sprintf("%s and IPAM calico-ipam, %s", errCtx, err.Error())}
		}
	case "host-local":
		install.Spec.CNI.IPAM.Type = operatorv1.IPAMPluginHostLocal

		if c.hostLocalIPAMConfig == nil {
			return ErrIncompatibleCluster{fmt.Sprintf("%s and IPAM host-local, but no IPAM configuration available", errCtx)}
		}

		if err := subhandleHostLocalIPAM(netBackend, *c.hostLocalIPAMConfig, install); err != nil {
			return ErrIncompatibleCluster{fmt.Sprintf("%s and IPAM plugin %s, %s",
				errCtx, c.calicoCNIConfig.IPAM.Type, err.Error())}
		}
	default:
		return ErrIncompatibleCluster{fmt.Sprintf("%s, unrecognized IPAM plugin %s, expected calico-ipam or host-local", errCtx, c.calicoCNIConfig.IPAM.Type)}
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

	if c.cniConfigName != "k8s-pod-network" {
		return ErrIncompatibleCluster{fmt.Sprintf("%s, only 'k8s-pod-network' is supported as CNI name, found %s", errCtx, c.cniConfigName)}
	}

	// Other CNI features
	if c.calicoCNIConfig.FeatureControl.FloatingIPs {
		return ErrIncompatibleCluster{errCtx + ", floating IPs not supported"}
	}
	if c.calicoCNIConfig.FeatureControl.IPAddrsNoIpam {
		return ErrIncompatibleCluster{errCtx + ", IpAddrsNoIpam not supported"}
	}
	if c.calicoCNIConfig.ContainerSettings.AllowIPForwarding {
		return ErrIncompatibleCluster{errCtx + ", AllowIPForwarding not supported"}
	}

	return nil
}

func getNetworkingBackend(node CheckedDaemonSet, client client.Client) (string, error) {
	netBackend, err := node.getEnv(ctx, client, containerCalicoNode, "CALICO_NETWORKING_BACKEND")
	if err != nil {
		return "", err
	}

	switch {
	case netBackend == nil:
		return "bird", nil
	case *netBackend == "":
		return "bird", nil
	case *netBackend == "bird":
		return "bird", nil
	case *netBackend == "vxlan":
		return "vxlan", nil
	case *netBackend == "none":
		return "none", nil
	default:
		return "", fmt.Errorf("CALICO_NETWORKING_BACKEND %s is not valid", *netBackend)
	}
}

// subhandleCalicoIPAM checks all fields in the Calico IPAM configuration,
// if any fields have unexpected values an error message will be returned.
// The function tries to collect all the errors and report one message.
// If there are no errors and the config can be added to the passed in 'install'
// then nil is returned.
func subhandleCalicoIPAM(netBackend string, cnicfg calicocni.NetConf, install *Installation) error {
	switch netBackend {
	case "bird":
		install.Spec.CalicoNetwork.BGP = operatorv1.BGPOptionPtr(operatorv1.BGPEnabled)
	case "vxlan":
		install.Spec.CalicoNetwork.BGP = operatorv1.BGPOptionPtr(operatorv1.BGPDisabled)
	default:
		return ErrIncompatibleCluster{fmt.Sprintf("CALICO_NETWORKING_BACKEND %s is not valid", netBackend)}
	}

	// ignored fields:
	//   - c.calicoCNIConfig.IPAM.Name

	invalidFields := []string{}
	if cnicfg.IPAM.Subnet != "" {
		invalidFields = append(invalidFields, "ipam.subnet field is unsupported")
	}

	if len(cnicfg.IPAM.IPv4Pools) != 0 {
		invalidFields = append(invalidFields, "ipam.ipv4pools field is unsupported")
	}
	if len(cnicfg.IPAM.IPv6Pools) != 0 {
		invalidFields = append(invalidFields, "ipam.ipv6pools field is unsupported")
	}

	if len(invalidFields) > 0 {
		return ErrIncompatibleCluster{"configuration could not be migrated: " + strings.Join(invalidFields, ",")}
	}
	return nil
}

const UnsupportedMsg = "is unsupported"

// subhandleHostLocalIPAM checks all fields in the Host Local IPAM configuration,
// if any fields have unexpected values an error message will be returned.
// The function tries to collect all the errors and report one message.
// If there are no errors and the config can be added to the passed in 'install'
// then nil is returned.
func subhandleHostLocalIPAM(netBackend string, ipamcfg HostLocalIPAMConfig, install *Installation) error {
	switch netBackend {
	case "bird":
		install.Spec.CalicoNetwork.BGP = operatorv1.BGPOptionPtr(operatorv1.BGPEnabled)
	case "none":
		install.Spec.CalicoNetwork.BGP = operatorv1.BGPOptionPtr(operatorv1.BGPDisabled)
	default:
		return ErrIncompatibleCluster{fmt.Sprintf("CALICO_NETWORKING_BACKEND %s is not valid", netBackend)}
	}

	// ignored fields:
	//   - ipamcfg.Name

	invalidFields := []string{}
	if ipamcfg.Range != nil {
		invalidFields = checkRange("", *ipamcfg.Range)
	}
	if len(ipamcfg.Routes) != 0 {
		invalidFields = append(invalidFields, "routes "+UnsupportedMsg)
	}
	if ipamcfg.DataDir != "" {
		invalidFields = append(invalidFields, "dataDir "+UnsupportedMsg)
	}
	if ipamcfg.ResolvConf != "" {
		invalidFields = append(invalidFields, "resolveConf "+UnsupportedMsg)
	}
	switch len(ipamcfg.Ranges) {
	case 0:
	case 1:
		switch len(ipamcfg.Ranges[0]) {
		case 0:
		case 1:
			invalidFields = append(invalidFields, checkRange("ranges.", ipamcfg.Ranges[0][0])...)
		default:
			invalidFields = append(invalidFields, "only zero or one range is valid in the ranges field")
		}
	default:
		invalidFields = append(invalidFields, "only zero or one range is valid in the ranges field")
	}

	if len(invalidFields) > 0 {
		return ErrIncompatibleCluster{"configuration could not be migrated: " + strings.Join(invalidFields, ",")}
	}

	return nil
}

// checkRange checks the fields in r for invalid values for HostLocal IPAM configuration.
func checkRange(prefix string, r Range) []string {
	bf := []string{}
	if r.Subnet != "" {
		if r.Subnet != "usePodCidr" {
			bf = append(bf, prefix+"subnet has invalid value "+r.Subnet)
		}
	}
	if r.RangeStart != "" {
		bf = append(bf, prefix+"rangeStart "+UnsupportedMsg)
	}
	if r.RangeEnd != "" {
		bf = append(bf, prefix+"rangeEnd "+UnsupportedMsg)
	}
	if len(r.Gateway) != 0 {
		bf = append(bf, prefix+"gateway "+UnsupportedMsg)
	}

	return bf
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

func handleIPPool(c *components, install *Installation) error {

	// TODO: Until we're migrating IPPools
	c.node.ignoreEnv("calico-node", "CALICO_IPv4POOL_IPIP")
	c.node.ignoreEnv("calico-node", "CALICO_IPv4POOL_VXLAN")

	// TODO: Check these fields when we're setting the Installation IPPools since those
	// settings will drive these fields.
	// c.calicoCNIConfig.IPAM.AssignIpv4
	// c.calicoCNIConfig.IPAM.AssignIpv6

	return nil
}
