package convert

import (
	"fmt"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	v1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/migration/cni"
)

const (
	containerCalicoNode      = "calico-node"
	containerInstallCNI      = "install-cni"
	containerKubeControllers = "calico-kube-controllers"
)

func handleNetwork(c *components, install *operatorv1.Installation) error {

	// Verify FELIX_DEFAULTENDPOINTTOHOSTACTION is set to Accept because that is what the operator sets it to.
	if err := c.node.assertEnv(ctx, c.client, containerCalicoNode, "FELIX_DEFAULTENDPOINTTOHOSTACTION", "accept"); err != nil {
		return err
	}

	return nil
}

func handleCalicoCNI(c *components, install *operatorv1.Installation) error {
	plugin, err := getCNIPlugin(c)
	if err != nil {
		return err
	}
	if plugin != operatorv1.PluginCalico {
		return nil
	}

	if c.cni.CalicoConfig == nil {
		return ErrIncompatibleCluster{
			err:       "detected Calico CNI but couldn't find any CNI plugin with type=calico",
			component: ComponentCNIConfig,
			fix:       "ensure CNI config contains a plugin with type=calico, or if not using Calico CNI, ensure FELIX_INTERFACEPREFIX is set correctly on calico-node",
		}
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

	switch c.cni.CalicoConfig.IPAM.Type {
	case "calico-ipam":
		install.Spec.CNI.IPAM.Type = operatorv1.IPAMPluginCalico

		if err := subhandleCalicoIPAM(netBackend, *c.cni.CalicoConfig, install); err != nil {
			return err
		}
	case "host-local":
		install.Spec.CNI.IPAM.Type = operatorv1.IPAMPluginHostLocal

		if c.cni.HostLocalIPAMConfig == nil {
			return ErrIncompatibleCluster{
				err:       "detected Calico CNI with host-local IPAM, but failed to load host-local config",
				component: ComponentCNIConfig,
				fix:       FixFileBugReport,
			}
		}

		if err := subhandleHostLocalIPAM(netBackend, *c.cni.HostLocalIPAMConfig, install); err != nil {
			return err
		}
	default:
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("unrecognized IPAM plugin '%s'", c.cni.CalicoConfig.IPAM.Type),
			component: ComponentCNIConfig,
			fix:       "update cluster to supported type 'calico-ipam' or 'host-local'",
		}
	}

	// IP
	if err := c.node.assertEnv(ctx, c.client, containerCalicoNode, "IP", "autodetect"); err != nil {
		return err
	}

	// IP_AUTODETECTION_METHOD
	if err := handleAutoDetectionMethod(c, install); err != nil {
		return err
	}

	// CNI portmap plugin
	if _, ok := c.cni.Plugins["portmap"]; ok {
		hp := v1.HostPortsEnabled
		install.Spec.CalicoNetwork.HostPorts = &hp
	} else {
		hp := v1.HostPortsDisabled
		install.Spec.CalicoNetwork.HostPorts = &hp
	}

	if c.cni.ConfigName != "k8s-pod-network" {
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("only 'k8s-pod-network' is supported as CNI name, found %s", c.cni.ConfigName),
			component: ComponentCNIConfig,
			fix:       "set CNI config name to 'k8s-pod-network'",
		}
	}

	// Other CNI features
	if c.cni.CalicoConfig.FeatureControl.FloatingIPs {
		return ErrIncompatibleCluster{
			err:       "floating IPs not supported",
			component: ComponentCNIConfig,
			fix:       "disable 'floating_ips' in the CNI configuration",
		}
	}
	if c.cni.CalicoConfig.FeatureControl.IPAddrsNoIpam {
		return ErrIncompatibleCluster{
			err:       "IpAddrsNoIpam not supported",
			component: ComponentCNIConfig,
			fix:       "disable 'IpAddrsNoIpam' in the CNI configuration",
		}
	}
	if c.cni.CalicoConfig.ContainerSettings.AllowIPForwarding {
		return ErrIncompatibleCluster{
			err:       "AllowIPForwarding not supported",
			component: ComponentCNIConfig,
			fix:       "disable 'AllowIPForwarding' in the CNI configuration",
		}
	}

	return nil
}

func handleIpv6(c *components, _ *operatorv1.Installation) error {
	if err := c.node.assertEnv(ctx, c.client, containerCalicoNode, "FELIX_IPV6SUPPORT", "false"); err != nil {
		return err
	}

	if err := c.node.assertEnv(ctx, c.client, containerCalicoNode, "IP6", "none"); err != nil {
		return err
	}

	c.node.ignoreEnv(containerCalicoNode, "IP6_AUTODETECTION_METHOD")

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
func subhandleCalicoIPAM(netBackend string, cnicfg cni.CalicoConf, install *operatorv1.Installation) error {
	switch netBackend {
	case "bird":
		install.Spec.CalicoNetwork.BGP = operatorv1.BGPOptionPtr(operatorv1.BGPEnabled)
	case "vxlan":
		install.Spec.CalicoNetwork.BGP = operatorv1.BGPOptionPtr(operatorv1.BGPDisabled)
	default:
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("detected networking backend '%s' is unknown or incompatible with Calico IPAM", netBackend),
			component: ComponentCalicoNode,
			fix:       FixImpossible,
		}
	}

	// ignored fields:
	//   - c.cni.CalicoCNIConfig.IPAM.Name

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
		return ErrIncompatibleCluster{
			err:       "configuration could not be migrated: " + strings.Join(invalidFields, ","),
			component: ComponentCNIConfig,
			fix:       "remove the unsupported fields from the IPAM config",
		}
	}
	return nil
}

// subhandleHostLocalIPAM checks all fields in the Host Local IPAM configuration,
// if any fields have unexpected values an error message will be returned.
// The function tries to collect all the errors and report one message.
// If there are no errors and the config can be added to the passed in 'install'
// then nil is returned.
func subhandleHostLocalIPAM(netBackend string, ipamcfg cni.HostLocalIPAMConfig, install *operatorv1.Installation) error {
	switch netBackend {
	case "bird":
		install.Spec.CalicoNetwork.BGP = operatorv1.BGPOptionPtr(operatorv1.BGPEnabled)
	case "none":
		install.Spec.CalicoNetwork.BGP = operatorv1.BGPOptionPtr(operatorv1.BGPDisabled)
	default:
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("CALICO_NETWORKING_BACKEND %s is not valid", netBackend),
			component: ComponentCalicoNode,
			fix:       FixImpossible,
		}
	}

	// ignored fields:
	//   - ipamcfg.Name

	invalidFields := []string{}
	if ipamcfg.Range != nil {
		invalidFields = checkRange("", *ipamcfg.Range)
	}
	if len(ipamcfg.Routes) != 0 {
		invalidFields = append(invalidFields, "routes is unsupported")
	}
	if ipamcfg.DataDir != "" {
		invalidFields = append(invalidFields, "dataDir is unsupported")
	}
	if ipamcfg.ResolvConf != "" {
		invalidFields = append(invalidFields, "resolveConf is unsupported")
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
		return ErrIncompatibleCluster{
			err:       "configuration could not be migrated: " + strings.Join(invalidFields, ","),
			component: ComponentCNIConfig,
			fix:       "adjust CNI config accordingly",
		}
	}

	return nil
}

// checkRange checks the fields in r for invalid values for HostLocal IPAM configuration.
func checkRange(prefix string, r cni.Range) []string {
	bf := []string{}
	if r.Subnet != "" {
		if r.Subnet != "usePodCidr" {
			bf = append(bf, prefix+"subnet has invalid value "+r.Subnet)
		}
	}
	if r.RangeStart != "" {
		bf = append(bf, prefix+"rangeStart is unsupported")
	}
	if r.RangeEnd != "" {
		bf = append(bf, prefix+"rangeEnd is unsupported")
	}
	if len(r.Gateway) != 0 {
		bf = append(bf, prefix+"gateway is unsupported")
	}

	return bf
}

func handleNonCalicoCNI(c *components, install *operatorv1.Installation) error {
	plugin, err := getCNIPlugin(c)
	if err != nil {
		return err
	}
	if plugin == operatorv1.PluginCalico {
		return nil
	}

	if icc := getContainer(c.node.Spec.Template.Spec, containerInstallCNI); icc != nil {
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("found unexpected '%s' container for '%s' CNI", containerInstallCNI, plugin),
			component: ComponentCNIConfig,
			fix:       FixFileFeatureRequest,
		}
	}

	// CALICO_NETWORKING_BACKEND
	if err := c.node.assertEnvIsSet(ctx, c.client, containerCalicoNode, "CALICO_NETWORKING_BACKEND", "none"); err != nil {
		return err
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
		if err := c.node.assertEnvIsSet(ctx, c.client, containerCalicoNode, "FELIX_IPTABLESMANGLEALLOWACTION", "return"); err != nil {
			return err
		}
	case operatorv1.PluginAzureVNET:
		install.Spec.CNI.Type = plugin
	case operatorv1.PluginGKE:
		install.Spec.CNI.Type = plugin
		// Verify FELIX_IPTABLESMANGLEALLOWACTION is set to Return because the operator will set it to Return
		// when configured with PluginGKE. The value is also expected to be necessary for Calico policy
		// to correctly function with the GKE plugin.
		if err := c.node.assertEnvIsSet(ctx, c.client, containerCalicoNode, "FELIX_IPTABLESMANGLEALLOWACTION", "return"); err != nil {
			return err
		}

		// Verify FELIX_IPTABLESFILTERALLOWACTION is set to Return because the operator will set it to Return
		// when configured with PluginGKE. The value is also expected to be necessary for Calico policy
		// to correctly function with the GKE plugin.
		if err := c.node.assertEnvIsSet(ctx, c.client, containerCalicoNode, "FELIX_IPTABLESFILTERALLOWACTION", "return"); err != nil {
			return err
		}
	default:
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("unable to migrate plugin '%s': unsupported.", plugin),
			component: ComponentCNIConfig,
			fix:       FixFileFeatureRequest,
		}
	}

	// TODO: Handle configuration with IPs and Pools specified.
	// We need to relax the restriction on CalicoNetwork and non-Calico CNI to do this.
	if err := c.node.assertEnv(ctx, c.client, containerCalicoNode, "IP", ""); err != nil {
		return err
	}

	if err := c.node.assertEnv(ctx, c.client, containerCalicoNode, "NO_DEFAULT_POOLS", "true"); err != nil {
		return err
	}

	return nil
}

// getAutoDetection auto-detects the IP and Network using the requested
// detection method.
func handleAutoDetectionMethod(c *components, install *operatorv1.Installation) error {
	method, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "IP_AUTODETECTION_METHOD")
	if err != nil {
		return err
	}
	if method == nil {
		return nil
	}

	const (
		AutodetectionMethodFirst         = "first-found"
		AutodetectionMethodCanReach      = "can-reach="
		AutodetectionMethodInterface     = "interface="
		AutodetectionMethodSkipInterface = "skip-interface="
	)

	// first-found
	if *method == "" || *method == AutodetectionMethodFirst {
		var t = true
		install.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = &operatorv1.NodeAddressAutodetection{FirstFound: &t}
	}

	// interface
	if strings.HasPrefix(*method, AutodetectionMethodInterface) {
		ifStr := strings.TrimPrefix(*method, AutodetectionMethodInterface)
		install.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = &operatorv1.NodeAddressAutodetection{Interface: ifStr}
	}

	// can-reach
	if strings.HasPrefix(*method, AutodetectionMethodCanReach) {
		dest := strings.TrimPrefix(*method, AutodetectionMethodCanReach)
		install.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = &operatorv1.NodeAddressAutodetection{CanReach: dest}
	}

	// skip-interface
	if strings.HasPrefix(*method, AutodetectionMethodSkipInterface) {
		ifStr := strings.TrimPrefix(*method, AutodetectionMethodSkipInterface)
		install.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = &operatorv1.NodeAddressAutodetection{SkipInterface: ifStr}
	}

	return ErrIncompatibleCluster{
		err:       fmt.Sprintf("IP_AUTODETECTION_METHOD=%s is not supported", *method),
		component: ComponentCalicoNode,
		fix:       "remove the IP_AUTODETECTION_METHOD env var or set it to 'first-found=*', 'can-reach=*', 'interface=*', or 'skip-interface=*'",
	}
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
			err:       fmt.Sprintf("unexpected FELIX_INTERFACEPREFIX value: '%s'. Only 'eni, avz, gke, cali' are supported.", *prefix),
			component: ComponentCalicoNode,
			fix:       FixFileFeatureRequest,
		}
	}
}
