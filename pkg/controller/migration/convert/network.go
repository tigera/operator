package convert

import (
	"errors"
	"fmt"
	"net"
	"strings"

	calicocni "github.com/projectcalico/cni-plugin/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	v1 "github.com/tigera/operator/pkg/apis/operator/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
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

// handleIPPools sets the install.Spec.CalicoNetwork.IPPools field. We check the pools
// in the datastore prefering the ones specified by CALICO_IPV*POOL_CIDR.
// We read the pools from the datastore and select the appropriate ones.
// See selectInitialPool for details on which pool will be selected.
// Since the operator only supports one v4 and one v6 only one of each will be picked
// if they exist.
func handleIPPools(c *components, install *Installation) error {
	//pools, err := c.crdClientset.CrdV1().IPPools().List(metav1.ListOptions{})
	//if err != nil {
	//	return err
	//}
	pools := crdv1.IPPoolList{}
	if err := c.client.List(ctx, &pools); err != nil && !kerrors.IsNotFound(err) {
		return fmt.Errorf("failed to list IPPools %v", err)
	}

	// Get the initial CIDR for the v4 IPPool so if there is a pool that matches we will pick
	// it to load.
	v4cidr, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "CALICO_IPV4POOL_CIDR")
	if err != nil {
		return err
	}
	v4pool, err := selectInitialPool(pools.Items, v4cidr, isIpv4)
	if err != nil {
		return ErrIncompatibleCluster{err.Error()}
	}

	// Get the initial CIDR for the v6 IPPool so if there is a pool that matches we will pick
	// it to load.
	v6cidr, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "CALICO_IPV6POOL_CIDR")
	if err != nil {
		return err
	}
	v6pool, err := selectInitialPool(pools.Items, v6cidr, isIpv6)
	if err != nil {
		return ErrIncompatibleCluster{err.Error()}
	}
	// Only if there is at least one v4 or v6 pool will we initialize CalicoNetwork
	if v4pool != nil || v6pool != nil {
		if install.Spec.CalicoNetwork == nil {
			install.Spec.CalicoNetwork = &operatorv1.CalicoNetworkSpec{}
		}

		if install.Spec.CalicoNetwork.IPPools == nil {
			install.Spec.CalicoNetwork.IPPools = []operatorv1.IPPool{}
		}
	}

	// If IPAM is calico then check that the assign_ipv* fields match the IPPools that have been detected
	if c.calicoCNIConfig != nil && c.calicoCNIConfig.IPAM.Type == "calico-ipam" {
		if c.calicoCNIConfig.IPAM.AssignIpv4 == nil || strings.ToLower(*c.calicoCNIConfig.IPAM.AssignIpv4) == "true" {
			if v4pool == nil {
				return ErrIncompatibleCluster{"CNI config indicates assign_ipv4 true but there were no valid V4 pools found"}
			}
		} else {
			if v4pool != nil {
				return ErrIncompatibleCluster{"CNI config indicates assig_ipv4 false but a V4 pool was found"}
			}
		}
		if c.calicoCNIConfig.IPAM.AssignIpv6 != nil && strings.ToLower(*c.calicoCNIConfig.IPAM.AssignIpv6) == "true" {
			if v6pool == nil {
				return ErrIncompatibleCluster{"CNI config indicates assign_ipv6 true but there were no valid V6 pools found"}
			}
		} else {
			if v6pool != nil {
				return ErrIncompatibleCluster{"CNI config indicates assig_ipv6 false but a V6 pool was found"}
			}
		}
	}

	// Convert any found CRD pools into Operator pools and add them.
	if v4pool != nil {
		pool, err := convertPool(*v4pool)
		if err != nil {
			return ErrIncompatibleCluster{fmt.Sprintf("failed to convert IPPool %s, %s ", v4pool.Name, err.Error())}
		}
		install.Spec.CalicoNetwork.IPPools = append(install.Spec.CalicoNetwork.IPPools, pool)
	}
	if v6pool != nil {
		pool, err := convertPool(*v6pool)
		if err != nil {
			return ErrIncompatibleCluster{fmt.Sprintf("failed to convert IPPool %s, %s ", v6pool.Name, err.Error())}
		}
		install.Spec.CalicoNetwork.IPPools = append(install.Spec.CalicoNetwork.IPPools, pool)
	}

	// Ignore the initial pool variables (other than CIDR), we'll pick up everything we need from the datastore
	// V4
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_BLOCK_SIZE")
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_IPIP")
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_VXLAN")
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_NAT_OUTGOING")
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_NODE_SELECTOR")
	// V6
	c.node.ignoreEnv("calico-node", "CALICO_IPV6POOL_BLOCK_SIZE")
	c.node.ignoreEnv("calico-node", "CALICO_IPV6POOL_IPIP")
	c.node.ignoreEnv("calico-node", "CALICO_IPV6POOL_VXLAN")
	c.node.ignoreEnv("calico-node", "CALICO_IPV6POOL_NAT_OUTGOING")
	c.node.ignoreEnv("calico-node", "CALICO_IPV6POOL_NODE_SELECTOR")

	return nil
}

// getIPPools searches through the pools passed in using the matcher function passed in to see if the pool
// should be selected, the first pool that the matcher returns true on is returned.
// If there is an error returned from the matcher then that error is returned.
// If no pool is found and there is no error then nil,nil is returned.
func getIPPool(pools []crdv1.IPPool, matcher func(crdv1.IPPool) (bool, error)) (*crdv1.IPPool, error) {
	for _, pool := range pools {
		if pool.Spec.Disabled {
			continue
		}
		yes, err := matcher(pool)
		if err != nil {
			return nil, err
		}
		if yes {
			return &pool, nil
		}
	}
	return nil, nil
}

// isIPv4 check if the IP is an IPv4 address
func isIpv4(ip net.IP) bool {
	return ip.To4() != nil
}

// isIPv6 checks if the IP is an IPv6 address
func isIpv6(ip net.IP) bool {
	return ip.To4() == nil
}

// selectInitialPool searches through pools for enabled pools, returning the
// first to match one of the following:
//   1. the passed in cidr
//   2. one prefixed with default and matching the isver IP version
//   3. one matching isver IP version
// if none match then nil, nil is returned
// if there is an error parsing the cidr in a pool then that error will be returned
func selectInitialPool(pools []crdv1.IPPool, cidr *string, isver func(ip net.IP) bool) (*crdv1.IPPool, error) {
	// Get IP pool if there is one that matches the initial CIDR
	if cidr != nil {
		pool, _ := getIPPool(pools, func(p crdv1.IPPool) (bool, error) { return p.Spec.CIDR == *cidr, nil })
		if pool != nil {
			return pool, nil
		}
	}
	// If we don't have a pool then try finding one with the right version that is prefixed with 'default'
	pool, err := getIPPool(pools, func(p crdv1.IPPool) (bool, error) {
		ip, _, err := net.ParseCIDR(p.Spec.CIDR)
		if err != nil {
			return false, fmt.Errorf("failed to parse IPPool %s in datastore: %s", p.Name, err.Error())
		}
		if isver(ip) {
			if strings.HasPrefix(p.Name, "default") {
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	if pool != nil {
		return pool, nil
	}

	// If we don't have a pool then just grab any that has the right version
	pool, err = getIPPool(pools, func(p crdv1.IPPool) (bool, error) {
		ip, _, err := net.ParseCIDR(p.Spec.CIDR)
		if err != nil {
			return false, fmt.Errorf("failed to parse IPPool %s in datastore: %s", p.Name, err.Error())
		}
		return isver(ip), nil
	})
	if err != nil {
		return nil, err
	}
	if pool != nil {
		return pool, nil
	}
	return nil, nil
}

// convertPool converts the src (CRD) pool into an Installation/Operator IPPool
func convertPool(src crdv1.IPPool) (operatorv1.IPPool, error) {
	p := operatorv1.IPPool{CIDR: src.Spec.CIDR}

	ip := src.Spec.IPIPMode
	if ip == "" {
		ip = crdv1.IPIPModeNever
	}
	vx := src.Spec.VXLANMode
	if vx == "" {
		vx = crdv1.VXLANModeNever
	}
	switch {
	case ip == crdv1.IPIPModeNever && vx == crdv1.VXLANModeNever:
		p.Encapsulation = operatorv1.EncapsulationNone
	case ip == crdv1.IPIPModeNever && vx == crdv1.VXLANModeAlways:
		p.Encapsulation = operatorv1.EncapsulationVXLAN
	case ip == crdv1.IPIPModeNever && vx == crdv1.VXLANModeCrossSubnet:
		p.Encapsulation = operatorv1.EncapsulationVXLANCrossSubnet
	case vx == crdv1.VXLANModeNever && ip == crdv1.IPIPModeAlways:
		p.Encapsulation = operatorv1.EncapsulationIPIP
	case vx == crdv1.VXLANModeNever && ip == crdv1.IPIPModeCrossSubnet:
		p.Encapsulation = operatorv1.EncapsulationIPIPCrossSubnet
	default:
		return p, fmt.Errorf("unexpected encapsulation combination for pool %+v", src)
	}

	p.NATOutgoing = operatorv1.NATOutgoingEnabled
	if !src.Spec.NATOutgoing {
		p.NATOutgoing = operatorv1.NATOutgoingDisabled
	}

	if src.Spec.BlockSize != 0 {
		bs := int32(src.Spec.BlockSize)
		p.BlockSize = &bs
	}

	p.NodeSelector = src.Spec.NodeSelector

	return p, nil
}
