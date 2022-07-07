// Copyright (c) 2019-2022 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package render

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/migration"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render/common/configmap"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	BirdTemplatesConfigMapName        = "bird-templates"
	birdTemplateHashAnnotation        = "hash.operator.tigera.io/bird-templates"
	nodeCniConfigAnnotation           = "hash.operator.tigera.io/cni-config"
	bgpLayoutHashAnnotation           = "hash.operator.tigera.io/bgp-layout"
	bgpBindModeHashAnnotation         = "hash.operator.tigera.io/bgp-bind-mode"
	CSRLabelCalicoSystem              = "calico-system"
	BGPLayoutConfigMapName            = "bgp-layout"
	BGPLayoutConfigMapKey             = "earlyNetworkConfiguration"
	BGPLayoutVolumeName               = "bgp-layout"
	BGPLayoutPath                     = "/etc/calico/early-networking.yaml"
	K8sSvcEndpointConfigMapName       = "kubernetes-services-endpoint"
	nodeTerminationGracePeriodSeconds = 5
	NodeFinalizer                     = "tigera.io/cni-protector"

	CalicoNodeMetricsService      = "calico-node-metrics"
	NodePrometheusTLSServerSecret = "calico-node-prometheus-server-tls"
	CalicoNodeObjectName          = "calico-node"
)

var (
	// The port used by calico/node to report Calico Enterprise BGP metrics.
	// This is currently not intended to be user configurable.
	nodeBGPReporterPort int32 = 9900

	NodeTLSSecretName = "node-certs"
)

// TyphaNodeTLS holds configuration for Node and Typha to establish TLS.
type TyphaNodeTLS struct {
	TrustedBundle   certificatemanagement.TrustedBundle
	TyphaSecret     certificatemanagement.KeyPairInterface
	TyphaCommonName string
	TyphaURISAN     string
	NodeSecret      certificatemanagement.KeyPairInterface
	NodeCommonName  string
	NodeURISAN      string
}

// NodeConfiguration is the public API used to provide information to the render code to
// generate Kubernetes objects for installing calico/node on a cluster.
type NodeConfiguration struct {
	K8sServiceEp  k8sapi.ServiceEndpoint
	Installation  *operatorv1.InstallationSpec
	TLS           *TyphaNodeTLS
	ClusterDomain string

	// Optional fields.
	AmazonCloudIntegration  *operatorv1.AmazonCloudIntegration
	LogCollector            *operatorv1.LogCollector
	MigrateNamespaces       bool
	NodeAppArmorProfile     string
	BirdTemplates           map[string]string
	NodeReporterMetricsPort int
	// Indicates node is being terminated, so remove most resources but
	// leave RBAC and SA to allow any CNI plugin calls to continue to function
	// For details on why this is needed see 'Node and Installation finalizer' in the core_controller.
	Terminating         bool
	PrometheusServerTLS certificatemanagement.KeyPairInterface

	// BGPLayouts is returned by the rendering code after modifying its namespace
	// so that it can be deployed into the cluster.
	// TODO: The controller should pass the contents, the renderer should build its own
	// configmap, rather than this "copy" semantic.
	BGPLayouts *corev1.ConfigMap

	// The health port that Felix should bind to. The controller reads FelixConfiguration
	// and sets this.
	FelixHealthPort int

	// The bindMode read from the default BGPConfiguration. Used to trigger rolling updates
	// should this value change.
	BindMode string
}

// Node creates the node daemonset and other resources for the daemonset to operate normally.
func Node(cfg *NodeConfiguration) Component {
	return &nodeComponent{cfg: cfg}
}

type nodeComponent struct {
	// Input configuration from the controller.
	cfg *NodeConfiguration

	// Calculated internal fields based on the given information.
	cniImage     string
	flexvolImage string
	nodeImage    string
}

func (c *nodeComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		c.cniImage, err = components.GetReference(components.ComponentTigeraCNI, reg, path, prefix, is)
	} else {
		c.cniImage, err = components.GetReference(components.ComponentCalicoCNI, reg, path, prefix, is)
	}
	errMsgs := []string{}
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	c.flexvolImage, err = components.GetReference(components.ComponentFlexVolume, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		c.nodeImage, err = components.GetReference(components.ComponentTigeraNode, reg, path, prefix, is)
	} else {
		c.nodeImage, err = components.GetReference(components.ComponentCalicoNode, reg, path, prefix, is)
	}
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}
	return nil
}

func (c *nodeComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *nodeComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		c.nodeServiceAccount(),
		c.nodeRole(),
		c.nodeRoleBinding(),
	}

	// These are objects to keep even when we're terminating
	objsToKeep := []client.Object{}

	if c.cfg.Terminating {
		objsToKeep = objs
		objs = []client.Object{}
	}

	if c.cfg.BGPLayouts != nil {
		objs = append(objs, configmap.ToRuntimeObjects(configmap.CopyToNamespace(common.CalicoNamespace, c.cfg.BGPLayouts)...)...)
	}

	var objsToDelete []client.Object

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		// Include Service for exposing node metrics.
		objs = append(objs, c.nodeMetricsService())
	}

	cniConfig := c.nodeCNIConfigMap()
	if cniConfig != nil {
		objs = append(objs, cniConfig)
	}

	if btcm := c.birdTemplateConfigMap(); btcm != nil {
		objs = append(objs, btcm)
	}

	if c.cfg.Installation.KubernetesProvider == operatorv1.ProviderDockerEE {
		objs = append(objs, c.clusterAdminClusterRoleBinding())
	}

	if c.cfg.Installation.KubernetesProvider != operatorv1.ProviderOpenShift {
		objs = append(objs, c.nodePodSecurityPolicy())
	}

	objs = append(objs, c.nodeDaemonset(cniConfig))

	// This controller creates the cluster role for any pod in the cluster that requires certificate management.
	if c.cfg.Installation.CertificateManagement != nil {
		objs = append(objs, certificatemanagement.CSRClusterRole())
	}

	if c.cfg.Terminating {
		return objsToKeep, append(objs, objsToDelete...)
	}
	return objs, objsToDelete
}

func (c *nodeComponent) Ready() bool {
	return true
}

// nodeServiceAccount creates the node's service account.
func (c *nodeComponent) nodeServiceAccount() *corev1.ServiceAccount {
	finalizer := []string{}
	if !c.cfg.Terminating {
		finalizer = []string{NodeFinalizer}
	}

	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:       CalicoNodeObjectName,
			Namespace:  common.CalicoNamespace,
			Finalizers: finalizer,
		},
	}
}

// nodeRoleBinding creates a clusterrolebinding giving the node service account the required permissions to operate.
func (c *nodeComponent) nodeRoleBinding() *rbacv1.ClusterRoleBinding {
	finalizer := []string{}
	if !c.cfg.Terminating {
		finalizer = []string{NodeFinalizer}
	}
	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:       CalicoNodeObjectName,
			Labels:     map[string]string{},
			Finalizers: finalizer,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     CalicoNodeObjectName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      CalicoNodeObjectName,
				Namespace: common.CalicoNamespace,
			},
		},
	}
	if c.cfg.MigrateNamespaces {
		migration.AddBindingForKubeSystemNode(crb)
	}
	return crb
}

// nodeRole creates the clusterrole containing policy rules that allow the node daemonset to operate normally.
func (c *nodeComponent) nodeRole() *rbacv1.ClusterRole {
	finalizer := []string{}
	if !c.cfg.Terminating {
		finalizer = []string{NodeFinalizer}
	}
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:       CalicoNodeObjectName,
			Labels:     map[string]string{},
			Finalizers: finalizer,
		},

		Rules: []rbacv1.PolicyRule{
			{
				// Calico uses endpoint slices for service-based network policy rules.
				APIGroups: []string{"discovery.k8s.io"},
				Resources: []string{"endpointslices"},
				Verbs:     []string{"list", "watch"},
			},
			{
				// The CNI plugin needs to get pods, nodes, namespaces.
				APIGroups: []string{""},
				Resources: []string{"pods", "nodes", "namespaces"},
				Verbs:     []string{"get"},
			},
			{
				// Used to discover Typha endpoints and service IPs for advertisement.
				APIGroups: []string{""},
				Resources: []string{"endpoints", "services"},
				Verbs:     []string{"watch", "list", "get"},
			},
			{
				// Some information is stored on the node status.
				APIGroups: []string{""},
				Resources: []string{"nodes/status"},
				Verbs:     []string{"patch", "update"},
			},
			{
				// For enforcing network policies.
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"watch", "list"},
			},
			{
				// Metadata from these are used in conjunction with network policy.
				APIGroups: []string{""},
				Resources: []string{"pods", "namespaces", "serviceaccounts"},
				Verbs:     []string{"watch", "list"},
			},
			{
				// Calico patches the allocated IP onto the pod.
				APIGroups: []string{""},
				Resources: []string{"pods/status"},
				Verbs:     []string{"patch"},
			},
			{
				// Calico needs to query configmaps for pool auto-detection on kubeadm.
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get"},
			},
			{
				// For monitoring Calico-specific configuration.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"bgpconfigurations",
					"bgppeers",
					"blockaffinities",
					"clusterinformations",
					"felixconfigurations",
					"globalnetworkpolicies",
					"stagedglobalnetworkpolicies",
					"globalnetworksets",
					"hostendpoints",
					"ipamblocks",
					"ippools",
					"ipreservations",
					"networkpolicies",
					"stagedkubernetesnetworkpolicies",
					"stagednetworkpolicies",
					"networksets",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				// calico/node monitors for caliconodestatus objects and writes its status back into the object.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"caliconodestatuses",
				},
				Verbs: []string{"get", "list", "watch", "update"},
			},
			{
				// For migration code in calico/node startup only. Remove when the migration
				// code is removed from node.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"globalbgpconfigs",
					"globalfelixconfigs",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				// Calico creates some configuration on startup.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"clusterinformations",
					"felixconfigurations",
					"ippools",
				},
				Verbs: []string{"create", "update"},
			},
			{
				// Calico monitors nodes for some networking configuration.
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				// Most IPAM resources need full CRUD permissions so we can allocate and
				// release IP addresses for pods.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"blockaffinities",
					"ipamblocks",
					"ipamhandles",
				},
				Verbs: []string{"get", "list", "create", "update", "delete"},
			},
			{
				// But, we only need to be able to query for IPAM config.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"ipamconfigs"},
				Verbs:     []string{"get"},
			},
			{
				// confd (and in some cases, felix) watches block affinities for route aggregation.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"blockaffinities"},
				Verbs:     []string{"watch"},
			},
			{
				// Allows Calico to use the K8s TokenRequest API to create the tokens used by the CNI plugin.
				APIGroups:     []string{""},
				Resources:     []string{"serviceaccounts/token"},
				ResourceNames: []string{"calico-node"},
				Verbs:         []string{"create"},
			},
		},
	}
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		extraRules := []rbacv1.PolicyRule{
			{
				// Tigera Secure needs to be able to read licenses, tiers, and config.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"licensekeys",
					"remoteclusterconfigurations",
					"stagedglobalnetworkpolicies",
					"stagedkubernetesnetworkpolicies",
					"stagednetworkpolicies",
					"tiers",
					"packetcaptures",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				// Tigera Secure creates some tiers on startup.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"tiers",
				},
				Verbs: []string{"create"},
			},
			{
				// Tigera Secure updates status for packet captures.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"packetcaptures",
				},
				Verbs: []string{"update"},
			},
		}
		role.Rules = append(role.Rules, extraRules...)
	}
	if c.cfg.Installation.KubernetesProvider != operatorv1.ProviderOpenShift {
		// Allow access to the pod security policy in case this is enforced on the cluster
		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			Verbs:         []string{"use"},
			ResourceNames: []string{common.NodeDaemonSetName},
		})
	}
	return role
}

// nodeCNIConfigMap returns a config map containing the CNI network config to be installed on each node.
// Returns nil if no configmap is needed.
func (c *nodeComponent) nodeCNIConfigMap() *corev1.ConfigMap {
	if c.cfg.Installation.CNI.Type != operatorv1.PluginCalico {
		// If calico cni is not being used, then no cni configmap is needed.
		return nil
	}

	// Determine MTU to use for veth interfaces.
	// Zero means to use auto-detection.
	var mtu int32 = 0
	if m := getMTU(c.cfg.Installation); m != nil {
		mtu = *m
	}

	// Determine per-provider settings.
	nodenameFileOptional := false
	switch c.cfg.Installation.KubernetesProvider {
	case operatorv1.ProviderDockerEE:
		nodenameFileOptional = true
	}

	// Pull out other settings.
	ipForward := false
	if c.cfg.Installation.CalicoNetwork.ContainerIPForwarding != nil {
		ipForward = (*c.cfg.Installation.CalicoNetwork.ContainerIPForwarding == operatorv1.ContainerIPForwardingEnabled)
	}

	// Determine portmap configuration to use.
	var portmap string = ""
	if c.cfg.Installation.CalicoNetwork.HostPorts != nil && *c.cfg.Installation.CalicoNetwork.HostPorts == operatorv1.HostPortsEnabled {
		portmap = `,
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}`
	}

	ipam := c.getCalicoIPAM()
	if c.cfg.Installation.CNI.IPAM.Type == operatorv1.IPAMPluginHostLocal {
		ipam = buildHostLocalIPAM(c.cfg.Installation.CalicoNetwork)
	}

	var k8sAPIRoot string
	apiRoot := c.cfg.K8sServiceEp.CNIAPIRoot()
	if apiRoot != "" {
		k8sAPIRoot = fmt.Sprintf("\n          \"k8s_api_root\":\"%s\",", apiRoot)
	}

	var externalDataplane string = ""
	if c.vppDataplaneEnabled() {
		externalDataplane = `,
      "dataplane_options": {
        "type": "grpc",
        "socket": "unix:///var/run/calico/cni-server.sock"
      }`
	}

	// Build the CNI configuration json.
	config := fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": %d,
      "nodename_file_optional": %v,
      "log_level": "Info",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "ipam": %s,
      "container_settings": {
          "allow_ip_forwarding": %v
      },
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {%s
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }%s
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    }%s
  ]
}`, mtu, nodenameFileOptional, ipam, ipForward, k8sAPIRoot, externalDataplane, portmap)

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cni-config",
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{},
		},
		Data: map[string]string{
			"config": config,
		},
	}
}

func (c *nodeComponent) getCalicoIPAM() string {
	// Determine what address families to enable.
	var assign_ipv4 string
	var assign_ipv6 string
	if v4pool := GetIPv4Pool(c.cfg.Installation.CalicoNetwork.IPPools); v4pool != nil {
		assign_ipv4 = "true"
	} else {
		assign_ipv4 = "false"
	}
	if v6pool := GetIPv6Pool(c.cfg.Installation.CalicoNetwork.IPPools); v6pool != nil {
		assign_ipv6 = "true"
	} else {
		assign_ipv6 = "false"
	}
	return fmt.Sprintf(`{ "type": "calico-ipam", "assign_ipv4" : "%s", "assign_ipv6" : "%s"}`,
		assign_ipv4, assign_ipv6,
	)
}

func buildHostLocalIPAM(cns *operatorv1.CalicoNetworkSpec) string {
	v6 := GetIPv6Pool(cns.IPPools) != nil
	v4 := GetIPv4Pool(cns.IPPools) != nil

	if v4 && v6 {
		// Dual-stack
		return `{ "type": "host-local", "ranges": [[{"subnet": "usePodCidr"}],[{"subnet": "usePodCidrIPv6"}]]}`
	} else if v6 {
		// Single-stack v6
		return `{ "type": "host-local", "subnet": "usePodCidrIPv6"}`
	} else {
		// Single-stack v4
		return `{ "type": "host-local", "subnet": "usePodCidr"}`
	}
}

func (c *nodeComponent) birdTemplateConfigMap() *corev1.ConfigMap {
	if len(c.cfg.BirdTemplates) == 0 {
		return nil
	}
	cm := corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      BirdTemplatesConfigMapName,
			Namespace: common.CalicoNamespace,
		},
		Data: map[string]string{},
	}
	for k, v := range c.cfg.BirdTemplates {
		cm.Data[k] = v
	}
	return &cm
}

// clusterAdminClusterRoleBinding returns a ClusterRoleBinding for DockerEE to give
// the cluster-admin role to calico-node, this is needed for calico-node to be
// able to use hostNetwork in Docker Enterprise.
func (c *nodeComponent) clusterAdminClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "calico-cluster-admin",
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "cluster-admin",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      CalicoNodeObjectName,
				Namespace: common.CalicoNamespace,
			},
		},
	}
	return crb
}

// nodeDaemonset creates the node daemonset.
func (c *nodeComponent) nodeDaemonset(cniCfgMap *corev1.ConfigMap) *appsv1.DaemonSet {
	var terminationGracePeriod int64 = nodeTerminationGracePeriodSeconds
	var initContainers []corev1.Container

	annotations := c.cfg.TLS.TrustedBundle.HashAnnotations()
	if len(c.cfg.BirdTemplates) != 0 {
		annotations[birdTemplateHashAnnotation] = rmeta.AnnotationHash(c.cfg.BirdTemplates)
	}
	if c.cfg.PrometheusServerTLS != nil {
		annotations[c.cfg.PrometheusServerTLS.HashAnnotationKey()] = c.cfg.PrometheusServerTLS.HashAnnotationValue()
	}

	if c.cfg.TLS.NodeSecret.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.TLS.NodeSecret.InitContainer(common.CalicoNamespace))
	}

	if c.cfg.PrometheusServerTLS != nil && c.cfg.PrometheusServerTLS.UseCertificateManagement() {
		initContainers = append(initContainers, c.cfg.PrometheusServerTLS.InitContainer(common.CalicoNamespace))
	}

	if cniCfgMap != nil {
		annotations[nodeCniConfigAnnotation] = rmeta.AnnotationHash(cniCfgMap.Data)
	}

	// Include annotation for prometheus scraping configuration.
	if c.cfg.Installation.NodeMetricsPort != nil {
		annotations["prometheus.io/scrape"] = "true"
		annotations["prometheus.io/port"] = fmt.Sprintf("%d", *c.cfg.Installation.NodeMetricsPort)
	}

	// check tech preview annotation for calico-node apparmor profile
	if c.cfg.NodeAppArmorProfile != "" {
		annotations["container.apparmor.security.beta.kubernetes.io/calico-node"] = c.cfg.NodeAppArmorProfile
	}

	if c.cfg.BGPLayouts != nil {
		annotations[bgpLayoutHashAnnotation] = rmeta.AnnotationHash(c.cfg.BGPLayouts.Data)
	}

	if c.cfg.Installation.FlexVolumePath != "None" {
		initContainers = append(initContainers, c.flexVolumeContainer())
	}

	if c.bpfDataplaneEnabled() {
		initContainers = append(initContainers, c.bpffsInitContainer())
	}

	if c.runAsNonPrivileged() {
		initContainers = append(initContainers, c.hostPathInitContainer())
	}

	var affinity *corev1.Affinity
	if c.cfg.Installation.KubernetesProvider == operatorv1.ProviderAKS {
		affinity = &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{
						MatchExpressions: []corev1.NodeSelectorRequirement{{
							Key:      "type",
							Operator: corev1.NodeSelectorOpNotIn,
							Values:   []string{"virtual-kubelet"},
						}},
					}},
				},
			},
		}
	} else if c.cfg.Installation.KubernetesProvider == operatorv1.ProviderEKS {
		affinity = &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{
						MatchExpressions: []corev1.NodeSelectorRequirement{{
							Key:      "eks.amazonaws.com/compute-type",
							Operator: corev1.NodeSelectorOpNotIn,
							Values:   []string{"fargate"},
						}},
					}},
				},
			},
		}
	}

	// Include the annotation of BindMode
	if c.cfg.BindMode != "" {
		annotations[bgpBindModeHashAnnotation] = rmeta.AnnotationHash(c.cfg.BindMode)
	}

	// Determine the name to use for the calico/node daemonset. For mixed-mode, we run the enterprise DaemonSet
	// with its own name so as to not conflict.
	ds := appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.NodeDaemonSetName,
			Namespace: common.CalicoNamespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": CalicoNodeObjectName}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"k8s-app": CalicoNodeObjectName,
					},
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					Tolerations:                   rmeta.TolerateAll,
					Affinity:                      affinity,
					ImagePullSecrets:              c.cfg.Installation.ImagePullSecrets,
					ServiceAccountName:            CalicoNodeObjectName,
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					HostNetwork:                   true,
					InitContainers:                initContainers,
					Containers:                    []corev1.Container{c.nodeContainer()},
					Volumes:                       c.nodeVolumes(),
				},
			},
			UpdateStrategy: c.cfg.Installation.NodeUpdateStrategy,
		},
	}

	if c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
		ds.Spec.Template.Spec.InitContainers = append(ds.Spec.Template.Spec.InitContainers, c.cniContainer())
	}

	if c.collectProcessPathEnabled() {
		ds.Spec.Template.Spec.HostPID = true
	}

	setNodeCriticalPod(&(ds.Spec.Template))
	if c.cfg.MigrateNamespaces {
		migration.LimitDaemonSetToMigratedNodes(&ds)
	}
	return &ds
}

// cniDirectories returns the binary and network config directories for the configured platform.
func (c *nodeComponent) cniDirectories() (string, string, string) {
	var cniBinDir, cniNetDir, cniLogDir string
	switch c.cfg.Installation.KubernetesProvider {
	case operatorv1.ProviderOpenShift:
		cniNetDir = "/var/run/multus/cni/net.d"
		cniBinDir = "/var/lib/cni/bin"
	case operatorv1.ProviderGKE:
		// Used if we're installing a CNI plugin. If using the GKE plugin, these are not necessary.
		cniBinDir = "/home/kubernetes/bin"
		cniNetDir = "/etc/cni/net.d"
	default:
		// Default locations to match vanilla Kubernetes.
		cniBinDir = "/opt/cni/bin"
		cniNetDir = "/etc/cni/net.d"
	}
	cniLogDir = "/var/log/calico/cni"
	return cniNetDir, cniBinDir, cniLogDir
}

// nodeVolumes creates the node's volumes.
func (c *nodeComponent) nodeVolumes() []corev1.Volume {
	fileOrCreate := corev1.HostPathFileOrCreate
	dirOrCreate := corev1.HostPathDirectoryOrCreate
	dirMustExist := corev1.HostPathDirectory

	volumes := []corev1.Volume{
		{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
		{Name: "xtables-lock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
		{Name: "policysync", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
		c.cfg.TLS.TrustedBundle.Volume(),
		c.cfg.TLS.NodeSecret.Volume(),
	}

	if c.runAsNonPrivileged() {
		volumes = append(volumes,
			corev1.Volume{Name: "var-run", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run"}}},
			corev1.Volume{Name: "var-lib", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib"}}},
			corev1.Volume{Name: "var-log", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log"}}},
		)
	} else {
		volumes = append(volumes,
			corev1.Volume{Name: "var-run-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/calico"}}},
			corev1.Volume{Name: "var-lib-calico", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
		)
	}

	if c.bpfDataplaneEnabled() {
		volumes = append(volumes,
			// Volume for the containing directory so that the init container can mount the child bpf directory if needed.
			corev1.Volume{Name: "sys-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs", Type: &dirOrCreate}}},
			// Volume for the bpffs itself, used by the main node container.
			corev1.Volume{Name: "bpffs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf", Type: &dirMustExist}}},
			// Volume used by mount-cgroupv2 init container to access root cgroup name space of node.
			corev1.Volume{Name: "nodeproc", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc"}}},
		)
	}

	if c.vppDataplaneEnabled() {
		volumes = append(volumes,
			// Volume that contains the felix dataplane binary
			corev1.Volume{Name: "felix-plugins", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/calico/felix-plugins"}}},
		)
	}

	// If needed for this configuration, then include the CNI volumes.
	if c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
		// Determine directories to use for CNI artifacts based on the provider.
		cniNetDir, cniBinDir, cniLogDir := c.cniDirectories()
		volumes = append(volumes, corev1.Volume{Name: "cni-bin-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: cniBinDir}}})
		volumes = append(volumes, corev1.Volume{Name: "cni-net-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: cniNetDir}}})
		volumes = append(volumes, corev1.Volume{Name: "cni-log-dir", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: cniLogDir}}})
	}

	// Override with Tigera-specific config.
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		// Add volume for calico logs.
		calicoLogVol := corev1.Volume{
			Name:         "var-log-calico",
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/calico", Type: &dirOrCreate}},
		}
		volumes = append(volumes, calicoLogVol)
	}

	// Create and append flexvolume
	if c.cfg.Installation.FlexVolumePath != "None" {
		volumes = append(volumes, corev1.Volume{
			Name: "flexvol-driver-host",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{Path: c.cfg.Installation.FlexVolumePath + "nodeagent~uds", Type: &dirOrCreate},
			},
		})
	}
	if c.cfg.BirdTemplates != nil {
		volumes = append(volumes,
			corev1.Volume{
				Name: "bird-templates",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: BirdTemplatesConfigMapName,
						},
					},
				},
			})
	}

	if c.cfg.BGPLayouts != nil {
		volumes = append(volumes,
			corev1.Volume{
				Name: BGPLayoutVolumeName,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: BGPLayoutConfigMapName,
						},
					},
				},
			})
	}
	if c.cfg.PrometheusServerTLS != nil {
		volumes = append(volumes, c.cfg.PrometheusServerTLS.Volume())
	}

	return volumes
}

func (c *nodeComponent) bpfDataplaneEnabled() bool {
	return c.cfg.Installation.CalicoNetwork != nil &&
		c.cfg.Installation.CalicoNetwork.LinuxDataplane != nil &&
		*c.cfg.Installation.CalicoNetwork.LinuxDataplane == operatorv1.LinuxDataplaneBPF
}

func (c *nodeComponent) vppDataplaneEnabled() bool {
	return c.cfg.Installation.CalicoNetwork != nil &&
		c.cfg.Installation.CalicoNetwork.LinuxDataplane != nil &&
		*c.cfg.Installation.CalicoNetwork.LinuxDataplane == operatorv1.LinuxDataplaneVPP
}

func (c *nodeComponent) collectProcessPathEnabled() bool {
	return c.cfg.LogCollector != nil &&
		c.cfg.LogCollector.Spec.CollectProcessPath != nil &&
		*c.cfg.LogCollector.Spec.CollectProcessPath == operatorv1.CollectProcessPathEnable
}

// cniContainer creates the node's init container that installs CNI.
func (c *nodeComponent) cniContainer() corev1.Container {
	// Determine environment to pass to the CNI init container.
	cniEnv := c.cniEnvvars()
	cniVolumeMounts := []corev1.VolumeMount{
		{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
		{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
	}

	return corev1.Container{
		Name:         "install-cni",
		Image:        c.cniImage,
		Command:      []string{"/opt/cni/bin/install"},
		Env:          cniEnv,
		VolumeMounts: cniVolumeMounts,
		SecurityContext: &corev1.SecurityContext{
			Privileged: ptr.BoolToPtr(true),
		},
	}
}

// flexVolumeContainer creates the node's init container that installs the Unix Domain Socket to allow Dikastes
// to communicate with Felix over the Policy Sync API.
func (c *nodeComponent) flexVolumeContainer() corev1.Container {
	flexVolumeMounts := []corev1.VolumeMount{
		{MountPath: "/host/driver", Name: "flexvol-driver-host"},
	}

	return corev1.Container{
		Name:         "flexvol-driver",
		Image:        c.flexvolImage,
		VolumeMounts: flexVolumeMounts,
		SecurityContext: &corev1.SecurityContext{
			Privileged: ptr.BoolToPtr(true),
		},
	}
}

// bpffsInitContainer creates an init container that attempts to mount the BPF filesystem.  doing this from an
// init container reduces the privileges needed by the main container.  It's important that the BPF filesystem is
// mounted on the host itself, otherwise, a restart of the node container would tear down the mount and destroy
// the BPF dataplane's BPF maps.
func (c *nodeComponent) bpffsInitContainer() corev1.Container {
	bidirectional := corev1.MountPropagationBidirectional
	mounts := []corev1.VolumeMount{
		{
			MountPath: "/sys/fs",
			Name:      "sys-fs",
			// Bidirectional is required to ensure that the new mount we make at /sys/fs/bpf propagates to the host
			// so that it outlives the init container.
			MountPropagation: &bidirectional,
		},
		{
			MountPath: "/var/run/calico",
			Name:      "var-run-calico",
			// Bidirectional is required to ensure that the new mount we make at /var/run/calico/cgroup propagates to the host
			// so that it outlives the init container.
			MountPropagation: &bidirectional,
		},
		{
			MountPath: "/nodeproc",
			Name:      "nodeproc",
			ReadOnly:  true,
		},
	}

	return corev1.Container{
		Name:         "mount-bpffs",
		Image:        c.nodeImage,
		VolumeMounts: mounts,
		SecurityContext: &corev1.SecurityContext{
			Privileged: ptr.BoolToPtr(true),
		},
		Command: []string{CalicoNodeObjectName, "-init"},
	}
}

// cniEnvvars creates the CNI container's envvars.
func (c *nodeComponent) cniEnvvars() []corev1.EnvVar {
	if c.cfg.Installation.CNI.Type != operatorv1.PluginCalico {
		return []corev1.EnvVar{}
	}

	// Determine directories to use for CNI artifacts based on the provider.
	cniNetDir, _, _ := c.cniDirectories()

	envVars := []corev1.EnvVar{
		{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
		{Name: "SLEEP", Value: "false"},
		{Name: "CNI_NET_DIR", Value: cniNetDir},
		{
			Name: "CNI_NETWORK_CONFIG",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					Key: "config",
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "cni-config",
					},
				},
			},
		},
	}

	envVars = append(envVars, c.cfg.K8sServiceEp.EnvVars(true, c.cfg.Installation.KubernetesProvider)...)

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		if c.cfg.Installation.CalicoNetwork != nil && c.cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
			envVars = append(envVars, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value()})
		}
	}

	return envVars
}

// nodeContainer creates the main node container.
func (c *nodeComponent) nodeContainer() corev1.Container {
	lp, rp := c.nodeLivenessReadinessProbes()
	sc := &corev1.SecurityContext{Privileged: ptr.BoolToPtr(true)}
	if c.runAsNonPrivileged() {
		uid := int64(999)
		guid := int64(0)
		sc = &corev1.SecurityContext{
			// Set the user as our chosen user (999)
			RunAsUser: &uid,
			// Set the group to be the root user group since all container users should be a member
			RunAsGroup: &guid,
			Privileged: ptr.BoolToPtr(false),
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{
					corev1.Capability("NET_RAW"),
					corev1.Capability("NET_ADMIN"),
					corev1.Capability("NET_BIND_SERVICE"),
				},
			},
		}
	}
	return corev1.Container{
		Name:            CalicoNodeObjectName,
		Image:           c.nodeImage,
		Resources:       c.nodeResources(),
		SecurityContext: sc,
		Env:             c.nodeEnvVars(),
		VolumeMounts:    c.nodeVolumeMounts(),
		LivenessProbe:   lp,
		ReadinessProbe:  rp,
		Lifecycle:       c.nodeLifecycle(),
	}
}

// nodeResources creates the node's resource requirements.
func (c *nodeComponent) nodeResources() corev1.ResourceRequirements {
	return rmeta.GetResourceRequirements(c.cfg.Installation, operatorv1.ComponentNameNode)
}

// nodeVolumeMounts creates the node's volume mounts.
func (c *nodeComponent) nodeVolumeMounts() []corev1.VolumeMount {
	nodeVolumeMounts := []corev1.VolumeMount{
		{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
		{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
		{MountPath: "/var/run/nodeagent", Name: "policysync"},
		c.cfg.TLS.TrustedBundle.VolumeMount(),
		c.cfg.TLS.NodeSecret.VolumeMount(),
	}
	if c.runAsNonPrivileged() {
		nodeVolumeMounts = append(nodeVolumeMounts,
			corev1.VolumeMount{MountPath: "/var/run", Name: "var-run"},
			corev1.VolumeMount{MountPath: "/var/lib", Name: "var-lib"},
			corev1.VolumeMount{MountPath: "/var/log", Name: "var-log"},
		)
	} else {
		nodeVolumeMounts = append(nodeVolumeMounts,
			corev1.VolumeMount{MountPath: "/var/run/calico", Name: "var-run-calico"},
			corev1.VolumeMount{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
		)
	}
	if c.bpfDataplaneEnabled() {
		nodeVolumeMounts = append(nodeVolumeMounts, corev1.VolumeMount{MountPath: "/sys/fs/bpf", Name: "bpffs"})
	}
	if c.vppDataplaneEnabled() {
		nodeVolumeMounts = append(nodeVolumeMounts, corev1.VolumeMount{MountPath: "/usr/local/bin/felix-plugins", Name: "felix-plugins", ReadOnly: true})
	}
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		extraNodeMounts := []corev1.VolumeMount{
			{MountPath: "/var/log/calico", Name: "var-log-calico"},
		}
		nodeVolumeMounts = append(nodeVolumeMounts, extraNodeMounts...)
	} else if c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
		cniLogMount := corev1.VolumeMount{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: false}
		nodeVolumeMounts = append(nodeVolumeMounts, cniLogMount)
	}

	if c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
		nodeVolumeMounts = append(nodeVolumeMounts, corev1.VolumeMount{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"})
	}

	if c.cfg.BirdTemplates != nil {
		// create a volume mount for each bird template, but sort them alphabetically first,
		// otherwise, since map iteration is random, they'll be added to the list of volumes in a random order,
		// which will cause another reconciliation event when calico-node is updated.
		sortedKeys := []string{}
		for k := range c.cfg.BirdTemplates {
			sortedKeys = append(sortedKeys, k)
		}
		sort.Strings(sortedKeys)

		for _, k := range sortedKeys {
			nodeVolumeMounts = append(nodeVolumeMounts,
				corev1.VolumeMount{
					Name:      "bird-templates",
					ReadOnly:  true,
					MountPath: fmt.Sprintf("/etc/calico/confd/templates/%s", k),
					SubPath:   k,
				})
		}
	}

	if c.cfg.BGPLayouts != nil {
		nodeVolumeMounts = append(nodeVolumeMounts,
			corev1.VolumeMount{
				Name:      BGPLayoutVolumeName,
				ReadOnly:  true,
				MountPath: BGPLayoutPath,
				SubPath:   BGPLayoutConfigMapKey,
			})
	}
	if c.cfg.PrometheusServerTLS != nil {
		nodeVolumeMounts = append(nodeVolumeMounts, c.cfg.PrometheusServerTLS.VolumeMount())
	}
	return nodeVolumeMounts
}

// nodeEnvVars creates the node's envvars.
func (c *nodeComponent) nodeEnvVars() []corev1.EnvVar {
	// Set the clusterType.
	clusterType := "k8s,operator"

	// Note: Felix now activates certain special-case logic based on the provider in the cluster type; avoid changing
	// these unless you also update Felix's parsing logic.
	switch c.cfg.Installation.KubernetesProvider {
	case operatorv1.ProviderOpenShift:
		clusterType = clusterType + ",openshift"
	case operatorv1.ProviderEKS:
		clusterType = clusterType + ",ecs"
	case operatorv1.ProviderGKE:
		clusterType = clusterType + ",gke"
	case operatorv1.ProviderAKS:
		clusterType = clusterType + ",aks"
	}

	if bgpEnabled(c.cfg.Installation) {
		clusterType = clusterType + ",bgp"
	}

	nodeEnv := []corev1.EnvVar{
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		{Name: "WAIT_FOR_DATASTORE", Value: "true"},
		{Name: "CLUSTER_TYPE", Value: clusterType},
		{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
		{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
		{Name: "FELIX_HEALTHENABLED", Value: "true"},
		{Name: "FELIX_HEALTHPORT", Value: fmt.Sprintf("%d", c.cfg.FelixHealthPort)},
		{
			Name: "NODENAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		},
		{
			Name: "NAMESPACE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
			},
		},
		{Name: "FELIX_TYPHAK8SNAMESPACE", Value: common.CalicoNamespace},
		{Name: "FELIX_TYPHAK8SSERVICENAME", Value: TyphaServiceName},
		{Name: "FELIX_TYPHACAFILE", Value: c.cfg.TLS.TrustedBundle.MountPath()},
		{Name: "FELIX_TYPHACERTFILE", Value: c.cfg.TLS.NodeSecret.VolumeMountCertificateFilePath()},
		{Name: "FELIX_TYPHAKEYFILE", Value: c.cfg.TLS.NodeSecret.VolumeMountKeyFilePath()},
	}
	// We need at least the CN or URISAN set, we depend on the validation
	// done by the core_controller that the Secret will have one.
	if c.cfg.TLS.TyphaCommonName != "" {
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_TYPHACN", Value: c.cfg.TLS.TyphaCommonName})
	}
	if c.cfg.TLS.TyphaURISAN != "" {
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_TYPHAURISAN", Value: c.cfg.TLS.TyphaURISAN})
	}

	if c.cfg.Installation.CNI != nil && c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
		// If using Calico CNI, we need to manage CNI credential rotation on the host.
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_MANAGE_CNI", Value: "true"})
	} else {
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_MANAGE_CNI", Value: "false"})
	}

	if c.cfg.Installation.CNI != nil && c.cfg.Installation.CNI.Type == operatorv1.PluginAmazonVPC {
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_BPFEXTTOSERVICECONNMARK", Value: "0x80"})
	}

	// If there are no IP pools specified, then configure no default IP pools.
	if c.cfg.Installation.CalicoNetwork == nil || len(c.cfg.Installation.CalicoNetwork.IPPools) == 0 {
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "NO_DEFAULT_POOLS", Value: "true"})
	} else {
		// Configure IPv4 pool
		if v4pool := GetIPv4Pool(c.cfg.Installation.CalicoNetwork.IPPools); v4pool != nil {
			nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_IPV4POOL_CIDR", Value: v4pool.CIDR})

			switch v4pool.Encapsulation {
			case operatorv1.EncapsulationIPIPCrossSubnet:
				nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_IPV4POOL_IPIP", Value: "CrossSubnet"})
			case operatorv1.EncapsulationIPIP:
				nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"})
			case operatorv1.EncapsulationVXLAN:
				nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_IPV4POOL_VXLAN", Value: "Always"})
			case operatorv1.EncapsulationVXLANCrossSubnet:
				nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_IPV4POOL_VXLAN", Value: "CrossSubnet"})
			case operatorv1.EncapsulationNone:
				nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_IPV4POOL_IPIP", Value: "Never"})
			default:
				nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"})
			}

			if v4pool.BlockSize != nil {
				nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_IPV4POOL_BLOCK_SIZE", Value: fmt.Sprintf("%d", *v4pool.BlockSize)})
			}
			if v4pool.NATOutgoing == operatorv1.NATOutgoingDisabled {
				// Default for IPv4 NAT Outgoing is enabled so it is only necessary to
				// set when it is being disabled.
				nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_IPV4POOL_NAT_OUTGOING", Value: "false"})
			}
			if v4pool.NodeSelector != "" {
				nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_IPV4POOL_NODE_SELECTOR", Value: v4pool.NodeSelector})
			}
		}

		// Configure IPv6 pool.
		if v6pool := GetIPv6Pool(c.cfg.Installation.CalicoNetwork.IPPools); v6pool != nil {
			nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_IPV6POOL_CIDR", Value: v6pool.CIDR})

			switch v6pool.Encapsulation {
			case operatorv1.EncapsulationVXLAN:
				nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_IPV6POOL_VXLAN", Value: "Always"})
			case operatorv1.EncapsulationVXLANCrossSubnet:
				nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_IPV6POOL_VXLAN", Value: "CrossSubnet"})
			case operatorv1.EncapsulationNone:
				nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_IPV6POOL_VXLAN", Value: "Never"})
			}

			if v6pool.BlockSize != nil {
				nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_IPV6POOL_BLOCK_SIZE", Value: fmt.Sprintf("%d", *v6pool.BlockSize)})
			}
			if v6pool.NATOutgoing == operatorv1.NATOutgoingEnabled {
				// Default for IPv6 NAT Outgoing is disabled so it is only necessary to
				// set when it is being enabled.
				nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_IPV6POOL_NAT_OUTGOING", Value: "true"})
			}
			if v6pool.NodeSelector != "" {
				nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_IPV6POOL_NODE_SELECTOR", Value: v6pool.NodeSelector})
			}
		}
	}

	if c.bpfDataplaneEnabled() {
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_BPFENABLED", Value: "true"})
	}
	if c.vppDataplaneEnabled() {
		nodeEnv = append(nodeEnv, corev1.EnvVar{
			Name:  "FELIX_USEINTERNALDATAPLANEDRIVER",
			Value: "false",
		}, corev1.EnvVar{
			Name:  "FELIX_DATAPLANEDRIVER",
			Value: "/usr/local/bin/felix-plugins/felix-api-proxy",
		}, corev1.EnvVar{
			Name:  "FELIX_XDPENABLED",
			Value: "false",
		})
		if c.cfg.Installation.KubernetesProvider == operatorv1.ProviderEKS {
			nodeEnv = append(nodeEnv, corev1.EnvVar{
				Name:  "FELIX_AWSSRCDSTCHECK",
				Value: "Disable",
			})
		}
	}

	if c.collectProcessPathEnabled() {
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_FLOWLOGSCOLLECTPROCESSPATH", Value: "true"})
	}

	// Determine MTU to use. If specified explicitly, use that. Otherwise, set defaults based on an overall
	// MTU of 1460.
	mtu := getMTU(c.cfg.Installation)
	if mtu != nil {
		vxlanMtu := strconv.Itoa(int(*mtu))
		wireguardMtu := strconv.Itoa(int(*mtu))
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_VXLANMTU", Value: vxlanMtu})
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_WIREGUARDMTU", Value: wireguardMtu})
	}

	// If host-local IPAM is in use, we need to configure calico/node to use the Kubernetes pod CIDR.
	cni := c.cfg.Installation.CNI
	if cni != nil && cni.IPAM != nil && cni.IPAM.Type == operatorv1.IPAMPluginHostLocal {
		nodeEnv = append(nodeEnv, corev1.EnvVar{
			Name:  "USE_POD_CIDR",
			Value: "true",
		})
	}

	// Configure whether or not BGP should be enabled.
	if !bgpEnabled(c.cfg.Installation) {
		if c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
			if c.cfg.Installation.CNI.IPAM.Type == operatorv1.IPAMPluginHostLocal {
				// If BGP is disabled and using HostLocal, then that means routing is done
				// by Cloud routing, so networking backend is none. (because we don't support
				// vxlan with HostLocal.)
				nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "none"})
			} else {
				// If BGP is disabled, then set the networking backend to "vxlan". This means that BIRD will be
				// disabled, and VXLAN will optionally be configurable via IP pools.
				nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "vxlan"})
			}
		} else {
			// If not using Calico networking at all, set the backend to "none".
			nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "none"})
		}
	} else {
		// BGP is enabled.
		if c.vppDataplaneEnabled() {
			// VPP comes with its own BGP daemon, so bird should be disabled
			nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "none"})
		} else {
			nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"})
		}
		if mtu != nil {
			ipipMtu := strconv.Itoa(int(*mtu))
			nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_IPINIPMTU", Value: ipipMtu})
		}
	}

	// IPv4 auto-detection configuration.
	var v4Method string
	if c.cfg.Installation.CalicoNetwork != nil {
		v4Method = getAutodetectionMethod(c.cfg.Installation.CalicoNetwork.NodeAddressAutodetectionV4)
	}
	if v4Method != "" {
		// IPv4 Auto-detection is enabled.
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "IP", Value: "autodetect"})
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "IP_AUTODETECTION_METHOD", Value: v4Method})
	} else {
		// IPv4 Auto-detection is disabled.
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "IP", Value: "none"})
	}

	// IPv6 auto-detection and ippool configuration.
	var v6Method string
	if c.cfg.Installation.CalicoNetwork != nil {
		v6Method = getAutodetectionMethod(c.cfg.Installation.CalicoNetwork.NodeAddressAutodetectionV6)
	}
	if v6Method != "" {
		// IPv6 Auto-detection is enabled.
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "IP6", Value: "autodetect"})
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "IP6_AUTODETECTION_METHOD", Value: v6Method})
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_IPV6SUPPORT", Value: "true"})

		// Set CALICO_ROUTER_ID to "hash" for IPv6-only with BGP enabled.
		if v4Method == "" && bgpEnabled(c.cfg.Installation) {
			nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "CALICO_ROUTER_ID", Value: "hash"})
		}
	} else {
		// IPv6 Auto-detection is disabled.
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "IP6", Value: "none"})
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_IPV6SUPPORT", Value: "false"})
	}

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		// Add in Calico Enterprise specific configuration.
		extraNodeEnv := []corev1.EnvVar{
			{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
			{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: fmt.Sprintf("%d", c.cfg.NodeReporterMetricsPort)},
			{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDELABELS", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDEPOLICIES", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDESERVICE", Value: "true"},
			{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
			{Name: "FELIX_FLOWLOGSCOLLECTPROCESSINFO", Value: "true"},
			{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
			{Name: "FELIX_DNSLOGSFILEPERNODELIMIT", Value: "1000"},
		}

		if c.cfg.Installation.CalicoNetwork != nil && c.cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
			extraNodeEnv = append(extraNodeEnv, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value()})
		}

		if c.cfg.PrometheusServerTLS != nil {
			extraNodeEnv = append(extraNodeEnv,
				corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERCERTFILE", Value: c.cfg.PrometheusServerTLS.VolumeMountCertificateFilePath()},
				corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERKEYFILE", Value: c.cfg.PrometheusServerTLS.VolumeMountKeyFilePath()},
				corev1.EnvVar{Name: "FELIX_PROMETHEUSREPORTERCAFILE", Value: c.cfg.TLS.TrustedBundle.MountPath()},
			)
		}
		nodeEnv = append(nodeEnv, extraNodeEnv...)
	}

	if c.cfg.Installation.NodeMetricsPort != nil {
		// If a node metrics port was given, then enable felix prometheus metrics and set the port.
		// Note that this takes precedence over any FelixConfiguration resources in the cluster.
		extraNodeEnv := []corev1.EnvVar{
			{Name: "FELIX_PROMETHEUSMETRICSENABLED", Value: "true"},
			{Name: "FELIX_PROMETHEUSMETRICSPORT", Value: fmt.Sprintf("%d", *c.cfg.Installation.NodeMetricsPort)},
		}
		nodeEnv = append(nodeEnv, extraNodeEnv...)
	}

	// Configure provider specific environment variables here.
	switch c.cfg.Installation.KubernetesProvider {
	case operatorv1.ProviderOpenShift:
		// For Openshift, we need special configuration since our default port is already in use.
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_HEALTHPORT", Value: "9199"})
		if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
			// We also need to configure a non-default trusted DNS server, since there's no kube-dns.
			nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_DNSTRUSTEDSERVERS", Value: "k8s-service:openshift-dns/dns-default"})
		}
	// For AKS/AzureVNET and EKS/VPCCNI, we must explicitly ask felix to add host IP's to wireguard ifaces
	case operatorv1.ProviderAKS:
		if c.cfg.Installation.CNI.Type == operatorv1.PluginAzureVNET {
			nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_WIREGUARDHOSTENCRYPTIONENABLED", Value: "true"})
		}
	case operatorv1.ProviderEKS:
		if c.cfg.Installation.CNI.Type == operatorv1.PluginAmazonVPC {
			nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_WIREGUARDHOSTENCRYPTIONENABLED", Value: "true"})
		}
	}

	switch c.cfg.Installation.CNI.Type {
	case operatorv1.PluginAmazonVPC:
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "eni"})
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"})
	case operatorv1.PluginGKE:
		// The GKE CNI plugin uses its own interface prefix.
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "gke"})
		// The GKE CNI plugin has its own iptables rules. Defer to them after ours.
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"})
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_IPTABLESFILTERALLOWACTION", Value: "Return"})
	case operatorv1.PluginAzureVNET:
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "azv"})
	}

	if c.cfg.Installation.CNI.Type != operatorv1.PluginCalico {
		nodeEnv = append(nodeEnv, corev1.EnvVar{Name: "FELIX_ROUTESOURCE", Value: "WorkloadIPs"})
	}

	if c.cfg.AmazonCloudIntegration != nil {
		nodeEnv = append(nodeEnv, GetTigeraSecurityGroupEnvVariables(c.cfg.AmazonCloudIntegration)...)
		nodeEnv = append(nodeEnv, corev1.EnvVar{
			Name:  "FELIX_FAILSAFEINBOUNDHOSTPORTS",
			Value: "tcp:22,udp:68,tcp:179,tcp:443,tcp:5473,tcp:6443",
		})
		nodeEnv = append(nodeEnv, corev1.EnvVar{
			Name:  "FELIX_FAILSAFEOUTBOUNDHOSTPORTS",
			Value: "udp:53,udp:67,tcp:179,tcp:443,tcp:5473,tcp:6443",
		})
	}

	nodeEnv = append(nodeEnv, c.cfg.K8sServiceEp.EnvVars(true, c.cfg.Installation.KubernetesProvider)...)

	if c.cfg.BGPLayouts != nil {
		nodeEnv = append(nodeEnv, corev1.EnvVar{
			Name:  "CALICO_EARLY_NETWORKING",
			Value: BGPLayoutPath,
		})
	}

	return nodeEnv
}

// nodeLifecycle creates the node's postStart and preStop hooks.
func (c *nodeComponent) nodeLifecycle() *corev1.Lifecycle {
	preStopCmd := []string{"/bin/calico-node", "-shutdown"}
	lc := &corev1.Lifecycle{
		PreStop: &corev1.Handler{Exec: &corev1.ExecAction{Command: preStopCmd}},
	}
	return lc
}

// nodeLivenessReadinessProbes creates the node's liveness and readiness probes.
func (c *nodeComponent) nodeLivenessReadinessProbes() (*corev1.Probe, *corev1.Probe) {
	// Determine liveness and readiness configuration for node.
	livenessPort := intstr.FromInt(c.cfg.FelixHealthPort)
	readinessCmd := []string{"/bin/calico-node", "-bird-ready", "-felix-ready"}

	// Want to check for BGP metrics server if this is enterprise
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		readinessCmd = []string{"/bin/calico-node", "-bird-ready", "-felix-ready", "-bgp-metrics-ready"}
	}

	// If not using BGP or using VPP, don't check bird status (or bgp metrics server for enterprise).
	if !bgpEnabled(c.cfg.Installation) || c.vppDataplaneEnabled() {
		readinessCmd = []string{"/bin/calico-node", "-felix-ready"}
	}

	lp := &corev1.Probe{
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Host: "localhost",
				Path: "/liveness",
				Port: livenessPort,
			},
		},
		TimeoutSeconds: 10,
	}
	rp := &corev1.Probe{
		Handler: corev1.Handler{Exec: &corev1.ExecAction{Command: readinessCmd}},
		// Set the TimeoutSeconds greater than the default of 1 to allow additional time on loaded nodes.
		// This timeout should be less than the PeriodSeconds.
		TimeoutSeconds: 5,
		PeriodSeconds:  10,
	}
	return lp, rp
}

// nodeMetricsService creates a Service which exposes two endpoints on calico/node for
// reporting Prometheus metrics (for policy enforcement activity and BGP stats).
// This service is used internally by Calico Enterprise and is separate from general
// Prometheus metrics which are user-configurable.
func (c *nodeComponent) nodeMetricsService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CalicoNodeMetricsService,
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{"k8s-app": CalicoNodeObjectName},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": CalicoNodeObjectName},
			Type:     corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       "calico-metrics-port",
					Port:       int32(c.cfg.NodeReporterMetricsPort),
					TargetPort: intstr.FromInt(c.cfg.NodeReporterMetricsPort),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       "calico-bgp-metrics-port",
					Port:       nodeBGPReporterPort,
					TargetPort: intstr.FromInt(int(nodeBGPReporterPort)),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

func (c *nodeComponent) nodePodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := podsecuritypolicy.NewBasePolicy()
	psp.GetObjectMeta().SetName(common.NodeDaemonSetName)
	psp.Spec.Privileged = true
	psp.Spec.AllowPrivilegeEscalation = ptr.BoolToPtr(true)
	psp.Spec.Volumes = append(psp.Spec.Volumes, policyv1beta1.HostPath)
	psp.Spec.HostNetwork = true
	// CollectProcessPath feature in logCollectorSpec requires access to hostPID
	// Hence setting hostPID to true in the calico-node PSP, for this feature
	// to work with PSP turned on
	if c.collectProcessPathEnabled() {
		psp.Spec.HostPID = true
	}
	psp.Spec.RunAsUser.Rule = policyv1beta1.RunAsUserStrategyRunAsAny
	return psp
}

// hostPathInitContainer creates an init container that changes the permissions on hostPath volumes
// so that they can be written to by a non-root container.
func (c *nodeComponent) hostPathInitContainer() corev1.Container {
	rootUID := int64(0)
	mounts := []corev1.VolumeMount{
		{
			MountPath: "/var/run",
			Name:      "var-run",
			ReadOnly:  false,
		},
		{
			MountPath: "/var/lib",
			Name:      "var-lib",
			ReadOnly:  false,
		},
		{
			MountPath: "/var/log",
			Name:      "var-log",
			ReadOnly:  false,
		},
	}

	return corev1.Container{
		Name:  "hostpath-init",
		Image: c.nodeImage,
		Env: []corev1.EnvVar{
			{Name: "NODE_USER_ID", Value: "999"},
		},
		VolumeMounts: mounts,
		SecurityContext: &corev1.SecurityContext{
			RunAsUser: &rootUID,
		},
		Command: []string{"sh", "-c", "calico-node -hostpath-init"},
	}
}

// runAsNonPrivileged checks to ensure that all of the proper installation values are set for running
// Calico as non-privileged.
func (c *nodeComponent) runAsNonPrivileged() bool {
	// Check that the NonPrivileged flag is set
	return c.cfg.Installation.NonPrivileged != nil && *c.cfg.Installation.NonPrivileged == operatorv1.NonPrivilegedEnabled
}

// getAutodetectionMethod returns the IP auto detection method in a form understandable by the calico/node
// startup processing. It returns an empty string if IP auto detection should not be enabled.
func getAutodetectionMethod(ad *operatorv1.NodeAddressAutodetection) string {
	if ad != nil {
		if len(ad.Interface) != 0 {
			return fmt.Sprintf("interface=%s", ad.Interface)
		}
		if len(ad.SkipInterface) != 0 {
			return fmt.Sprintf("skip-interface=%s", ad.SkipInterface)
		}
		if len(ad.CanReach) != 0 {
			return fmt.Sprintf("can-reach=%s", ad.CanReach)
		}
		if ad.FirstFound != nil && *ad.FirstFound {
			return "first-found"
		}
		if len(ad.CIDRS) != 0 {
			return fmt.Sprintf("cidr=%s", strings.Join(ad.CIDRS, ","))
		}
		if ad.Kubernetes != nil {
			if *ad.Kubernetes == operatorv1.NodeInternalIP {
				return "kubernetes-internal-ip"
			}
		}
	}
	return ""
}

// GetIPv4Pool returns the IPv4 IPPool in an installation, or nil if one can't be found.
func GetIPv4Pool(pools []operatorv1.IPPool) *operatorv1.IPPool {
	for ii, pool := range pools {
		addr, _, err := net.ParseCIDR(pool.CIDR)
		if err == nil {
			if addr.To4() != nil {
				return &pools[ii]
			}
		}
	}

	return nil
}

// GetIPv6Pool returns the IPv6 IPPool in an installation, or nil if one can't be found.
func GetIPv6Pool(pools []operatorv1.IPPool) *operatorv1.IPPool {
	for ii, pool := range pools {
		addr, _, err := net.ParseCIDR(pool.CIDR)
		if err == nil {
			if addr.To4() == nil {
				return &pools[ii]
			}
		}
	}

	return nil
}

// bgpEnabled returns true if the given Installation enables BGP, false otherwise.
func bgpEnabled(instance *operatorv1.InstallationSpec) bool {
	return instance.CalicoNetwork != nil &&
		instance.CalicoNetwork.BGP != nil &&
		*instance.CalicoNetwork.BGP == operatorv1.BGPEnabled
}

// getMTU returns the MTU configured in the Installation if there is one, nil otherwise.
func getMTU(instance *operatorv1.InstallationSpec) *int32 {
	var mtu *int32
	if instance.CalicoNetwork != nil && instance.CalicoNetwork.MTU != nil {
		mtu = instance.CalicoNetwork.MTU
	}
	return mtu
}
