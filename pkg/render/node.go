// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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

	apps "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operator "github.com/tigera/operator/api/v1"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/migration"
	"github.com/tigera/operator/pkg/dns"
)

const (
	BirdTemplatesConfigMapName = "bird-templates"
	birdTemplateHashAnnotation = "hash.operator.tigera.io/bird-templates"
	nodeCertHashAnnotation     = "hash.operator.tigera.io/node-cert"
	nodeCniConfigAnnotation    = "hash.operator.tigera.io/cni-config"
	CSRLabelCalicoSystem       = "calico-system"
)

var (
	// The port used by calico/node to report Calico Enterprise BGP metrics.
	// This is currently not intended to be user configurable.
	nodeBGPReporterPort int32 = 9900
)

// Node creates the node daemonset and other resources for the daemonset to operate normally.
func Node(
	k8sServiceEp k8sapi.ServiceEndpoint,
	cr *operator.InstallationSpec,
	bt map[string]string,
	tnTLS *TyphaNodeTLS,
	aci *operator.AmazonCloudIntegration,
	migrate bool,
	nodeAppArmorProfile string,
	clusterDomain string,
	nodeReporterMetricsPort int,
) Component {
	return &nodeComponent{
		k8sServiceEp:            k8sServiceEp,
		cr:                      cr,
		birdTemplates:           bt,
		typhaNodeTLS:            tnTLS,
		amazonCloudInt:          aci,
		migrationNeeded:         migrate,
		nodeAppArmorProfile:     nodeAppArmorProfile,
		clusterDomain:           clusterDomain,
		nodeReporterMetricsPort: nodeReporterMetricsPort,
	}
}

type nodeComponent struct {
	k8sServiceEp            k8sapi.ServiceEndpoint
	cr                      *operator.InstallationSpec
	birdTemplates           map[string]string
	typhaNodeTLS            *TyphaNodeTLS
	amazonCloudInt          *operator.AmazonCloudIntegration
	migrationNeeded         bool
	nodeAppArmorProfile     string
	clusterDomain           string
	nodeImage               string
	cniImage                string
	flexvolImage            string
	certSignReqImage        string
	nodeReporterMetricsPort int
}

func (c *nodeComponent) ResolveImages(is *operator.ImageSet) error {
	reg := c.cr.Registry
	path := c.cr.ImagePath
	var err error
	if c.cr.Variant == operator.TigeraSecureEnterprise {
		c.cniImage, err = components.GetReference(components.ComponentTigeraCNI, reg, path, is)
	} else {
		c.cniImage, err = components.GetReference(components.ComponentCalicoCNI, reg, path, is)
	}
	errMsgs := []string{}
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	c.flexvolImage, err = components.GetReference(components.ComponentFlexVolume, reg, path, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if c.cr.Variant == operator.TigeraSecureEnterprise {
		c.nodeImage, err = components.GetReference(components.ComponentTigeraNode, reg, path, is)
	} else {
		c.nodeImage, err = components.GetReference(components.ComponentCalicoNode, reg, path, is)
	}
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if c.cr.CertificateManagement != nil {
		c.certSignReqImage, err = ResolveCSRInitImage(c.cr, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}
	return nil
}

func (c *nodeComponent) SupportedOSType() OSType {
	return OSTypeLinux
}

func (c *nodeComponent) Objects() ([]client.Object, []client.Object) {
	objsToCreate := []client.Object{
		c.nodeServiceAccount(),
		c.nodeRole(),
		c.nodeRoleBinding(),
	}

	var objsToDelete []client.Object

	if c.cr.Variant == operator.TigeraSecureEnterprise {
		// Include Service for exposing node metrics.
		objsToCreate = append(objsToCreate, c.nodeMetricsService())
	}

	cniConfig := c.nodeCNIConfigMap()
	if cniConfig != nil {
		objsToCreate = append(objsToCreate, cniConfig)
	}

	if btcm := c.birdTemplateConfigMap(); btcm != nil {
		objsToCreate = append(objsToCreate, btcm)
	}

	if c.cr.KubernetesProvider == operator.ProviderDockerEE {
		objsToCreate = append(objsToCreate, c.clusterAdminClusterRoleBinding())
	}

	if c.cr.KubernetesProvider != operator.ProviderOpenShift {
		objsToCreate = append(objsToCreate, c.nodePodSecurityPolicy())
	}

	objsToCreate = append(objsToCreate, c.nodeDaemonset(cniConfig))

	if c.cr.CertificateManagement != nil {
		objsToCreate = append(objsToCreate, csrClusterRole())
		objsToCreate = append(objsToCreate, csrClusterRoleBinding("calico-node", common.CalicoNamespace))
	}

	return objsToCreate, objsToDelete
}

func (c *nodeComponent) Ready() bool {
	return true
}

// nodeServiceAccount creates the node's service account.
func (c *nodeComponent) nodeServiceAccount() *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-node",
			Namespace: common.CalicoNamespace,
		},
	}
}

// nodeRoleBinding creates a clusterrolebinding giving the node service account the required permissions to operate.
func (c *nodeComponent) nodeRoleBinding() *rbacv1.ClusterRoleBinding {
	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "calico-node",
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "calico-node",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "calico-node",
				Namespace: common.CalicoNamespace,
			},
		},
	}
	if c.migrationNeeded {
		migration.AddBindingForKubeSystemNode(crb)
	}
	return crb
}

// nodeRole creates the clusterrole containing policy rules that allow the node daemonset to operate normally.
func (c *nodeComponent) nodeRole() *rbacv1.ClusterRole {
	role := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "calico-node",
			Labels: map[string]string{},
		},

		Rules: []rbacv1.PolicyRule{
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
					"networkpolicies",
					"stagedkubernetesnetworkpolicies",
					"stagednetworkpolicies",
					"networksets",
				},
				Verbs: []string{"get", "list", "watch"},
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
		},
	}
	if c.cr.Variant == operator.TigeraSecureEnterprise {
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
		}
		role.Rules = append(role.Rules, extraRules...)
	}
	if c.cr.KubernetesProvider != operator.ProviderOpenShift {
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
func (c *nodeComponent) nodeCNIConfigMap() *v1.ConfigMap {
	if c.cr.CNI.Type != operator.PluginCalico {
		// If calico cni is not being used, then no cni configmap is needed.
		return nil
	}

	// Determine MTU to use for veth interfaces.
	// Zero means to use auto-detection.
	var mtu int32 = 0
	if m := getMTU(c.cr); m != nil {
		mtu = *m
	}

	// Determine per-provider settings.
	nodenameFileOptional := false
	switch c.cr.KubernetesProvider {
	case operatorv1.ProviderDockerEE:
		nodenameFileOptional = true
	}

	// Pull out other settings.
	ipForward := false
	if c.cr.CalicoNetwork.ContainerIPForwarding != nil {
		ipForward = (*c.cr.CalicoNetwork.ContainerIPForwarding == operator.ContainerIPForwardingEnabled)
	}

	// Determine portmap configuration to use.
	var portmap string = ""
	if c.cr.CalicoNetwork.HostPorts != nil && *c.cr.CalicoNetwork.HostPorts == operator.HostPortsEnabled {
		portmap = `,
    {"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}`
	}

	ipam := c.getCalicoIPAM()
	if c.cr.CNI.IPAM.Type == operator.IPAMPluginHostLocal {
		ipam = buildHostLocalIPAM(c.cr.CalicoNetwork)
	}

	var k8sAPIRoot string
	apiRoot := c.k8sServiceEp.CNIAPIRoot()
	if apiRoot != "" {
		k8sAPIRoot = fmt.Sprintf("\n          \"k8s_api_root\":\"%s\",", apiRoot)
	}

	// Build the CNI configuration json.
	var config = fmt.Sprintf(`{
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
      }
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    }%s
  ]
}`, mtu, nodenameFileOptional, ipam, ipForward, k8sAPIRoot, portmap)

	return &v1.ConfigMap{
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
	if v4pool := GetIPv4Pool(c.cr.CalicoNetwork.IPPools); v4pool != nil {
		assign_ipv4 = "true"
	} else {
		assign_ipv4 = "false"
	}
	if v6pool := GetIPv6Pool(c.cr.CalicoNetwork.IPPools); v6pool != nil {
		assign_ipv6 = "true"
	} else {
		assign_ipv6 = "false"
	}
	return fmt.Sprintf(`{ "type": "calico-ipam", "assign_ipv4" : "%s", "assign_ipv6" : "%s"}`,
		assign_ipv4, assign_ipv6,
	)
}

func buildHostLocalIPAM(cns *operator.CalicoNetworkSpec) string {
	return `{ "type": "host-local", "subnet": "usePodCidr"}`
}

func (c *nodeComponent) birdTemplateConfigMap() *v1.ConfigMap {
	if len(c.birdTemplates) == 0 {
		return nil
	}
	cm := v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      BirdTemplatesConfigMapName,
			Namespace: common.CalicoNamespace,
		},
		Data: map[string]string{},
	}
	for k, v := range c.birdTemplates {
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
				Name:      "calico-node",
				Namespace: common.CalicoNamespace,
			},
		},
	}
	return crb
}

// nodeDaemonset creates the node daemonset.
func (c *nodeComponent) nodeDaemonset(cniCfgMap *v1.ConfigMap) *apps.DaemonSet {
	var terminationGracePeriod int64 = 0
	var initContainers []v1.Container

	annotations := make(map[string]string)
	if len(c.birdTemplates) != 0 {
		annotations[birdTemplateHashAnnotation] = AnnotationHash(c.birdTemplates)
	}
	annotations[typhaCAHashAnnotation] = AnnotationHash(c.typhaNodeTLS.CAConfigMap.Data)
	if c.cr.CertificateManagement == nil {
		annotations[nodeCertHashAnnotation] = AnnotationHash(c.typhaNodeTLS.NodeSecret.Data)
	} else {
		annotations[nodeCertHashAnnotation] = AnnotationHash(c.cr.CertificateManagement.CACert)
		initContainers = append(initContainers, CreateCSRInitContainer(
			c.cr,
			c.certSignReqImage,
			"felix-certs",
			FelixCommonName,
			TLSSecretKeyName,
			TLSSecretCertName,
			dns.GetServiceDNSNames(common.NodeDaemonSetName, common.CalicoNamespace, c.clusterDomain),
			CSRLabelCalicoSystem))
	}

	if cniCfgMap != nil {
		annotations[nodeCniConfigAnnotation] = AnnotationHash(cniCfgMap.Data)
	}

	// Include annotation for prometheus scraping configuration.
	if c.cr.NodeMetricsPort != nil {
		annotations["prometheus.io/scrape"] = "true"
		annotations["prometheus.io/port"] = fmt.Sprintf("%d", *c.cr.NodeMetricsPort)
	}

	// check tech preview annotation for calico-node apparmor profile
	if c.nodeAppArmorProfile != "" {
		annotations["container.apparmor.security.beta.kubernetes.io/calico-node"] = c.nodeAppArmorProfile
	}

	if c.cr.FlexVolumePath != "None" {
		initContainers = append(initContainers, c.flexVolumeContainer())
	}

	var affinity *v1.Affinity
	if c.cr.KubernetesProvider == operator.ProviderAKS {
		affinity = &v1.Affinity{
			NodeAffinity: &v1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
					NodeSelectorTerms: []v1.NodeSelectorTerm{{
						MatchExpressions: []v1.NodeSelectorRequirement{{
							Key:      "type",
							Operator: v1.NodeSelectorOpNotIn,
							Values:   []string{"virtual-kubelet"},
						}},
					}},
				},
			},
		}
	}

	ds := apps.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.NodeDaemonSetName,
			Namespace: common.CalicoNamespace,
		},
		Spec: apps.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "calico-node"}},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"k8s-app": "calico-node",
					},
					Annotations: annotations,
				},
				Spec: v1.PodSpec{
					Tolerations:                   tolerateAll,
					Affinity:                      affinity,
					ImagePullSecrets:              c.cr.ImagePullSecrets,
					ServiceAccountName:            "calico-node",
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					HostNetwork:                   true,
					InitContainers:                initContainers,
					Containers:                    []v1.Container{c.nodeContainer()},
					Volumes:                       c.nodeVolumes(),
				},
			},
			UpdateStrategy: c.cr.NodeUpdateStrategy,
		},
	}

	if c.cr.CNI.Type == operator.PluginCalico {
		ds.Spec.Template.Spec.InitContainers = append(ds.Spec.Template.Spec.InitContainers, c.cniContainer())
	}

	setCriticalPod(&(ds.Spec.Template))
	if c.migrationNeeded {
		migration.LimitDaemonSetToMigratedNodes(&ds)
	}
	return &ds
}

// cniDirectories returns the binary and network config directories for the configured platform.
func (c *nodeComponent) cniDirectories() (string, string, string) {
	var cniBinDir, cniNetDir, cniLogDir string
	switch c.cr.KubernetesProvider {
	case operator.ProviderOpenShift:
		cniNetDir = "/var/run/multus/cni/net.d"
		cniBinDir = "/var/lib/cni/bin"
	case operator.ProviderGKE:
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
func (c *nodeComponent) nodeVolumes() []v1.Volume {
	fileOrCreate := v1.HostPathFileOrCreate
	dirOrCreate := v1.HostPathDirectoryOrCreate

	volumes := []v1.Volume{
		{Name: "lib-modules", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/lib/modules"}}},
		{Name: "var-run-calico", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/run/calico"}}},
		{Name: "var-lib-calico", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
		{Name: "xtables-lock", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
		{Name: "policysync", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
		{
			Name: "typha-ca",
			VolumeSource: v1.VolumeSource{
				ConfigMap: &v1.ConfigMapVolumeSource{
					LocalObjectReference: v1.LocalObjectReference{
						Name: TyphaCAConfigMapName,
					},
				},
			},
		},
		{
			Name:         "felix-certs",
			VolumeSource: certificateVolumeSource(c.cr.CertificateManagement, NodeTLSSecretName),
		},
	}

	// If needed for this configuration, then include the CNI volumes.
	if c.cr.CNI.Type == operator.PluginCalico {
		// Determine directories to use for CNI artifacts based on the provider.
		cniNetDir, cniBinDir, cniLogDir := c.cniDirectories()
		volumes = append(volumes, v1.Volume{Name: "cni-bin-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: cniBinDir}}})
		volumes = append(volumes, v1.Volume{Name: "cni-net-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: cniNetDir}}})
		volumes = append(volumes, v1.Volume{Name: "cni-log-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: cniLogDir}}})
	}

	// Override with Tigera-specific config.
	if c.cr.Variant == operator.TigeraSecureEnterprise {
		// Add volume for calico logs.
		calicoLogVol := v1.Volume{
			Name:         "var-log-calico",
			VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/log/calico", Type: &dirOrCreate}},
		}
		volumes = append(volumes, calicoLogVol)
	}

	// Create and append flexvolume
	if c.cr.FlexVolumePath != "None" {
		volumes = append(volumes, v1.Volume{
			Name: "flexvol-driver-host",
			VolumeSource: v1.VolumeSource{
				HostPath: &v1.HostPathVolumeSource{Path: c.cr.FlexVolumePath + "nodeagent~uds", Type: &dirOrCreate},
			},
		})
	}
	if c.birdTemplates != nil {
		volumes = append(volumes,
			v1.Volume{
				Name: "bird-templates",
				VolumeSource: v1.VolumeSource{
					ConfigMap: &v1.ConfigMapVolumeSource{
						LocalObjectReference: v1.LocalObjectReference{
							Name: BirdTemplatesConfigMapName,
						},
					},
				},
			})
	}
	return volumes
}

// cniContainer creates the node's init container that installs CNI.
func (c *nodeComponent) cniContainer() v1.Container {
	// Determine environment to pass to the CNI init container.
	cniEnv := c.cniEnvvars()
	cniVolumeMounts := []v1.VolumeMount{
		{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
		{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
	}

	return v1.Container{
		Name:         "install-cni",
		Image:        c.cniImage,
		Command:      []string{"/opt/cni/bin/install"},
		Env:          cniEnv,
		VolumeMounts: cniVolumeMounts,
		SecurityContext: &v1.SecurityContext{
			Privileged: Bool(true),
		},
	}
}

// flexVolumeContainer creates the node's init container that installs the Unix Domain Socket to allow Dikastes
// to communicate with Felix over the Policy Sync API.
func (c *nodeComponent) flexVolumeContainer() v1.Container {
	flexVolumeMounts := []v1.VolumeMount{
		{MountPath: "/host/driver", Name: "flexvol-driver-host"},
	}

	return v1.Container{
		Name:         "flexvol-driver",
		Image:        c.flexvolImage,
		VolumeMounts: flexVolumeMounts,
		SecurityContext: &v1.SecurityContext{
			Privileged: Bool(true),
		},
	}
}

// cniEnvvars creates the CNI container's envvars.
func (c *nodeComponent) cniEnvvars() []v1.EnvVar {
	if c.cr.CNI.Type != operator.PluginCalico {
		return []v1.EnvVar{}
	}

	// Determine directories to use for CNI artifacts based on the provider.
	cniNetDir, _, _ := c.cniDirectories()

	envVars := []v1.EnvVar{
		{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
		{Name: "SLEEP", Value: "false"},
		{Name: "CNI_NET_DIR", Value: cniNetDir},
		{
			Name: "CNI_NETWORK_CONFIG",
			ValueFrom: &v1.EnvVarSource{
				ConfigMapKeyRef: &v1.ConfigMapKeySelector{
					Key: "config",
					LocalObjectReference: v1.LocalObjectReference{
						Name: "cni-config",
					},
				},
			},
		},
	}

	envVars = append(envVars, c.k8sServiceEp.EnvVars()...)

	if c.cr.Variant == operator.TigeraSecureEnterprise {
		if c.cr.CalicoNetwork != nil && c.cr.CalicoNetwork.MultiInterfaceMode != nil {
			envVars = append(envVars, v1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cr.CalicoNetwork.MultiInterfaceMode.Value()})
		}
	}

	return envVars
}

// nodeContainer creates the main node container.
func (c *nodeComponent) nodeContainer() v1.Container {
	lp, rp := c.nodeLivenessReadinessProbes()
	return v1.Container{
		Name:            "calico-node",
		Image:           c.nodeImage,
		Resources:       c.nodeResources(),
		SecurityContext: &v1.SecurityContext{Privileged: Bool(true)},
		Env:             c.nodeEnvVars(),
		VolumeMounts:    c.nodeVolumeMounts(),
		LivenessProbe:   lp,
		ReadinessProbe:  rp,
	}
}

// nodeResources creates the node's resource requirements.
func (c *nodeComponent) nodeResources() v1.ResourceRequirements {
	return GetResourceRequirements(c.cr, operator.ComponentNameNode)
}

// nodeVolumeMounts creates the node's volume mounts.
func (c *nodeComponent) nodeVolumeMounts() []v1.VolumeMount {
	nodeVolumeMounts := []v1.VolumeMount{
		{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
		{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
		{MountPath: "/var/run/calico", Name: "var-run-calico"},
		{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
		{MountPath: "/var/run/nodeagent", Name: "policysync"},
		{MountPath: "/typha-ca", Name: "typha-ca", ReadOnly: true},
		{MountPath: "/felix-certs", Name: "felix-certs", ReadOnly: true},
	}
	if c.cr.Variant == operator.TigeraSecureEnterprise {
		extraNodeMounts := []v1.VolumeMount{
			{MountPath: "/var/log/calico", Name: "var-log-calico"},
		}
		nodeVolumeMounts = append(nodeVolumeMounts, extraNodeMounts...)
	} else if c.cr.CNI.Type == operator.PluginCalico {
		cniLogMount := v1.VolumeMount{MountPath: "/var/log/calico/cni", Name: "cni-log-dir", ReadOnly: true}
		nodeVolumeMounts = append(nodeVolumeMounts, cniLogMount)
	}

	if c.birdTemplates != nil {
		// create a volume mount for each bird template, but sort them alphabetically first,
		// otherwise, since map iteration is random, they'll be added to the list of volumes in a random order,
		// which will cause another reconciliation event when calico-node is updated.
		sortedKeys := []string{}
		for k := range c.birdTemplates {
			sortedKeys = append(sortedKeys, k)
		}
		sort.Strings(sortedKeys)

		for _, k := range sortedKeys {
			nodeVolumeMounts = append(nodeVolumeMounts,
				v1.VolumeMount{
					Name:      "bird-templates",
					ReadOnly:  true,
					MountPath: fmt.Sprintf("/etc/calico/confd/templates/%s", k),
					SubPath:   k,
				})
		}
	}
	return nodeVolumeMounts
}

// nodeEnvVars creates the node's envvars.
func (c *nodeComponent) nodeEnvVars() []v1.EnvVar {
	// Set the clusterType.
	clusterType := "k8s,operator"

	switch c.cr.KubernetesProvider {
	case operator.ProviderOpenShift:
		clusterType = clusterType + ",openshift"
	case operator.ProviderEKS:
		clusterType = clusterType + ",ecs"
	case operator.ProviderGKE:
		clusterType = clusterType + ",gke"
	case operator.ProviderAKS:
		clusterType = clusterType + ",aks"
	}

	if bgpEnabled(c.cr) {
		clusterType = clusterType + ",bgp"
	}

	var cnEnv v1.EnvVar
	if c.cr.CertificateManagement != nil {
		cnEnv = v1.EnvVar{
			Name: "FELIX_TYPHACN", Value: TyphaCommonName,
		}
	} else {
		cnEnv = v1.EnvVar{
			Name: "FELIX_TYPHACN", ValueFrom: &v1.EnvVarSource{
				SecretKeyRef: &v1.SecretKeySelector{
					LocalObjectReference: v1.LocalObjectReference{
						Name: TyphaTLSSecretName,
					},
					Key:      CommonName,
					Optional: Bool(true),
				},
			},
		}
	}

	nodeEnv := []v1.EnvVar{
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		{Name: "WAIT_FOR_DATASTORE", Value: "true"},
		{Name: "CLUSTER_TYPE", Value: clusterType},
		{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "false"},
		{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
		{Name: "FELIX_HEALTHENABLED", Value: "true"},
		{
			Name: "NODENAME",
			ValueFrom: &v1.EnvVarSource{
				FieldRef: &v1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		},
		{
			Name: "NAMESPACE",
			ValueFrom: &v1.EnvVarSource{
				FieldRef: &v1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
			},
		},
		{Name: "FELIX_TYPHAK8SNAMESPACE", Value: common.CalicoNamespace},
		{Name: "FELIX_TYPHAK8SSERVICENAME", Value: TyphaServiceName},
		{Name: "FELIX_TYPHACAFILE", Value: "/typha-ca/caBundle"},
		{Name: "FELIX_TYPHACERTFILE", Value: fmt.Sprintf("/felix-certs/%s", TLSSecretCertName)},
		{Name: "FELIX_TYPHAKEYFILE", Value: fmt.Sprintf("/felix-certs/%s", TLSSecretKeyName)},

		// We need at least the CN or URISAN set, we depend on the validation
		// done by the core_controller that the Secret will have one.
		cnEnv,
		{Name: "FELIX_TYPHAURISAN", ValueFrom: &v1.EnvVarSource{
			SecretKeyRef: &v1.SecretKeySelector{
				LocalObjectReference: v1.LocalObjectReference{
					Name: TyphaTLSSecretName,
				},
				Key:      URISAN,
				Optional: Bool(true),
			},
		}},
	}

	// If there are no IP pools specified, then configure no default IP pools.
	if c.cr.CalicoNetwork == nil || len(c.cr.CalicoNetwork.IPPools) == 0 {
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "NO_DEFAULT_POOLS", Value: "true"})
	} else {
		// Configure IPv4 pool
		if v4pool := GetIPv4Pool(c.cr.CalicoNetwork.IPPools); v4pool != nil {
			nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV4POOL_CIDR", Value: v4pool.CIDR})

			switch v4pool.Encapsulation {
			case operator.EncapsulationIPIPCrossSubnet:
				nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV4POOL_IPIP", Value: "CrossSubnet"})
			case operator.EncapsulationIPIP:
				nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"})
			case operator.EncapsulationVXLAN:
				nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV4POOL_VXLAN", Value: "Always"})
			case operator.EncapsulationVXLANCrossSubnet:
				nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV4POOL_VXLAN", Value: "CrossSubnet"})
			case operator.EncapsulationNone:
				nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV4POOL_IPIP", Value: "Never"})
			default:
				nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"})
			}

			if v4pool.BlockSize != nil {
				nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV4POOL_BLOCK_SIZE", Value: fmt.Sprintf("%d", *v4pool.BlockSize)})
			}
			if v4pool.NATOutgoing == operator.NATOutgoingDisabled {
				// Default for IPv4 NAT Outgoing is enabled so it is only necessary to
				// set when it is being disabled.
				nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV4POOL_NAT_OUTGOING", Value: "false"})
			}
			if v4pool.NodeSelector != "" {
				nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV4POOL_NODE_SELECTOR", Value: v4pool.NodeSelector})
			}
		}

		// Configure IPv6 pool.
		if v6pool := GetIPv6Pool(c.cr.CalicoNetwork.IPPools); v6pool != nil {
			nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV6POOL_CIDR", Value: v6pool.CIDR})

			if v6pool.BlockSize != nil {
				nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV6POOL_BLOCK_SIZE", Value: fmt.Sprintf("%d", *v6pool.BlockSize)})
			}
			if v6pool.NATOutgoing == operator.NATOutgoingEnabled {
				// Default for IPv6 NAT Outgoing is disabled so it is only necessary to
				// set when it is being enabled.
				nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV6POOL_NAT_OUTGOING", Value: "true"})
			}
			if v6pool.NodeSelector != "" {
				nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV6POOL_NODE_SELECTOR", Value: v6pool.NodeSelector})
			}
		}

	}

	// Determine MTU to use. If specified explicitly, use that. Otherwise, set defaults based on an overall
	// MTU of 1460.
	mtu := getMTU(c.cr)
	if mtu != nil {
		vxlanMtu := strconv.Itoa(int(*mtu))
		wireguardMtu := strconv.Itoa(int(*mtu))
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_VXLANMTU", Value: vxlanMtu})
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_WIREGUARDMTU", Value: wireguardMtu})
	}

	// Configure whether or not BGP should be enabled.
	if !bgpEnabled(c.cr) {
		if c.cr.CNI.Type == operator.PluginCalico {
			if c.cr.CNI.IPAM.Type == operator.IPAMPluginHostLocal {
				// If BGP is disabled and using HostLocal, then that means routing is done
				// by Cloud routing, so networking backend is none. (because we don't support
				// vxlan with HostLocal.)
				nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "none"})
			} else {
				// If BGP is disabled, then set the networking backend to "vxlan". This means that BIRD will be
				// disabled, and VXLAN will optionally be configurable via IP pools.
				nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "vxlan"})
			}
		} else {
			// If not using Calico networking at all, set the backend to "none".
			nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "none"})
		}
	} else {
		// BGP is enabled.
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"})
		if mtu != nil {
			ipipMtu := strconv.Itoa(int(*mtu))
			nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_IPINIPMTU", Value: ipipMtu})
		}
	}

	// IPv4 auto-detection configuration.
	var v4Method string
	if c.cr.CalicoNetwork != nil {
		v4Method = getAutodetectionMethod(c.cr.CalicoNetwork.NodeAddressAutodetectionV4)
	}
	if v4Method != "" {
		// IPv4 Auto-detection is enabled.
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "IP", Value: "autodetect"})
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "IP_AUTODETECTION_METHOD", Value: v4Method})
	} else {
		// IPv4 Auto-detection is disabled.
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "IP", Value: "none"})
	}

	// IPv6 auto-detection and ippool configuration.
	var v6Method string
	if c.cr.CalicoNetwork != nil {
		v6Method = getAutodetectionMethod(c.cr.CalicoNetwork.NodeAddressAutodetectionV6)
	}
	if v6Method != "" {
		// IPv6 Auto-detection is enabled.
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "IP6", Value: "autodetect"})
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "IP6_AUTODETECTION_METHOD", Value: v6Method})
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_IPV6SUPPORT", Value: "true"})

		// Set CALICO_ROUTER_ID to "hash" if IPv6 only.
		if v4Method == "" {
			nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_ROUTER_ID", Value: "hash"})
		}
	} else {
		// IPv6 Auto-detection is disabled.
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "IP6", Value: "none"})
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_IPV6SUPPORT", Value: "false"})
	}

	if c.cr.Variant == operator.TigeraSecureEnterprise {
		// Add in Calico Enterprise specific configuration.
		extraNodeEnv := []v1.EnvVar{
			{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
			{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: fmt.Sprintf("%d", c.nodeReporterMetricsPort)},
			{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDELABELS", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDEPOLICIES", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDESERVICE", Value: "true"},
			{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
			{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
			{Name: "FELIX_DNSLOGSFILEPERNODELIMIT", Value: "1000"},
		}

		if c.cr.CalicoNetwork != nil && c.cr.CalicoNetwork.MultiInterfaceMode != nil {
			extraNodeEnv = append(extraNodeEnv, v1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cr.CalicoNetwork.MultiInterfaceMode.Value()})
		}

		nodeEnv = append(nodeEnv, extraNodeEnv...)
	}

	if c.cr.NodeMetricsPort != nil {
		// If a node metrics port was given, then enable felix prometheus metrics and set the port.
		// Note that this takes precedence over any FelixConfiguration resources in the cluster.
		extraNodeEnv := []v1.EnvVar{
			{Name: "FELIX_PROMETHEUSMETRICSENABLED", Value: "true"},
			{Name: "FELIX_PROMETHEUSMETRICSPORT", Value: fmt.Sprintf("%d", *c.cr.NodeMetricsPort)},
		}
		nodeEnv = append(nodeEnv, extraNodeEnv...)
	}

	// Configure provider specific environment variables here.
	switch c.cr.KubernetesProvider {
	case operator.ProviderOpenShift:
		// For Openshift, we need special configuration since our default port is already in use.
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_HEALTHPORT", Value: "9199"})
		if c.cr.Variant == operator.TigeraSecureEnterprise {
			// We also need to configure a non-default trusted DNS server, since there's no kube-dns.
			nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_DNSTRUSTEDSERVERS", Value: "k8s-service:openshift-dns/dns-default"})
		}
	}

	switch c.cr.CNI.Type {
	case operator.PluginAmazonVPC:
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "eni"})
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"})
	case operator.PluginGKE:
		// The GKE CNI plugin uses its own interface prefix.
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "gke"})
		// The GKE CNI plugin has its own iptables rules. Defer to them after ours.
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"})
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_IPTABLESFILTERALLOWACTION", Value: "Return"})
		// Don't conflict with the GKE CNI plugin's routes.
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_ROUTETABLERANGE", Value: "10-250"})
	case operator.PluginAzureVNET:
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "azv"})
	}

	if c.cr.CNI.Type != operator.PluginCalico {
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_ROUTESOURCE", Value: "WorkloadIPs"})
	}

	if c.amazonCloudInt != nil {
		nodeEnv = append(nodeEnv, GetTigeraSecurityGroupEnvVariables(c.amazonCloudInt)...)
		nodeEnv = append(nodeEnv, v1.EnvVar{
			Name:  "FELIX_FAILSAFEINBOUNDHOSTPORTS",
			Value: "tcp:22,udp:68,tcp:179,tcp:443,tcp:5473,tcp:6443",
		})
		nodeEnv = append(nodeEnv, v1.EnvVar{
			Name:  "FELIX_FAILSAFEOUTBOUNDHOSTPORTS",
			Value: "udp:53,udp:67,tcp:179,tcp:443,tcp:5473,tcp:6443",
		})
	}

	nodeEnv = append(nodeEnv, c.k8sServiceEp.EnvVars()...)

	return nodeEnv
}

// nodeLivenessReadinessProbes creates the node's liveness and readiness probes.
func (c *nodeComponent) nodeLivenessReadinessProbes() (*v1.Probe, *v1.Probe) {
	// Determine liveness and readiness configuration for node.
	livenessPort := intstr.FromInt(9099)
	readinessCmd := []string{"/bin/calico-node", "-bird-ready", "-felix-ready"}

	// Want to check for BGP metrics server if this is enterprise
	if c.cr.Variant == operator.TigeraSecureEnterprise {
		readinessCmd = []string{"/bin/calico-node", "-bird-ready", "-felix-ready", "-bgp-metrics-ready"}
	}

	// If not using BGP, don't check bird status (or bgp metrics server for enterprise).
	if !bgpEnabled(c.cr) {
		readinessCmd = []string{"/bin/calico-node", "-felix-ready"}
	}

	// For Openshift, we need a different port since our default port is already in use.
	if c.cr.KubernetesProvider == operator.ProviderOpenShift {
		livenessPort = intstr.FromInt(9199)
	}

	lp := &v1.Probe{
		Handler: v1.Handler{
			HTTPGet: &v1.HTTPGetAction{
				Host: "localhost",
				Path: "/liveness",
				Port: livenessPort,
			},
		},
	}
	rp := &v1.Probe{
		Handler: v1.Handler{Exec: &v1.ExecAction{Command: readinessCmd}},
	}
	return lp, rp
}

// nodeMetricsService creates a Service which exposes two endpoints on calico/node for
// reporting Prometheus metrics (for policy enforcement activity and BGP stats).
// This service is used internally by Calico Enterprise and is separate from general
// Prometheus metrics which are user-configurable.
func (c *nodeComponent) nodeMetricsService() *v1.Service {
	return &v1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-node-metrics",
			Namespace: common.CalicoNamespace,
			Labels:    map[string]string{"k8s-app": "calico-node"},
		},
		Spec: v1.ServiceSpec{
			Selector: map[string]string{"k8s-app": "calico-node"},
			Type:     v1.ServiceTypeClusterIP,
			Ports: []v1.ServicePort{
				{
					Name:       "calico-metrics-port",
					Port:       int32(c.nodeReporterMetricsPort),
					TargetPort: intstr.FromInt(c.nodeReporterMetricsPort),
					Protocol:   v1.ProtocolTCP,
				},
				{
					Name:       "calico-bgp-metrics-port",
					Port:       nodeBGPReporterPort,
					TargetPort: intstr.FromInt(int(nodeBGPReporterPort)),
					Protocol:   v1.ProtocolTCP,
				},
			},
		},
	}
}

func (c *nodeComponent) nodePodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := basePodSecurityPolicy()
	psp.GetObjectMeta().SetName(common.NodeDaemonSetName)
	psp.Spec.Privileged = true
	psp.Spec.AllowPrivilegeEscalation = Bool(true)
	psp.Spec.Volumes = append(psp.Spec.Volumes, policyv1beta1.HostPath)
	psp.Spec.HostNetwork = true
	psp.Spec.RunAsUser.Rule = policyv1beta1.RunAsUserStrategyRunAsAny
	return psp
}

// getAutodetectionMethod returns the IP auto detection method in a form understandable by the calico/node
// startup processing. It returns an empty string if IP auto detection should not be enabled.
func getAutodetectionMethod(ad *operator.NodeAddressAutodetection) string {
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
	}
	return ""
}

// GetIPv4Pool returns the IPv4 IPPool in an instalation, or nil if one can't be found.
func GetIPv4Pool(pools []operator.IPPool) *operator.IPPool {
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

// GetIPv6Pool returns the IPv6 IPPool in an instalation, or nil if one can't be found.
func GetIPv6Pool(pools []operator.IPPool) *operator.IPPool {
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
func bgpEnabled(instance *operator.InstallationSpec) bool {
	return instance.CalicoNetwork != nil &&
		instance.CalicoNetwork.BGP != nil &&
		*instance.CalicoNetwork.BGP == operatorv1.BGPEnabled
}

// getMTU returns the MTU configured in the Installation if there is one, nil otherwise.
func getMTU(instance *operator.InstallationSpec) *int32 {
	var mtu *int32
	if instance.CalicoNetwork != nil && instance.CalicoNetwork.MTU != nil {
		mtu = instance.CalicoNetwork.MTU
	}
	return mtu
}
