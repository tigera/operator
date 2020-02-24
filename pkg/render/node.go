// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	"strconv"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"

	apps "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var (
	nodeMetricsPort int32 = 9081
)

const (
	BirdTemplatesConfigMapName = "bird-templates"
	birdTemplateHashAnnotation = "hash.operator.tigera.io/bird-templates"
	nodeCertHashAnnotation     = "hash.operator.tigera.io/node-cert"
)

// Node creates the node daemonset and other resources for the daemonset to operate normally.
func Node(cr *operator.Installation, p operator.Provider, nc NetworkConfig, bt map[string]string, tnTLS *TyphaNodeTLS) Component {
	return &nodeComponent{cr: cr, provider: p, netConfig: nc, birdTemplates: bt, typhaNodeTLS: tnTLS}
}

type nodeComponent struct {
	cr            *operator.Installation
	provider      operator.Provider
	netConfig     NetworkConfig
	birdTemplates map[string]string
	typhaNodeTLS  *TyphaNodeTLS
}

func (c *nodeComponent) Objects() []runtime.Object {
	objs := []runtime.Object{
		c.nodeServiceAccount(),
		c.nodeRole(),
		c.nodeRoleBinding(),
	}
	if c.cr.Spec.Variant == operator.TigeraSecureEnterprise {
		// Include Service for exposing node metrics.
		objs = append(objs, c.nodeMetricsService())
	}

	if cniConfig := c.nodeCNIConfigMap(); cniConfig != nil {
		objs = append(objs, cniConfig)
	}

	if btcm := c.birdTemplateConfigMap(); btcm != nil {
		objs = append(objs, btcm)
	}

	if c.provider == operator.ProviderDockerEE {
		objs = append(objs, c.clusterAdminClusterRoleBinding())
	}

	objs = append(objs, c.nodeDaemonset())

	return objs
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
			Namespace: CalicoNamespace,
		},
	}
}

// nodeRoleBinding creates a clusterrolebinding giving the node service account the required permissions to operate.
func (c *nodeComponent) nodeRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
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
				Namespace: CalicoNamespace,
			},
		},
	}
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
	if c.cr.Spec.Variant == operator.TigeraSecureEnterprise {
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
	return role
}

// nodeCNIConfigMap returns a config map containing the CNI network config to be installed on each node.
// Returns nil if no configmap is needed.
func (c *nodeComponent) nodeCNIConfigMap() *v1.ConfigMap {
	if c.netConfig.CNI == CNINone {
		// If calico cni is not being used, then no cni configmap is needed.
		return nil
	}

	// Determine MTU to use for veth interfaces.
	var mtu int32 = 1410
	if c.cr.Spec.CalicoNetwork.MTU != nil {
		mtu = *c.cr.Spec.CalicoNetwork.MTU
	}

	var config = fmt.Sprintf(`{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": %d,
      "nodename_file_optional": %v,
      "ipam": {
          "type": "calico-ipam"
      },
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "__KUBECONFIG_FILEPATH__"
      }
    },
    {
      "type": "portmap",
      "snat": true,
      "capabilities": {"portMappings": true}
    }
  ]
}`, mtu, c.netConfig.NodenameFileOptional)
	return &v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cni-config",
			Namespace: CalicoNamespace,
			Labels:    map[string]string{},
		},
		Data: map[string]string{
			"config": config,
		},
	}
}

func (c *nodeComponent) birdTemplateConfigMap() *v1.ConfigMap {
	if len(c.birdTemplates) == 0 {
		return nil
	}
	cm := v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      BirdTemplatesConfigMapName,
			Namespace: CalicoNamespace,
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
	return &rbacv1.ClusterRoleBinding{
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
				Namespace: CalicoNamespace,
			},
		},
	}
}

// nodeDaemonset creates the node damonset.
func (c *nodeComponent) nodeDaemonset() *apps.DaemonSet {
	var terminationGracePeriod int64 = 0

	annotations := make(map[string]string)
	if len(c.birdTemplates) != 0 {
		annotations[birdTemplateHashAnnotation] = AnnotationHash(c.birdTemplates)
	}
	annotations[typhaCAHashAnnotation] = AnnotationHash(c.typhaNodeTLS.CAConfigMap.Data)
	annotations[nodeCertHashAnnotation] = AnnotationHash(c.typhaNodeTLS.NodeSecret.Data)

	ds := apps.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-node",
			Namespace: CalicoNamespace,
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
					NodeSelector:                  map[string]string{},
					Tolerations:                   c.nodeTolerations(),
					ImagePullSecrets:              c.cr.Spec.ImagePullSecrets,
					ServiceAccountName:            "calico-node",
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					HostNetwork:                   true,
					InitContainers:                []v1.Container{c.flexVolumeContainer()},
					Containers:                    []v1.Container{c.nodeContainer()},
					Volumes:                       c.nodeVolumes(),
				},
			},
			UpdateStrategy: apps.DaemonSetUpdateStrategy{
				RollingUpdate: &apps.RollingUpdateDaemonSet{},
			},
		},
	}

	if c.netConfig.CNI != CNINone {
		ds.Spec.Template.Spec.InitContainers = append(ds.Spec.Template.Spec.InitContainers, c.cniContainer())
	}

	setCriticalPod(&(ds.Spec.Template))
	return &ds
}

// nodeTolerations creates the node's tolerations.
func (c *nodeComponent) nodeTolerations() []v1.Toleration {
	return []v1.Toleration{
		{Operator: v1.TolerationOpExists, Effect: v1.TaintEffectNoSchedule},
		{Operator: v1.TolerationOpExists, Effect: v1.TaintEffectNoExecute},
		{Operator: v1.TolerationOpExists, Key: "CriticalAddonsOnly"},
	}
}

// cniDirectories returns the binary and network config directories for the configured platform.
func (c *nodeComponent) cniDirectories() (string, string) {
	var cniBinDir, cniNetDir string
	switch c.provider {
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
	return cniNetDir, cniBinDir
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
			Name: "felix-certs",
			VolumeSource: v1.VolumeSource{
				Secret: &v1.SecretVolumeSource{
					SecretName: NodeTLSSecretName,
				},
			},
		},
	}

	// If needed for this configuration, then include the CNI volumes.
	if c.netConfig.CNI != CNINone {
		// Determine directories to use for CNI artifacts based on the provider.
		cniNetDir, cniBinDir := c.cniDirectories()
		volumes = append(volumes, v1.Volume{Name: "cni-bin-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: cniBinDir}}})
		volumes = append(volumes, v1.Volume{Name: "cni-net-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: cniNetDir}}})
	}

	// Override with Tigera-specific config.
	if c.cr.Spec.Variant == operator.TigeraSecureEnterprise {
		// Add volume for calico logs.
		calicoLogVol := v1.Volume{
			Name:         "var-log-calico",
			VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/log/calico", Type: &dirOrCreate}},
		}
		volumes = append(volumes, calicoLogVol)
	}

	// Set the flex volume plugin location based on platform.
	flexVolumePluginsPath := "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
	if c.provider == operator.ProviderOpenShift {
		// In OpenShift 4.x, the location for flexvolume plugins has changed.
		// See: https://bugzilla.redhat.com/show_bug.cgi?id=1667606#c5
		flexVolumePluginsPath = "/etc/kubernetes/kubelet-plugins/volume/exec/"
	} else if c.provider == operator.ProviderGKE {
		flexVolumePluginsPath = "/home/kubernetes/flexvolume/"
	} else if c.provider == operator.ProviderAKS {
		flexVolumePluginsPath = "/etc/kubernetes/volumeplugins/"
	}

	// Create and append flexvolume
	volumes = append(volumes, v1.Volume{
		Name: "flexvol-driver-host",
		VolumeSource: v1.VolumeSource{
			HostPath: &v1.HostPathVolumeSource{Path: flexVolumePluginsPath + "nodeagent~uds", Type: &dirOrCreate},
		},
	})
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
		Image:        constructImage(CNIImageName, c.cr.Spec.Registry),
		Command:      []string{"/install-cni.sh"},
		Env:          cniEnv,
		VolumeMounts: cniVolumeMounts,
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
		Image:        constructImage(FlexVolumeImageName, c.cr.Spec.Registry),
		VolumeMounts: flexVolumeMounts,
	}
}

// cniEnvvars creates the CNI container's envvars.
func (c *nodeComponent) cniEnvvars() []v1.EnvVar {
	if c.netConfig.CNI == CNINone {
		return []v1.EnvVar{}
	}

	// Determine directories to use for CNI artifacts based on the provider.
	cniNetDir, _ := c.cniDirectories()

	return []v1.EnvVar{
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
}

// nodeContainer creates the main node container.
func (c *nodeComponent) nodeContainer() v1.Container {
	lp, rp := c.nodeLivenessReadinessProbes()
	isPrivileged := true

	// Select which image to use.
	image := constructImage(NodeImageNameCalico, c.cr.Spec.Registry)
	if c.cr.Spec.Variant == operator.TigeraSecureEnterprise {
		image = constructImage(NodeImageNameTigera, c.cr.Spec.Registry)
	}
	return v1.Container{
		Name:            "calico-node",
		Image:           image,
		Resources:       c.nodeResources(),
		SecurityContext: &v1.SecurityContext{Privileged: &isPrivileged},
		Env:             c.nodeEnvVars(),
		VolumeMounts:    c.nodeVolumeMounts(),
		LivenessProbe:   lp,
		ReadinessProbe:  rp,
	}
}

// nodeResources creates the node's resource requirements.
func (c *nodeComponent) nodeResources() v1.ResourceRequirements {
	return v1.ResourceRequirements{}
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
	if c.cr.Spec.Variant == operator.TigeraSecureEnterprise {
		extraNodeMounts := []v1.VolumeMount{
			{MountPath: "/var/log/calico", Name: "var-log-calico"},
		}
		nodeVolumeMounts = append(nodeVolumeMounts, extraNodeMounts...)
	}

	if c.birdTemplates != nil {
		for k := range c.birdTemplates {
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

	switch c.provider {
	case operator.ProviderOpenShift:
		clusterType = clusterType + ",openshift"
	case operator.ProviderEKS:
		clusterType = clusterType + ",ecs"
	case operator.ProviderGKE:
		clusterType = clusterType + ",gke"
	case operator.ProviderAKS:
		clusterType = clusterType + ",aks"
	}

	if c.netConfig.CNI == CNICalico {
		clusterType = clusterType + ",bgp"
	}

	optional := true
	nodeEnv := []v1.EnvVar{
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		{Name: "WAIT_FOR_DATASTORE", Value: "true"},
		{Name: "CLUSTER_TYPE", Value: clusterType},
		{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "true"},
		{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
		{Name: "FELIX_IPV6SUPPORT", Value: "false"},
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
		{Name: "FELIX_TYPHAK8SNAMESPACE", Value: CalicoNamespace},
		{Name: "FELIX_TYPHAK8SSERVICENAME", Value: TyphaServiceName},
		{Name: "FELIX_TYPHACAFILE", Value: "/typha-ca/caBundle"},
		{Name: "FELIX_TYPHACERTFILE", Value: fmt.Sprintf("/felix-certs/%s", TLSSecretCertName)},
		{Name: "FELIX_TYPHAKEYFILE", Value: fmt.Sprintf("/felix-certs/%s", TLSSecretKeyName)},
		// We need at least the CN or URISAN set, we depend on the validation
		// done by the core_controller that the Secret will have one.
		{Name: "FELIX_TYPHACN", ValueFrom: &v1.EnvVarSource{
			SecretKeyRef: &v1.SecretKeySelector{
				LocalObjectReference: v1.LocalObjectReference{
					Name: TyphaTLSSecretName,
				},
				Key:      CommonName,
				Optional: &optional,
			},
		}},
		{Name: "FELIX_TYPHAURISAN", ValueFrom: &v1.EnvVarSource{
			SecretKeyRef: &v1.SecretKeySelector{
				LocalObjectReference: v1.LocalObjectReference{
					Name: TyphaTLSSecretName,
				},
				Key:      URISAN,
				Optional: &optional,
			},
		}},
	}

	// Set networking-specific configuration.
	if c.netConfig.CNI == CNINone {
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "none"})
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "NO_DEFAULT_POOLS", Value: "true"})
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "IP", Value: "none"})
	} else {
		// Determine MTU to use. If specified explicitly, use that. Otherwise, set defaults.
		ipipMtu := "1440"
		vxlanMtu := "1410"
		if c.cr.Spec.CalicoNetwork.MTU != nil {
			ipipMtu = strconv.Itoa(int(*c.cr.Spec.CalicoNetwork.MTU))
			vxlanMtu = strconv.Itoa(int(*c.cr.Spec.CalicoNetwork.MTU))
		}
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_IPINIPMTU", Value: ipipMtu})
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_VXLANMTU", Value: vxlanMtu})
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"})

		// Env based on IPv4 auto-detection configuration.
		v4Method := getAutodetectionMethod(c.cr.Spec.CalicoNetwork.NodeAddressAutodetectionV4)
		if v4Method != "" {
			// IPv4 Auto-detection is enabled.
			nodeEnv = append(nodeEnv, v1.EnvVar{Name: "IP", Value: "autodetect"})
			nodeEnv = append(nodeEnv, v1.EnvVar{Name: "IP_AUTODETECTION_METHOD", Value: v4Method})
		} else {
			// IPv4 Auto-detection is disabled.
			nodeEnv = append(nodeEnv, v1.EnvVar{Name: "IP", Value: "none"})
		}

		// Env based on IPv6 auto-detection configuration.
		v6Method := getAutodetectionMethod(c.cr.Spec.CalicoNetwork.NodeAddressAutodetectionV6)
		if v6Method != "" {
			// IPv6 Auto-detection is enabled.
			nodeEnv = append(nodeEnv, v1.EnvVar{Name: "IP6", Value: "autodetect"})
			nodeEnv = append(nodeEnv, v1.EnvVar{Name: "IP6_AUTODETECTION_METHOD", Value: v6Method})
		} else {
			// IPv6 Auto-detection is disabled.
			nodeEnv = append(nodeEnv, v1.EnvVar{Name: "IP6", Value: "none"})
		}

		if len(c.cr.Spec.CalicoNetwork.IPPools) == 1 {
			pool := c.cr.Spec.CalicoNetwork.IPPools[0]
			// set the networking backend
			nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV4POOL_CIDR", Value: pool.CIDR})
			switch pool.Encapsulation {
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

			// Default for NAT Outgoing is enabled so it is only necessary to
			// set when it is being disabled.
			if pool.NATOutgoing == operator.NATOutgoingDisabled {
				nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV4POOL_NAT_OUTGOING", Value: "false"})
			}
			if pool.NodeSelector != "" {
				nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV4POOL_NODE_SELECTOR", Value: pool.NodeSelector})
			}
			if pool.BlockSize != nil {
				nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV4POOL_BLOCK_SIZE", Value: fmt.Sprintf("%d", *pool.BlockSize)})
			}

		} else if len(c.cr.Spec.CalicoNetwork.IPPools) == 0 {
			nodeEnv = append(nodeEnv, v1.EnvVar{Name: "NO_DEFAULT_POOLS", Value: "true"})
		}
	}

	if c.cr.Spec.Variant == operator.TigeraSecureEnterprise {
		extraNodeEnv := []v1.EnvVar{
			{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
			{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: fmt.Sprintf("%d", nodeMetricsPort)},
			{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDELABELS", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDEPOLICIES", Value: "true"},
			{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
			{Name: "FELIX_DNSLOGSFILEENABLED", Value: "true"},
			{Name: "FELIX_DNSLOGSFILEPERNODELIMIT", Value: "1000"},
		}
		nodeEnv = append(nodeEnv, extraNodeEnv...)
	}

	iptablesBackend := "auto"

	// Configure provider specific environment variables here.
	switch c.provider {
	case operator.ProviderOpenShift:
		// For Openshift, we need special configuration since our default port is already in use.
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_HEALTHPORT", Value: "9199"})
		if c.cr.Spec.Variant == operator.TigeraSecureEnterprise {
			// TODO: Remove this once the private node/felix is updated to support the auto
			// option.
			// Use iptables in nftables mode.
			iptablesBackend = "NFT"
		}
	case operator.ProviderEKS:
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "eni"})
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"})
	case operator.ProviderGKE:
		// The GKE CNI plugin uses its own interface prefix.
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "gke"})
		// The GKE CNI plugin has its own iptables rules. Defer to them after ours.
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"})
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_IPTABLESFILTERALLOWACTION", Value: "Return"})
	case operator.ProviderAKS:
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "azv"})
	}
	nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_IPTABLESBACKEND", Value: iptablesBackend})
	return nodeEnv
}

// nodeLivenessReadinessProbes creates the node's liveness and readiness probes.
func (c *nodeComponent) nodeLivenessReadinessProbes() (*v1.Probe, *v1.Probe) {
	// Determine liveness and readiness configuration for node.
	livenessPort := intstr.FromInt(9099)
	readinessCmd := []string{"/bin/calico-node", "-bird-ready", "-felix-ready"}

	// if not using calico networking, don't check bird status.
	if c.netConfig.CNI != CNICalico {
		readinessCmd = []string{"/bin/calico-node", "-felix-ready"}
	}

	if c.provider == operator.ProviderOpenShift {
		// For Openshift, we need special configuration since our default port is already in use.
		// Additionally, since the node readiness probe doesn't yet support
		// custom ports, we need to disable felix readiness for now.
		livenessPort = intstr.FromInt(9199)
		readinessCmd = []string{"/bin/calico-node", "-bird-ready"}
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

// nodeMetricsServices creates a Service which exposes the calico/node metrics
// reporting endpoint.
func (c *nodeComponent) nodeMetricsService() *v1.Service {
	return &v1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-node-metrics",
			Namespace: CalicoNamespace,
			Labels:    map[string]string{"k8s-app": "calico-node"},
		},
		Spec: v1.ServiceSpec{
			Selector: map[string]string{"k8s-app": "calico-node"},
			Type:     v1.ServiceTypeClusterIP,
			Ports: []v1.ServicePort{
				v1.ServicePort{
					Name:       "calico-metrics-port",
					Port:       nodeMetricsPort,
					TargetPort: intstr.FromInt(int(nodeMetricsPort)),
					Protocol:   v1.ProtocolTCP,
				},
			},
		},
	}
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
	}
	return ""
}
