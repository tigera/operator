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

// Node creates the node daemonset and other resources for the daemonset to operate normally.
func Node(cr *operator.Installation, p operator.Provider, nc NetworkConfig) Component {
	return &nodeComponent{cr: cr, provider: p, netConfig: nc}
}

type nodeComponent struct {
	cr        *operator.Installation
	provider  operator.Provider
	netConfig NetworkConfig
}

func (c *nodeComponent) Objects() []runtime.Object {
	objs := []runtime.Object{
		c.nodeServiceAccount(),
		c.nodeRole(),
		c.nodeRoleBinding(),
		c.nodeDaemonset(),
	}
	if c.cr.Spec.Variant == operator.TigeraSecureEnterprise {
		// Include Service for exposing node metrics.
		objs = append(objs, c.nodeMetricsService())
	}

	if cniConfig := c.nodeCNIConfigMap(); cniConfig != nil {
		objs = append(objs, cniConfig)
	}

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
			Namespace: calicoNamespace,
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
				Namespace: calicoNamespace,
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
					"globalnetworksets",
					"hostendpoints",
					"ipamblocks",
					"ippools",
					"networkpolicies",
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

	var config = `{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "datastore_type": "kubernetes",
      "mtu": 1440,
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
}`
	return &v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cni-config",
			Namespace: calicoNamespace,
			Labels:    map[string]string{},
		},
		Data: map[string]string{
			"config": config,
		},
	}
}

// nodeDaemonset creates the node damonset.
func (c *nodeComponent) nodeDaemonset() *apps.DaemonSet {
	var terminationGracePeriod int64 = 0

	ds := apps.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-node",
			Namespace: calicoNamespace,
		},
		Spec: apps.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "calico-node"}},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"k8s-app": "calico-node",
					},
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
				RollingUpdate: &apps.RollingUpdateDaemonSet{
					MaxUnavailable: c.cr.Spec.Components.Node.MaxUnavailable,
				},
			},
		},
	}

	if cniContainer := c.cniContainer(); cniContainer != nil {
		ds.Spec.Template.Spec.InitContainers = append(ds.Spec.Template.Spec.InitContainers, *cniContainer)
	}

	setCriticalPod(&(ds.Spec.Template))
	return &ds
}

// nodeTolerations creates the node's tolerations.
func (c *nodeComponent) nodeTolerations() []v1.Toleration {
	tolerations := []v1.Toleration{
		{Operator: v1.TolerationOpExists, Effect: v1.TaintEffectNoSchedule},
		{Operator: v1.TolerationOpExists, Effect: v1.TaintEffectNoExecute},
		{Operator: v1.TolerationOpExists, Key: "CriticalAddonsOnly"},
	}

	// Merge in any user-supplied overrides.
	tolerations = setCustomTolerations(tolerations, c.cr.Spec.Components.Node.Tolerations)
	return tolerations
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
		{Name: "cni-bin-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: c.cr.Spec.CNIBinDir}}},
		{Name: "cni-net-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: c.cr.Spec.CNINetDir}}},
		{Name: "policysync", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/run/nodeagent", Type: &dirOrCreate}}},
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

	flexVolumePluginsPath := "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
	// In OpenShift 4.x, the location for flexvolume plugins has changed.
	// See: https://bugzilla.redhat.com/show_bug.cgi?id=1667606#c5
	if c.provider == operator.ProviderOpenshift {
		flexVolumePluginsPath = "/etc/kubernetes/kubelet-plugins/volume/exec/"
	}

	// Create and append flexvolume
	flexVolume := v1.Volume{
		Name: "flexvol-driver-host",
		VolumeSource: v1.VolumeSource{
			HostPath: &v1.HostPathVolumeSource{Path: flexVolumePluginsPath + "nodeagent~uds", Type: &dirOrCreate},
		},
	}
	volumes = append(volumes, flexVolume)

	volumes = setCustomVolumes(volumes, c.cr.Spec.Components.Node.ExtraVolumes)
	volumes = setCustomVolumes(volumes, c.cr.Spec.Components.CNI.ExtraVolumes)
	return volumes
}

// cniContainer creates the node's init container that installs CNI.
func (c *nodeComponent) cniContainer() *v1.Container {
	if c.netConfig.CNI == CNINone {
		return nil
	}

	// Determine environment to pass to the CNI init container.
	cniEnv := c.cniEnvvars()
	cniVolumeMounts := []v1.VolumeMount{
		{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
		{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
	}

	// Merge in any user-supplied overrides.
	cniEnv = setCustomEnv(cniEnv, c.cr.Spec.Components.CNI.ExtraEnv)
	cniVolumeMounts = setCustomVolumeMounts(cniVolumeMounts, c.cr.Spec.Components.CNI.ExtraVolumeMounts)

	return &v1.Container{
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

	return []v1.EnvVar{
		{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
		{Name: "SLEEP", Value: "false"},
		{Name: "CNI_NET_DIR", Value: c.cr.Spec.CNINetDir},
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
	res := v1.ResourceRequirements{}
	if len(c.cr.Spec.Components.Node.Resources.Limits) > 0 || len(c.cr.Spec.Components.Node.Resources.Requests) > 0 {
		res.Requests = c.cr.Spec.Components.Node.Resources.Requests
		res.Limits = c.cr.Spec.Components.Node.Resources.Limits
	}
	return res
}

// nodeVolumeMounts creates the node's volume mounts.
func (c *nodeComponent) nodeVolumeMounts() []v1.VolumeMount {
	nodeVolumeMounts := []v1.VolumeMount{
		{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
		{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
		{MountPath: "/var/run/calico", Name: "var-run-calico"},
		{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
		{MountPath: "/var/run/nodeagent", Name: "policysync"},
	}
	if c.cr.Spec.Variant == operator.TigeraSecureEnterprise {
		extraNodeMounts := []v1.VolumeMount{
			{MountPath: "/var/log/calico", Name: "var-log-calico"},
		}
		nodeVolumeMounts = append(nodeVolumeMounts, extraNodeMounts...)
	}

	nodeVolumeMounts = setCustomVolumeMounts(nodeVolumeMounts, c.cr.Spec.Components.Node.ExtraVolumeMounts)
	return nodeVolumeMounts
}

// nodeEnvVars creates the node's envvars.
func (c *nodeComponent) nodeEnvVars() []v1.EnvVar {
	// set the clusterType
	clusterType := "k8s,operator"

	switch c.provider {
	case operator.ProviderOpenshift:
		clusterType = clusterType + ",openshift"
	case operator.ProviderEKS:
		clusterType = clusterType + ",eks"
	}

	if c.netConfig.CNI == CNICalico {
		clusterType = clusterType + ",bgp"
	}

	nodeEnv := []v1.EnvVar{
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
		{Name: "WAIT_FOR_DATASTORE", Value: "true"},
		{Name: "CLUSTER_TYPE", Value: clusterType},
		{Name: "IP", Value: "autodetect"},
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
	}

	// set the networking backend
	if c.netConfig.CNI == CNINone {
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "none"})
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "NO_DEFAULT_POOLS", Value: "true"})
	} else {
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"})
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV4POOL_CIDR", Value: c.cr.Spec.IPPools[0].CIDR})
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"})
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_IPINIPMTU", Value: "1440"})
	}

	if c.cr.Spec.Variant == operator.TigeraSecureEnterprise {
		extraNodeEnv := []v1.EnvVar{
			{Name: "FELIX_PROMETHEUSREPORTERENABLED", Value: "true"},
			{Name: "FELIX_PROMETHEUSREPORTERPORT", Value: fmt.Sprintf("%d", nodeMetricsPort)},
			{Name: "FELIX_FLOWLOGSFILEENABLED", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDELABELS", Value: "true"},
			{Name: "FELIX_FLOWLOGSFILEINCLUDEPOLICIES", Value: "true"},
			{Name: "FELIX_FLOWLOGSENABLENETWORKSETS", Value: "true"},
		}
		nodeEnv = append(nodeEnv, extraNodeEnv...)
	}
	if c.provider == operator.ProviderOpenshift {
		// For Openshift, we need special configuration since our default port is already in use.
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_HEALTHPORT", Value: "9199"})

		// Use iptables in nftables mode.
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_IPTABLESBACKEND", Value: "NFT"})
	}
	if c.provider == operator.ProviderEKS {
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_INTERFACEPREFIX", Value: "eni"})
	}

	nodeEnv = setCustomEnv(nodeEnv, c.cr.Spec.Components.Node.ExtraEnv)
	return nodeEnv
}

// nodeLivenessReadinessProbes creates the node's liveness and readiness probes.
func (c *nodeComponent) nodeLivenessReadinessProbes() (*v1.Probe, *v1.Probe) {
	// Determine liveness and readiness configuration for node.
	livenessPort := intstr.FromInt(9099)
	readinessCmd := []string{"/bin/calico-node", "-bird-ready", "-felix-ready"}

	// if not using calico networking, don't check bird status.
	if c.netConfig.CNI != "calico" {
		readinessCmd = []string{"/bin/calico-node", "-felix-ready"}
	}

	if c.provider == operator.ProviderOpenshift {
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
			Namespace: calicoNamespace,
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
