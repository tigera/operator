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
	"os"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"

	apps "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	defaultCNIImageName        = "calico/cni"
	defaultCalicoNodeImageName = "calico/node"
	defaultTigeraNodeImageName = "tigera/cnx-node"
)

func Node(cr *operator.Installation) []runtime.Object {
	return []runtime.Object{
		nodeServiceAccount(cr),
		nodeRole(cr),
		nodeRoleBinding(cr),
		nodeCNIConfigMap(cr),
		nodeDaemonset(cr),
	}
}

func nodeServiceAccount(cr *operator.Installation) *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-node",
			Namespace: calicoNamespace,
		},
	}
}

func nodeRoleBinding(cr *operator.Installation) *rbacv1.ClusterRoleBinding {
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

func nodeRole(cr *operator.Installation) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "calico-node",
			Labels: map[string]string{},
		},
		// TODO: Comments explaining why each permission is needed.
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
				APIGroups: []string{""},
				Resources: []string{"nodes/status"},
				Verbs:     []string{"patch", "update"},
			},
			{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"watch", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "namespaces", "serviceaccounts"},
				Verbs:     []string{"watch", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods/status"},
				Verbs:     []string{"patch"},
			},
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"bgpconfigurations",
					"bgppeers",
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
				// For migration code only. Remove when no longer needed.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"globalbgpconfigs",
					"globalfelixconfigs",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"clusterinformations",
					"felixconfigurations",
					"ippools",
				},
				Verbs: []string{"create", "update"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"blockaffinities",
					"ipamblocks",
					"ipamhandles",
				},
				Verbs: []string{"get", "list", "create", "update", "delete"},
			},
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"ipamconfigs"},
				Verbs:     []string{"get"},
			},
			{
				// confd watches block affinities for route aggregation.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"blockaffinities"},
				Verbs:     []string{"watch"},
			},
		},
	}
}

// nodeCNIConfigMap returns a config map containing the CNI network config to be installed on each node.
func nodeCNIConfigMap(cr *operator.Installation) *v1.ConfigMap {
	var config = `{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.0",
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

func nodeDaemonset(cr *operator.Installation) *apps.DaemonSet {
	// Build image strings to use.
	imageName := defaultCalicoNodeImageName
	if cr.Spec.Variant == operator.TigeraSecureEnterprise {
		imageName = defaultTigeraNodeImageName
	}
	nodeImage := fmt.Sprintf("%s%s:%s", cr.Spec.Registry, imageName, cr.Spec.Version)
	if len(cr.Spec.Components.Node.ImageOverride) > 0 {
		nodeImage = cr.Spec.Components.Node.ImageOverride
	}
	cniImage := fmt.Sprintf("%s%s:%s", cr.Spec.Registry, defaultCNIImageName, cr.Spec.Version)
	if len(cr.Spec.Components.CNI.ImageOverride) > 0 {
		cniImage = cr.Spec.Components.CNI.ImageOverride
	}

	tolerations := []v1.Toleration{
		{Operator: v1.TolerationOpExists, Effect: v1.TaintEffectNoSchedule},
		{Operator: v1.TolerationOpExists, Effect: v1.TaintEffectNoExecute},
		{Operator: v1.TolerationOpExists, Key: "CriticalAddonsOnly"},
	}
	tolerations = setCustomTolerations(tolerations, cr.Spec.Components.Node.Tolerations)

	nodeVolumeMounts := []v1.VolumeMount{
		{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
		{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
		{MountPath: "/var/run/calico", Name: "var-run-calico"},
		{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
	}
	nodeVolumeMounts = setCustomVolumeMounts(nodeVolumeMounts, cr.Spec.Components.Node.ExtraVolumeMounts)

	cniVolumeMounts := []v1.VolumeMount{
		{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
		{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
	}
	cniVolumeMounts = setCustomVolumeMounts(cniVolumeMounts, cr.Spec.Components.CNI.ExtraVolumeMounts)

	var fileOrCreate = v1.HostPathFileOrCreate
	allVolumes := []v1.Volume{
		{Name: "lib-modules", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/lib/modules"}}},
		{Name: "var-run-calico", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/run/calico"}}},
		{Name: "var-lib-calico", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
		{Name: "xtables-lock", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
		{Name: "cni-bin-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: cr.Spec.CNIBinDir}}},
		{Name: "cni-net-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: cr.Spec.CNINetDir}}},
	}
	allVolumes = setCustomVolumes(allVolumes, cr.Spec.Components.Node.ExtraVolumes)
	allVolumes = setCustomVolumes(allVolumes, cr.Spec.Components.CNI.ExtraVolumes)

	// Determine environment to pass to the node container.
	nodeEnv := []v1.EnvVar{
		{Name: "DATASTORE_TYPE", Value: string(cr.Spec.Datastore.Type)},
		{Name: "WAIT_FOR_DATASTORE", Value: "true"},
		{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
		{Name: "CLUSTER_TYPE", Value: "k8s,bgp,operator"},
		{Name: "IP", Value: "autodetect"},
		{Name: "CALICO_IPV4POOL_CIDR", Value: cr.Spec.IPPools[0].CIDR},
		{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"},
		{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "true"},
		{Name: "FELIX_IPINIPMTU", Value: "1440"},
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

	// Determine liveness and readiness configuration for node.
	livenessPort := intstr.FromInt(9099)
	readinessCmd := []string{"/bin/calico-node", "-bird-ready", "-felix-ready"}
	if os.Getenv("OPENSHIFT") == "true" {
		// TODO: For Openshift, we need special configuration since our default port is already in use.
		// Additionally, since the node readiness probe doesn't yet support
		// custom ports, we need to disable felix readiness for now.
		livenessPort = intstr.FromInt(9199)
		readinessCmd = []string{"/bin/calico-node", "-bird-ready"}
		nodeEnv = append(nodeEnv, v1.EnvVar{Name: "FELIX_HEALTHPORT", Value: "9199"})
	}

	// Merge in any user-supplied extra environment variables into the node environment.
	nodeEnv = setCustomEnv(nodeEnv, cr.Spec.Components.Node.ExtraEnv)

	// Determine environment to pass to the CNI init container.
	cniEnv := []v1.EnvVar{
		{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
		{Name: "SLEEP", Value: "false"},
		{Name: "CNI_NET_DIR", Value: cr.Spec.CNINetDir},
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
	cniEnv = setCustomEnv(cniEnv, cr.Spec.Components.CNI.ExtraEnv)

	nodeResources := v1.ResourceRequirements{}
	if len(cr.Spec.Components.Node.Resources.Limits) > 0 || len(cr.Spec.Components.Node.Resources.Requests) > 0 {
		nodeResources.Requests = cr.Spec.Components.Node.Resources.Requests
		nodeResources.Limits = cr.Spec.Components.Node.Resources.Limits
	}

	var terminationGracePeriod int64 = 0
	trueBool := true

	return &apps.DaemonSet{
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
					Tolerations:                   tolerations,
					ServiceAccountName:            "calico-node",
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					HostNetwork:                   true,
					InitContainers: []v1.Container{
						{
							Name:         "install-cni",
							Image:        cniImage,
							Command:      []string{"/install-cni.sh"},
							Env:          cniEnv,
							VolumeMounts: cniVolumeMounts,
						},
					},
					Containers: []v1.Container{
						{
							Name:            "calico-node",
							Image:           nodeImage,
							Resources:       nodeResources,
							SecurityContext: &v1.SecurityContext{Privileged: &trueBool},
							Env:             nodeEnv,
							VolumeMounts:    nodeVolumeMounts,
							LivenessProbe: &v1.Probe{
								Handler: v1.Handler{
									HTTPGet: &v1.HTTPGetAction{
										Host: "localhost",
										Path: "/liveness",
										Port: livenessPort,
									},
								},
							},
							ReadinessProbe: &v1.Probe{
								Handler: v1.Handler{Exec: &v1.ExecAction{Command: readinessCmd}},
							},
						},
					},
					Volumes: allVolumes,
				},
			},
			UpdateStrategy: apps.DaemonSetUpdateStrategy{
				RollingUpdate: &apps.RollingUpdateDaemonSet{
					MaxUnavailable: cr.Spec.Components.Node.MaxUnavailable,
				},
			},
		},
	}
}
