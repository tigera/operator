// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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
	"path/filepath"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	CalicoVPPSA            = "calico-vpp-node-sa"
	CalicoVPPNamespace     = "calico-vpp-dataplane"
	CalicoVPPDaemonSetName = "calico-vpp-node"
	CalicoVPPRole          = "calico-vpp-node-role"
	CalicoVPPConfigMap     = "calico-vpp-config"
	VPPContainerName       = "vpp"
	AgentContainerName     = "agent"
)

type VPPConfiguration struct {
	Installation *operatorv1.InstallationSpec
}

type vppComponent struct {
	cfg *VPPConfiguration

	vppImage   string
	agentImage string
}

func (c *vppComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := "docker.io/"
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error

	c.agentImage, err = components.GetReference(components.ComponentCalicoVPPAgent, reg, path, prefix, is)
	if err != nil {
		return err
	}
	c.vppImage, err = components.GetReference(components.ComponentCalicoVPPVPP, reg, path, prefix, is)
	return err
}

func (c *vppComponent) Objects() (objsToCreate, objsToDelete []client.Object) {
	objs := []client.Object{c.serviceAccount(), c.clusterRole(), c.clusterRoleBinding(), c.configMap(), c.daemonset()}
	return objs, nil
}

func (c *vppComponent) Ready() bool {
	return true
}

func (c *vppComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func VPP(vpp *VPPConfiguration) Component {
	return &vppComponent{
		cfg: vpp,
	}
}

func (c *vppComponent) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CalicoVPPSA,
			Namespace: CalicoVPPNamespace,
		},
	}
}

func (c *vppComponent) clusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CalicoVPPDaemonSetName,
			Namespace: CalicoVPPNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     CalicoVPPRole,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      CalicoVPPSA,
				Namespace: CalicoVPPNamespace,
			},
		},
	}
}

func (c *vppComponent) clusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CalicoVPPRole,
			Namespace: CalicoVPPNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "nodes", "namespaces"},
				Verbs:     []string{"get"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"endpoints", "services"},
				Verbs:     []string{"get", "watch", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get"},
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
				Resources: []string{"pods", "serviceaccounts", "namespaces"},
				Verbs:     []string{"list", "watch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "nodes", "namespaces"},
				Verbs:     []string{"get"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods/status"},
				Verbs:     []string{"patch"},
			},
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"globalfelixconfigs", "felixconfigurations", "bgppeers", "globalbgpconfigs", "bgpconfigurations", "ippools", "ipamblocks", "globalnetworkpolicies", "globalnetworksets", "networkpolicies", "networksets", "clusterinformations", "hostendpoints", "blockaffinities"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"blockaffinities", "ipamblocks", "ipamhandles"},
				Verbs:     []string{"get", "list", "create", "update", "delete"},
			},
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"ipamconfigs"},
				Verbs:     []string{"get"},
			},
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"blockaffinities"},
				Verbs:     []string{"watch"},
			},
		},
	}
}

// nodeCNIConfigMap returns a config map containing the CNI network config to be installed on each node.
// Returns nil if no configmap is needed.
func (c *vppComponent) configMap() *corev1.ConfigMap {

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CalicoVPPConfigMap,
			Namespace: CalicoVPPNamespace,
			Labels:    map[string]string{},
		},
		Data: map[string]string{
			"CALICOVPP_CONFIG_TEMPLATE": c.cfg.Installation.CalicoNetwork.VppDataplaneOptions.VppConfig,
			"CALICOVPP_INITIAL_CONFIG":  c.cfg.Installation.CalicoNetwork.VppDataplaneOptions.InitialConfig,
			"CALICOVPP_INTERFACES":      c.cfg.Installation.CalicoNetwork.VppDataplaneOptions.Interfaces,
			"SERVICE_PREFIX":            c.cfg.Installation.CalicoNetwork.VppDataplaneOptions.ServicePrefix,
			"CALICOVPP_FEATURE_GATES":   c.cfg.Installation.CalicoNetwork.VppDataplaneOptions.FeatureGates,
		},
	}
}

func (c *vppComponent) volumes() []corev1.Volume {
	hostPathTypeDirOrCreate := corev1.HostPathDirectoryOrCreate
	return []corev1.Volume{
		{
			Name: "share-certs",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/usr/share/ca-certificates",
				},
			},
		},
		{
			Name: "ssl-certs",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/etc/ssl/certs/",
				},
			},
		},
		{
			Name: "repo-directory",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/home/hbouatto/vpp-dataplane",
				},
			},
		},
		{
			Name: "lib-firmware",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/lib/firmware",
				},
			},
		},
		{
			Name: "vpp-rundir",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/run/vpp",
				},
			},
		},
		{
			Name: "vpp-data",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/lib/vpp",
					Type: &hostPathTypeDirOrCreate,
				},
			},
		},
		{
			Name: "vpp-config",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/etc/vpp",
				},
			},
		},
		{
			Name: "devices",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/dev",
				},
			},
		},
		{
			Name: "hostsys",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/sys",
				},
			},
		},
		{
			Name: "var-run-calico",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/run/calico",
				},
			},
		},
		{
			Name: "netns",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/run/netns",
				},
			},
		},
		{
			Name: "felix-plugins",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/lib/calico/felix-plugins",
				},
			},
		},
		{
			Name: "host-root",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/proc/1/root",
				},
			},
		},
	}
}

func (c *vppComponent) tolerations() []corev1.Toleration {
	return rmeta.TolerateAll
}

func (c *vppComponent) containers() []corev1.Container {
	mountPropagation := corev1.MountPropagationBidirectional
	vppContainer := corev1.Container{
		Name:            VPPContainerName,
		Image:           c.vppImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		EnvFrom: []corev1.EnvFromSource{
			{
				ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "calico-vpp-config"}},
			},
		},
		Env: []corev1.EnvVar{
			{
				Name:  "LD_LIBRARY_PATH",
				Value: "/repo/vpp-manager/vpp_build/build-root/install-vpp-native/vpp/",
			},
			{
				Name:  "DATASTORE_TYPE",
				Value: "kubernetes",
			},
			{
				Name:  "WAIT_FOR_DATASTORE",
				Value: "true",
			},
			{
				Name: "NODENAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "spec.nodeName",
					},
				},
			},
		},
		SecurityContext: securitycontext.NewRootContext(true),
		Resources: corev1.ResourceRequirements{
			Limits:   corev1.ResourceList{"hugepages-2Mi": resource.Quantity{Format: "4Gi"}, "memory": resource.Quantity{Format: "80Gi"}},
			Requests: corev1.ResourceList{"cpu": resource.Quantity{Format: "1"}, "memory": resource.Quantity{Format: "4Gi"}},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "repo-directory",
				MountPath: filepath.Clean("/repo"),
			},
			{
				Name:      "ssl-certs",
				MountPath: filepath.Clean("/etc/ssl/certs/"),
			},
			{
				Name:      "share-certs",
				MountPath: filepath.Clean("/usr/share/ca-certificates"),
			},
			{
				Name:      "lib-firmware",
				MountPath: filepath.Clean("/lib/firmware"),
			},
			{
				Name:      "vpp-rundir",
				MountPath: filepath.Clean("/var/run/vpp"),
			},
			{
				Name:      "vpp-data",
				MountPath: filepath.Clean("/var/lib/vpp"),
			},
			{
				Name:      "vpp-config",
				MountPath: filepath.Clean("/etc/vpp"),
			},
			{
				Name:      "devices",
				MountPath: filepath.Clean("/dev"),
			},
			{
				Name:      "hostsys",
				MountPath: filepath.Clean("/sys"),
			},
			{
				Name:             "netns",
				MountPath:        filepath.Clean("/run/netns"),
				MountPropagation: &mountPropagation,
			},
			{
				Name:      "host-root",
				MountPath: filepath.Clean("/host"),
			},
		},
	}

	agentContainer := corev1.Container{
		Name:            AgentContainerName,
		Image:           c.agentImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		EnvFrom: []corev1.EnvFromSource{
			{
				ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "calico-vpp-config"}},
			},
		},
		Env: []corev1.EnvVar{
			{
				Name:  "DATASTORE_TYPE",
				Value: "kubernetes",
			},
			{
				Name:  "WAIT_FOR_DATASTORE",
				Value: "true",
			},
			{
				Name: "NODENAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "spec.nodeName",
					},
				},
			},
			{
				Name: "NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "metadata.namespace",
					},
				},
			},
		},
		SecurityContext: securitycontext.NewRootContext(true),
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{"cpu": resource.Quantity{Format: "250m"}},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "var-run-calico",
				MountPath: filepath.Clean("/var/run/calico"),
				ReadOnly:  false,
			},
			{
				Name:      "felix-plugins",
				MountPath: filepath.Clean("/var/lib/calico/felix-plugins"),
				ReadOnly:  false,
			},
			{
				Name:      "vpp-rundir",
				MountPath: filepath.Clean("/var/run/vpp"),
			},
			{
				Name:             "netns",
				MountPath:        filepath.Clean("/run/netns"),
				MountPropagation: &mountPropagation,
			},
		},
	}

	return []corev1.Container{
		vppContainer,
		agentContainer,
	}
}

func (c *vppComponent) template() corev1.PodTemplateSpec {
	templateLabels := map[string]string{
		"name": CSIDaemonSetName,
	}
	templateMeta := metav1.ObjectMeta{
		Labels: templateLabels,
	}
	var terminationGracePeriodSeconds int64
	terminationGracePeriodSeconds = 10
	templateSpec := corev1.PodSpec{
		TerminationGracePeriodSeconds: &terminationGracePeriodSeconds,
		Tolerations:                   c.tolerations(),
		Containers:                    c.containers(),
		Volumes:                       c.volumes(),
		ServiceAccountName:            CalicoVPPSA,
		PriorityClassName:             NodePriorityClassName,
		HostNetwork:                   true,
		HostPID:                       true,
		NodeSelector:                  map[string]string{"kubernetes.io/os": "linux"},
	}

	return corev1.PodTemplateSpec{
		ObjectMeta: templateMeta,
		Spec:       templateSpec,
	}
}

// csiDaemonset creates the daemonset necessary to enable the CSI driver
func (c *vppComponent) daemonset() *appsv1.DaemonSet {
	dsMeta := metav1.ObjectMeta{
		Name:      CalicoVPPDaemonSetName,
		Namespace: CalicoVPPNamespace,
	}

	typeMeta := metav1.TypeMeta{
		Kind:       "DaemonSet",
		APIVersion: "apps/v1",
	}

	dsSpec := appsv1.DaemonSetSpec{
		Template: c.template(),
	}

	ds := appsv1.DaemonSet{
		TypeMeta:   typeMeta,
		ObjectMeta: dsMeta,
		Spec:       dsSpec,
	}

	return &ds
}
