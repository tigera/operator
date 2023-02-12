// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.

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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

func Windows(
	cfg *WindowsConfig,
) Component {
	return &windowsComponent{cfg: cfg}
}

type WindowsConfig struct {
	Installation *operatorv1.InstallationSpec
	Terminating  bool
}

type windowsComponent struct {
	cfg                 *WindowsConfig
	windowsUpgradeImage string
}

func (c *windowsComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix

	component := components.ComponentWindowsUpgrade
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		component = components.ComponentTigeraWindowsUpgrade
	}

	image, err := components.GetReference(component, reg, path, prefix, is)
	if err != nil {
		return err
	}

	c.windowsUpgradeImage = image

	return nil
}

func (c *windowsComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeWindows
}

func (c *windowsComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{
		c.windowsInstallDaemonset(),
	}
	upgradeObjs := []client.Object{
		c.windowsServiceAccount(),
		c.windowsUpgradeDaemonset(),
	}

	if c.cfg.Installation.KubernetesProvider != operatorv1.ProviderAKS {
		return objs, upgradeObjs
	}

	if c.cfg.Terminating {
		return nil, append(objs, upgradeObjs...)
	}
	return append(objs, upgradeObjs...), nil
}

func (c *windowsComponent) Ready() bool {
	return true
}

func (c *windowsComponent) windowsServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.CalicoWindowsUpgradeResourceName,
			Namespace: common.CalicoNamespace,
		},
	}
}

func (c *windowsComponent) windowsUpgradeDaemonset() *appsv1.DaemonSet {
	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.CalicoWindowsUpgradeResourceName,
			Namespace: "calico-system",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: common.CalicoWindowsUpgradeResourceName,
			Affinity: &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{{
							// The Calico for Windows upgrade daemonset only
							// runs:
							// - on nodes with the upgrade script label
							// - on Windows nodes
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      common.CalicoWindowsUpgradeLabel,
									Operator: corev1.NodeSelectorOpExists,
								},
								{
									Key:      corev1.LabelOSStable,
									Operator: corev1.NodeSelectorOpIn,
									Values:   []string{"windows"},
								},
							},
						}},
					},
				},
			},
			Tolerations: []corev1.Toleration{
				{
					Key:    common.CalicoWindowsUpgradeTaintKey,
					Effect: corev1.TaintEffectNoSchedule,
				},
			},
			ImagePullSecrets: c.cfg.Installation.ImagePullSecrets,
			Containers:       []corev1.Container{c.windowsUpgradeContainer()},
			Volumes:          c.calicoWindowsVolume(),
		},
	}

	ds := &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.CalicoWindowsUpgradeResourceName,
			Namespace: "calico-system",
		},
		Spec: appsv1.DaemonSetSpec{
			Template: *podTemplate,
		},
	}

	if overrides := c.cfg.Installation.CalicoWindowsUpgradeDaemonSet; overrides != nil {
		rcomp.ApplyDaemonSetOverrides(ds, overrides)
	}

	return ds
}

func (c *windowsComponent) windowsUpgradeContainer() corev1.Container {
	mounts := []corev1.VolumeMount{
		{
			Name:      common.CalicoWindowsUpgradeResourceName,
			MountPath: common.CalicoWindowsUpgradeVolumePath,
		},
	}

	return corev1.Container{
		Name:         common.CalicoWindowsUpgradeResourceName,
		Image:        c.windowsUpgradeImage,
		VolumeMounts: mounts,
	}
}

func (c *windowsComponent) calicoWindowsVolume() []corev1.Volume {
	dirOrCreate := corev1.HostPathDirectoryOrCreate
	volumes := []corev1.Volume{
		{
			Name: common.CalicoWindowsUpgradeResourceName,
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: common.CalicoWindowsUpgradeVolumePath,
					Type: &dirOrCreate,
				},
			},
		},
	}

	return volumes
}

func (c *windowsComponent) mapConfigToEnvVars() []corev1.EnvVar {
	nodeSource := &corev1.EnvVarSource{
		FieldRef: &corev1.ObjectFieldSelector{
			APIVersion: "v1",
			FieldPath:  "spec.NodeName",
		},
	}
	return []corev1.EnvVar{
		{
			Value: c.cfg.Installation.CalicoNodeDaemonSet.WindowsConfiguration.CalicoNetworkingBackend,
			Name:  "CALICO_NETWORKING_BACKEND",
		},
		{Name: "NODENAME", ValueFrom: nodeSource},
		{
			Name:  "KUBERNETES_SERVICE_HOST",
			Value: *c.cfg.Installation.CalicoNodeDaemonSet.WindowsConfiguration.KubernetesServiceHost,
		},
		{
			Name:  "KUBERNETES_SERVICE_PORT",
			Value: *c.cfg.Installation.CalicoNodeDaemonSet.WindowsConfiguration.KubernetesServicePort,
		},
		{
			Name:  "K8S_SERVICE_CIDR",
			Value: c.cfg.Installation.CalicoNodeDaemonSet.WindowsConfiguration.KubernetesServiceCIDR,
		},
		{
			Name:  "DNS_NAME_SERVERS",
			Value: c.cfg.Installation.CalicoNodeDaemonSet.WindowsConfiguration.DNSNameServers,
		},
		{
			Name:  "CNI_BIN_DIR",
			Value: c.cfg.Installation.CalicoNodeDaemonSet.WindowsConfiguration.CNIBinDir,
		},
		{
			Name:  "CNI_CONF_DIR",
			Value: c.cfg.Installation.CalicoNodeDaemonSet.WindowsConfiguration.CNIConfDir,
		},
		{
			Name:  "FELIX_HEALTHENABLED",
			Value: "true",
		},
	}
}

func (c *windowsComponent) windowsInitContainers() []corev1.Container {
	return []corev1.Container{
		{
			Name:            "install",
			Image:           "calico/windows:v3.25.0",
			Args:            []string{".\\host-process-install.ps1"},
			ImagePullPolicy: corev1.PullAlways,
			Env:             c.mapConfigToEnvVars(),
		},
	}
}

func (c *windowsComponent) windowsCalicoContainers() []corev1.Container {
	return []corev1.Container{
		{
			Name:            "node",
			Image:           "calico/windows:v3.25.0",
			Args:            []string{".\\node\\node-service.ps1"},
			WorkingDir:      "..\\..\\CalicoWindows",
			ImagePullPolicy: corev1.PullAlways,
			Env:             c.mapConfigToEnvVars(),
		},
		{
			Name:            "node",
			Image:           "calico/windows:v3.25.0",
			Args:            []string{".\\felix\\felix-service.ps1"},
			WorkingDir:      "..\\..\\CalicoWindows",
			ImagePullPolicy: corev1.PullAlways,
			Env:             c.mapConfigToEnvVars(),
			LivenessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					Exec: &corev1.ExecAction{
						Command: []string{"c:\\CalicoWindows\\calico-node.exe", "-felix-live"},
					},
				},
				PeriodSeconds:       10,
				InitialDelaySeconds: 10,
				FailureThreshold:    6,
				TimeoutSeconds:      10,
			},
			ReadinessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					Exec: &corev1.ExecAction{
						Command: []string{"c:\\\\CalicoWindows\\\\calico-node.exe", "-felix-ready"},
					},
				},
				TimeoutSeconds: 10,
				PeriodSeconds:  10,
			},
		},
	}
}

func (c *windowsComponent) windowsInstallDaemonset() *appsv1.DaemonSet {
	hostProcess := true
	runAs := "NT AUTHORITY\\system"

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.CalicoWindowsResourceName,
			Namespace: "calico-system",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "calico-node",
			SecurityContext: &corev1.PodSecurityContext{
				WindowsOptions: &corev1.WindowsSecurityContextOptions{
					HostProcess:   &hostProcess,
					RunAsUserName: &runAs,
				},
			},
			HostNetwork: true,
			Affinity: &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{{
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      corev1.LabelOSStable,
									Operator: corev1.NodeSelectorOpIn,
									Values:   []string{"windows"},
								},
							},
						}},
					},
				},
			},
			Tolerations:      []corev1.Toleration{ /* todo(knabben) fix correct tolerations */ },
			ImagePullSecrets: c.cfg.Installation.ImagePullSecrets,
			InitContainers:   c.windowsInitContainers(),
			Containers:       c.windowsCalicoContainers(),
		},
	}

	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.CalicoWindowsResourceName,
			Namespace: "calico-system",
		},
		Spec: appsv1.DaemonSetSpec{
			Template: *podTemplate,
		},
	}
}
