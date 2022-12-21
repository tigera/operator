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
		c.windowsServiceAccount(),
		c.windowsUpgradeDaemonset(),
	}

	if c.cfg.Installation.KubernetesProvider != operatorv1.ProviderAKS {
		return nil, objs
	}

	if c.cfg.Terminating {
		return nil, objs
	}
	return objs, nil
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
