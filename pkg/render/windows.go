// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

func Windows(
	installation *operatorv1.Installation,
	pullSecrets []*corev1.Secret,
	hasMonitoredNodes bool,
) (Component, error) {
	return &windowsComponent{
		installation:      installation,
		pullSecrets:       pullSecrets,
		hasMonitoredNodes: hasMonitoredNodes,
	}, nil
}

type windowsComponent struct {
	installation        *operatorv1.Installation
	pullSecrets         []*corev1.Secret
	hasMonitoredNodes   bool
	windowsUpgradeImage string
}

func (c *windowsComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.installation.Spec.Registry
	path := c.installation.Spec.ImagePath
	prefix := c.installation.Spec.ImagePrefix

	image, err := components.GetReference(components.ComponentWindows, reg, path, prefix, is)
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
		c.windowsUpgradeDaemonset(),
	}

	if !c.hasMonitoredNodes {
		return nil, objs
	}

	return objs, nil
}

func (c *windowsComponent) Ready() bool {
	return true
}

func (c *windowsComponent) windowsUpgradeDaemonset() *appsv1.DaemonSet {
	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.CalicoWindowsUpgradeResourceName,
			Namespace: "calico-system",
			Labels: map[string]string{
				"k8s-app": common.CalicoWindowsUpgradeResourceName,
			},
		},
		Spec: corev1.PodSpec{
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
									Key:      common.CalicoWindowsUpgradeScriptLabel,
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
			Tolerations:      rmeta.TolerateAll,
			ImagePullSecrets: c.installation.Spec.ImagePullSecrets,
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
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": common.CalicoWindowsUpgradeResourceName}},
			Template: *podTemplate,
		},
	}

	return ds
}
func (c *windowsComponent) windowsUpgradeContainer() corev1.Container {
	mounts := []corev1.VolumeMount{
		{
			Name:      "calico-windows-upgrade",
			MountPath: `c:\CalicoUpdateExec`,
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
			Name: "calico-windows-upgrade",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: `c:\CalicoUpdateExec`,
					Type: &dirOrCreate,
				},
			},
		},
	}

	return volumes
}
