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

package render_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
	apps "k8s.io/api/apps/v1"
)

var _ = Describe("kube-controllers rendering tests", func() {
	var instance *operator.Installation

	tolerations := []v1.Toleration{
		// This overrides node-role.kubernetes.io/master with a different effect.
		{Key: "node-role.kubernetes.io/master", Effect: v1.TaintEffectPreferNoSchedule},
		// A custom toleration
		{
			Key:      "somekey",
			Operator: v1.TolerationOpEqual,
			Value:    "somevalue",
			Effect:   v1.TaintEffectNoSchedule,
		},
	}
	volume := v1.Volume{
		Name: "extravolKubeControllers",
		VolumeSource: v1.VolumeSource{
			EmptyDir: &v1.EmptyDirVolumeSource{},
		},
	}
	volumeMount := v1.VolumeMount{
		Name:      "extravolKubeControllers",
		MountPath: "/test/calico/kubecontrollers",
	}
	// Override an existing env and add a new one.
	envVars := []v1.EnvVar{
		{Name: "ENABLED_CONTROLLERS", Value: "node,namespace"},
		{Name: "kubecontrollers-env", Value: "kubecontrollers-value"},
	}
	res := v1.ResourceRequirements{
		Requests: v1.ResourceList{
			v1.ResourceCPU:    resource.MustParse("1000m"),
			v1.ResourceMemory: resource.MustParse("250Mi"),
		},
		Limits: v1.ResourceList{
			v1.ResourceCPU:    resource.MustParse("1500m"),
			v1.ResourceMemory: resource.MustParse("500Mi"),
		},
	}

	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		instance = &operator.Installation{
			Spec: operator.InstallationSpec{
				IPPools: []operator.IPPool{
					{CIDR: "192.168.1.0/16"},
				},
				Version:   "test",
				Registry:  "test-reg/",
				CNINetDir: "/test/cni/net/dir",
				CNIBinDir: "/test/cni/bin/dir",
				Datastore: operator.DatastoreConfig{
					Type: "kubernetes",
				},
				Components: operator.ComponentsSpec{
					KubeControllers: operator.KubeControllersSpec{
						Image:             "customRegistry/customImage:customVersion",
						ExtraEnv:          envVars,
						ExtraVolumes:      []v1.Volume{volume},
						ExtraVolumeMounts: []v1.VolumeMount{volumeMount},
						Tolerations:       tolerations,
						Resources:         res,
					},
				},
			},
		}

	})

	It("should render all resources for a custom configuration", func() {
		component := render.KubeControllers(instance)
		resources := component.Objects()
		Expect(len(resources)).To(Equal(4))

		// Should render the correct resources.
		ExpectResource(resources[0], "calico-kube-controllers", "calico-system", "", "v1", "ServiceAccount")
		ExpectResource(resources[1], "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		ExpectResource(resources[2], "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
		ExpectResource(resources[3], "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment")

		// The Deployment should have the correct configuration.
		ds := resources[3].(*apps.Deployment)

		// Image override results in correct image.
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal("customRegistry/customImage:customVersion"))

		// Verify env
		expectedEnv := []v1.EnvVar{{Name: "DATASTORE_TYPE", Value: "kubernetes"}}
		expectedEnv = append(expectedEnv, envVars...)
		Expect(ds.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedEnv))

		// Verify volumes and volumeMounts.
		Expect(ds.Spec.Template.Spec.Volumes).To(ConsistOf(volume))
		Expect(ds.Spec.Template.Spec.Containers[0].VolumeMounts).To(ConsistOf(volumeMount))

		// Verify resources.
		Expect(ds.Spec.Template.Spec.Containers[0].Resources).To(Equal(res))

		// Verify tolerations.
		expectedTolerations := []v1.Toleration{
			{Key: "CriticalAddonsOnly", Operator: v1.TolerationOpExists},
			{Key: "node-role.kubernetes.io/master", Effect: v1.TaintEffectNoSchedule},
		}
		expectedTolerations = append(expectedTolerations, tolerations...)
		Expect(ds.Spec.Template.Spec.Tolerations).To(ConsistOf(expectedTolerations))
	})

	It("should render all resources for a default configuration using TigeraSecureEnterprise", func() {
		instance.Spec.Variant = operator.TigeraSecureEnterprise
		instance.Spec.Components.KubeControllers = operator.KubeControllersSpec{}

		component := render.KubeControllers(instance)
		resources := component.Objects()
		Expect(len(resources)).To(Equal(4))

		// Should render the correct resources.
		ExpectResource(resources[0], "calico-kube-controllers", "calico-system", "", "v1", "ServiceAccount")
		ExpectResource(resources[1], "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		ExpectResource(resources[2], "calico-kube-controllers", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
		ExpectResource(resources[3], "calico-kube-controllers", "calico-system", "apps", "v1", "Deployment")

		// The Deployment should have the correct configuration.
		ds := resources[3].(*apps.Deployment)

		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(BeEmpty())
	})
})
