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

package core

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"

	operatorv1alpha1 "github.com/tigera/operator/pkg/apis/operator/v1alpha1"
)

var _ = Describe("Defaulting logic tests", func() {
	maxUnavailable := intstr.FromInt(2)
	It("should properly fill defaults on an empty instance", func() {
		instance := &operatorv1alpha1.Core{}
		fillDefaults(instance)
		Expect(instance.Spec.Version).To(Equal("latest"))
		Expect(instance.Spec.Variant).To(Equal(operatorv1alpha1.Calico))
		Expect(instance.Spec.Registry).To(Equal("docker.io/"))
		Expect(instance.Spec.CNINetDir).To(Equal("/etc/cni/net.d"))
		Expect(instance.Spec.CNIBinDir).To(Equal("/opt/cni/bin"))
		Expect(instance.Spec.IPPools).To(HaveLen(1))
		Expect(instance.Spec.IPPools[0].CIDR).To(Equal("192.168.0.0/16"))
		Expect(instance.Spec.Components.KubeProxy.Required).To(BeFalse())
		Expect(instance.Spec.Components.KubeProxy.APIServer).To(Equal(""))

		Expect(instance.Spec.Components.Node.MaxUnavailable).To(Not(BeNil()))
		Expect(instance.Spec.Components.Node.MaxUnavailable.IntVal).To(Equal(int32(1)))
	})

	It("should not override custom configuration", func() {
		instance := &operatorv1alpha1.Core{
			Spec: operatorv1alpha1.CoreSpec{
				Version:                "test",
				MinimumOperatorVersion: "0.9.1",
				Variant:                operatorv1alpha1.TigeraSecureEnterprise,
				Registry:               "test-reg/",
				ImagePullSecretsRef: []v1.LocalObjectReference{
					{
						Name: "pullSecret1",
					},
					{
						Name: "pullSecret2",
					},
				},
				CNIBinDir: "/test/bin",
				CNINetDir: "/test/net",
				IPPools: []operatorv1alpha1.IPPool{
					{CIDR: "1.2.3.0/24"},
				},
				Datastore: operatorv1alpha1.DatastoreConfig{
					Type: operatorv1alpha1.Kubernetes,
				},
				Components: operatorv1alpha1.ComponentsSpec{
					Node: operatorv1alpha1.NodeSpec{
						ImageOverride:  "nodeRegistry/nodeImage:1.2.3",
						MaxUnavailable: &maxUnavailable,
						ExtraEnv: []v1.EnvVar{
							{
								Name:  "project",
								Value: "calico",
							},
						},
						ExtraVolumes: []v1.Volume{
							{
								Name: "volume1",
								VolumeSource: v1.VolumeSource{
									NFS: &v1.NFSVolumeSource{
										Server: "localhost",
										Path:   "/",
									},
								},
							},
						},
						Resources: v1.ResourceRequirements{
							Requests: v1.ResourceList{
								v1.ResourceCPU:    resource.MustParse("100m"),
								v1.ResourceMemory: resource.MustParse("250Mi"),
							},
							Limits: v1.ResourceList{
								v1.ResourceCPU:    resource.MustParse("100m"),
								v1.ResourceMemory: resource.MustParse("250Mi"),
							},
						},
						Tolerations: []v1.Toleration{
							{Operator: v1.TolerationOpEqual, Value: "nodeValue", Effect: v1.TaintEffectNoSchedule, Key: "node"},
						},
					},
					KubeControllers: operatorv1alpha1.KubeControllersSpec{
						ImageOverride: "kubecontrollersRegistry/kubecontrollersImage:1.2.3",
						ExtraEnv: []v1.EnvVar{
							{
								Name:  "project",
								Value: "calico",
							},
						},
						ExtraVolumes: []v1.Volume{
							{
								Name: "volume1",
								VolumeSource: v1.VolumeSource{
									NFS: &v1.NFSVolumeSource{
										Server: "localhost",
										Path:   "/",
									},
								},
							},
						},
						Resources: v1.ResourceRequirements{
							Requests: v1.ResourceList{
								v1.ResourceCPU:    resource.MustParse("150m"),
								v1.ResourceMemory: resource.MustParse("350Mi"),
							},
							Limits: v1.ResourceList{
								v1.ResourceCPU:    resource.MustParse("150m"),
								v1.ResourceMemory: resource.MustParse("350Mi"),
							},
						},
						Tolerations: []v1.Toleration{
							{Operator: v1.TolerationOpEqual, Value: "kubecontrollersValue", Effect: v1.TaintEffectNoSchedule, Key: "kubecontrollers"},
						},
					},
					CNI: operatorv1alpha1.CNISpec{
						ImageOverride: "kubecontrollersRegistry/kubecontrollersImage:1.2.3",
						ExtraEnv: []v1.EnvVar{
							{
								Name:  "project",
								Value: "calico",
							},
						},
						ExtraVolumes: []v1.Volume{
							{
								Name: "volume1",
								VolumeSource: v1.VolumeSource{
									NFS: &v1.NFSVolumeSource{
										Server: "localhost",
										Path:   "/",
									},
								},
							},
						},
					},
					KubeProxy: operatorv1alpha1.KubeProxySpec{
						Required:  true,
						APIServer: "http://server",
						Image:     "test-image",
					},
				},
			},
		}
		instanceCopy := instance.DeepCopyObject().(*operatorv1alpha1.Core)
		fillDefaults(instanceCopy)
		Expect(instanceCopy.Spec).To(Equal(instance.Spec))
	})

	It("should correct missing slashes on registry", func() {
		instance := &operatorv1alpha1.Core{
			Spec: operatorv1alpha1.CoreSpec{
				Registry: "test-reg",
			},
		}
		fillDefaults(instance)
		Expect(instance.Spec.Registry).To(Equal("test-reg/"))
	})
})
