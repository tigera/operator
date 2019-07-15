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

package installation

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
)

var _ = Describe("Defaulting logic tests", func() {
	maxUnavailable := intstr.FromInt(2)
	It("should properly fill defaults on an empty instance", func() {
		instance := &operator.Installation{}
		fillDefaults(instance)
		Expect(instance.Spec.Version).To(Equal("latest"))
		Expect(instance.Spec.Variant).To(Equal(operator.Calico))
		Expect(instance.Spec.Registry).To(Equal("docker.io/"))
		Expect(instance.Spec.CNINetDir).To(Equal("/etc/cni/net.d"))
		Expect(instance.Spec.CNIBinDir).To(Equal("/opt/cni/bin"))
		Expect(instance.Spec.IPPools).To(HaveLen(1))
		Expect(instance.Spec.IPPools[0].CIDR).To(Equal("192.168.0.0/16"))
		Expect(instance.Spec.Components.KubeProxy.Required).To(BeFalse())
		Expect(instance.Spec.Components.KubeProxy.APIServer).To(Equal(""))

		// Image override results in correct images.
		Expect(instance.Spec.Components.Node.Image).To(Equal("docker.io/calico/node:latest"))
		Expect(instance.Spec.Components.CNI.Image).To(Equal("docker.io/calico/cni:latest"))
		Expect(instance.Spec.Components.KubeControllers.Image).To(Equal("docker.io/calico/kube-controllers:latest"))
		Expect(instance.Spec.Components.KubeProxy.Image).To(BeEmpty())
		Expect(instance.Spec.Components.APIServer.Image).To(BeEmpty())
		Expect(instance.Spec.Components.Console.Manager.Image).To(BeEmpty())
		Expect(instance.Spec.Components.Console.Proxy.Image).To(BeEmpty())
		Expect(instance.Spec.Components.Console.EsProxy.Image).To(BeEmpty())

		Expect(instance.Spec.Components.Node.MaxUnavailable).To(Not(BeNil()))
		Expect(instance.Spec.Components.Node.MaxUnavailable.IntVal).To(Equal(int32(1)))
	})

	It("should properly fill defaults on an empty TigeraSecureEnterprise instance", func() {
		instance := &operator.Installation{}
		instance.Spec.Variant = operator.TigeraSecureEnterprise
		fillDefaults(instance)
		Expect(instance.Spec.Version).To(Equal("latest"))
		Expect(instance.Spec.Variant).To(Equal(operator.TigeraSecureEnterprise))
		Expect(instance.Spec.Registry).To(Equal("quay.io/"))
		Expect(instance.Spec.CNINetDir).To(Equal("/etc/cni/net.d"))
		Expect(instance.Spec.CNIBinDir).To(Equal("/opt/cni/bin"))
		Expect(instance.Spec.IPPools).To(HaveLen(1))
		Expect(instance.Spec.IPPools[0].CIDR).To(Equal("192.168.0.0/16"))
		Expect(instance.Spec.Components.KubeProxy.Required).To(BeFalse())
		Expect(instance.Spec.Components.KubeProxy.APIServer).To(Equal(""))

		// Image override results in correct images.
		Expect(instance.Spec.Components.Node.Image).To(Equal("quay.io/tigera/cnx-node:latest"))
		Expect(instance.Spec.Components.CNI.Image).To(Equal("quay.io/calico/cni:latest"))
		Expect(instance.Spec.Components.KubeControllers.Image).To(Equal("quay.io/tigera/kube-controllers:latest"))
		Expect(instance.Spec.Components.KubeProxy.Image).To(BeEmpty())
		Expect(instance.Spec.Components.APIServer.Image).To(Equal("quay.io/tigera/cnx-apiserver:latest"))
		Expect(instance.Spec.Components.IntrusionDetection.Controller.Image).To(Equal("quay.io/tigera/intrusion-detection-controller:latest"))
		Expect(instance.Spec.Components.IntrusionDetection.Installer.Image).To(Equal("quay.io/tigera/intrusion-detection-job-installer:latest"))
		Expect(instance.Spec.Components.Console.Manager.Image).To(Equal("quay.io/tigera/cnx-manager:latest"))
		Expect(string(instance.Spec.Components.Console.AuthenticationType)).To(Equal("Basic"))
		Expect(instance.Spec.Components.Console.Proxy.Image).To(Equal("quay.io/tigera/cnx-manager-proxy:latest"))
		Expect(instance.Spec.Components.Console.EsProxy.Image).To(Equal("quay.io/tigera/es-proxy:latest"))

		Expect(instance.Spec.Components.Node.MaxUnavailable).To(Not(BeNil()))
		Expect(instance.Spec.Components.Node.MaxUnavailable.IntVal).To(Equal(int32(1)))
	})

	It("should not override custom configuration", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				Version:                "test",
				MinimumOperatorVersion: "0.9.1",
				Variant:                operator.TigeraSecureEnterprise,
				Registry:               "test-reg/",
				ImagePullSecrets: []v1.LocalObjectReference{
					{
						Name: "pullSecret1",
					},
					{
						Name: "pullSecret2",
					},
				},
				CNIBinDir: "/test/bin",
				CNINetDir: "/test/net",
				IPPools: []operator.IPPool{
					{CIDR: "1.2.3.0/24"},
				},
				Datastore: operator.DatastoreConfig{
					Type: operator.Kubernetes,
				},
				Components: operator.ComponentsSpec{
					Node: operator.NodeSpec{
						Image:          "nodeRegistry/nodeImage:1.2.3",
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
					KubeControllers: operator.KubeControllersSpec{
						Image: "kubecontrollersRegistry/kubecontrollersImage:1.2.3",
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
					CNI: operator.CNISpec{
						Image: "cniRegistry/cniImage:1.2.3",
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
					KubeProxy: operator.KubeProxySpec{
						Required:  true,
						APIServer: "http://server",
						Image:     "test-image",
					},
					APIServer: operator.APIServerSpec{
						Image: "apiserver/server:v0.0.1",
						ExtraEnv: []v1.EnvVar{
							{
								Name:  "asenv1",
								Value: "env1",
							},
						},
						ExtraVolumes: []v1.Volume{
							{
								Name: "asvol1",
								VolumeSource: v1.VolumeSource{
									NFS: &v1.NFSVolumeSource{
										Server: "localhost",
										Path:   "/as",
									},
								},
							},
						},
						ExtraVolumeMounts: []v1.VolumeMount{
							{Name: "asvolmount", MountPath: "/asvolmount"},
						},
						Tolerations: []v1.Toleration{
							{Operator: v1.TolerationOpEqual, Value: "asValue", Effect: v1.TaintEffectNoSchedule, Key: "asKey"},
						},
						Resources: v1.ResourceRequirements{
							Requests: v1.ResourceList{
								v1.ResourceCPU:    resource.MustParse("225m"),
								v1.ResourceMemory: resource.MustParse("335Mi"),
							},
							Limits: v1.ResourceList{
								v1.ResourceCPU:    resource.MustParse("325m"),
								v1.ResourceMemory: resource.MustParse("435Mi"),
							},
						},
					},
					Compliance: operator.ComplianceSpec{
						Controller: operator.ComplianceControllerSpec{
							Image: "complianceController-test-image",
						},
						Reporter: operator.ComplianceReporterSpec{
							Image: "complianceReporter-test-image",
						},
						Server: operator.ComplianceServerSpec{
							Image: "complianceServerer-test-mage",
						},
						Snapshotter: operator.ComplianceSnapshotterSpec{
							Image: "complianceSnapshotter-test-image",
						},
						Benchmarker: operator.ComplianceBenchmarkerSpec{
							Image: "complianceBenchmarker-test-Image",
						},
					},
					IntrusionDetection: operator.IntrusionDetectionSpec{
						Controller: operator.IntrusionDetectionControllerSpec{
							Image: "intrusionreg/ctrl:v1",
						},
						Installer: operator.IntrusionDetectionInstallerSpec{
							Image: "intrusionreg/job:v2",
						},
					},
					Console: operator.ConsoleSpec{
						Manager: operator.ConsoleManagerSpec{
							Image: "consoleRegistry/manager:beta",
						},
						Proxy: operator.ConsoleProxySpec{
							Image: "consoleRegistry/proxy:v1",
						},
						EsProxy: operator.ConsoleEsProxySpec{
							Image: "consoleRegistry/esproxy:v2",
						},
						AuthenticationType: operator.AuthTypeToken,
						OAuth2Authority:    "https://api.tigera.io",
						OAuth2ClientId:     "oauth2-client-id",
						OIDCAuthority:      "https://oidc-auth-server.com",
						OIDCClientId:       "oidc-client-id",
					},
				},
			},
		}
		instanceCopy := instance.DeepCopyObject().(*operator.Installation)
		fillDefaults(instanceCopy)
		Expect(instanceCopy.Spec).To(Equal(instance.Spec))
	})

	It("should correct missing slashes on registry", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				Registry: "test-reg",
			},
		}
		fillDefaults(instance)
		Expect(instance.Spec.Registry).To(Equal("test-reg/"))
	})
})
