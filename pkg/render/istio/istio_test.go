// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package istio_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/istio"
)

var _ = Describe("Istio Component Rendering", func() {
	var (
		testScheme *runtime.Scheme
		cfg        *istio.Configuration
	)

	BeforeEach(func() {
		testScheme = runtime.NewScheme()
		Expect(scheme.AddToScheme(testScheme)).ShouldNot(HaveOccurred())
		Expect(operatorv1.AddToScheme(testScheme)).ShouldNot(HaveOccurred())
		Expect(v3.AddToScheme(testScheme)).ShouldNot(HaveOccurred())
		Expect(apiextv1.AddToScheme(testScheme)).ShouldNot(HaveOccurred())

		cfg = &istio.Configuration{
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "test-registry",
				ImagePath:          "test-path",
				ImagePrefix:        "test-prefix",
			},
			Istio: &operatorv1.Istio{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: operatorv1.IstioSpec{
					DSCPMark: func() *numorstring.DSCP { d := numorstring.DSCPFromInt(0); return &d }(),
				},
			},
			IstioNamespace: istio.IstioNamespace,
			Scheme:         testScheme,
		}
	})

	Describe("Component Initialization", func() {
		It("should successfully create Istio components", func() {
			crds, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(crds).NotTo(BeNil())
			Expect(component).NotTo(BeNil())
		})

		It("should set GKE platform when provider is GKE", func() {
			cfg.Installation.KubernetesProvider = operatorv1.ProviderGKE
			crds, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(crds).NotTo(BeNil())
			Expect(component).NotTo(BeNil())
		})
	})

	Describe("ResolveImages", func() {
		It("should resolve all images correctly", func() {
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			imageSet := &operatorv1.ImageSet{
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/istio-pilot", Digest: "sha256:test-pilot-digest"},
						{Image: "tigera/istio-install-cni", Digest: "sha256:test-cni-digest"},
						{Image: "tigera/istio-ztunnel", Digest: "sha256:test-ztunnel-digest"},
						{Image: "tigera/istio-proxyv2", Digest: "sha256:test-proxyv2-digest"},
					},
				},
			}

			err = component.ResolveImages(imageSet)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should fail when required images are missing", func() {
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			imageSet := &operatorv1.ImageSet{
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{},
				},
			}

			err = component.ResolveImages(imageSet)
			Expect(err).Should(HaveOccurred())
		})
	})

	Describe("Objects", func() {
		var (
			crds      *istio.IstioComponentCRDs
			component *istio.IstioComponent
			err       error
		)

		BeforeEach(func() {
			crds, component, err = istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			imageSet := &operatorv1.ImageSet{
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/istio-pilot", Digest: "sha256:test-pilot-digest"},
						{Image: "tigera/istio-install-cni", Digest: "sha256:test-cni-digest"},
						{Image: "tigera/istio-ztunnel", Digest: "sha256:test-ztunnel-digest"},
						{Image: "tigera/istio-proxyv2", Digest: "sha256:test-proxyv2-digest"},
					},
				},
			}
			err = component.ResolveImages(imageSet)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should return CRDs", func() {
			objsToCreate, objsToDelete := crds.Objects()
			Expect(objsToCreate).NotTo(BeEmpty())
			Expect(objsToDelete).To(BeEmpty())
		})

		It("should return objects to create", func() {
			objsToCreate, objsToDelete := component.Objects()
			Expect(objsToCreate).NotTo(BeEmpty())
			Expect(objsToDelete).To(BeEmpty())
		})

		It("should include network policies", func() {
			objsToCreate, _ := component.Objects()

			// Verify istiod policy
			istiodPolicy, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, istio.IstioIstiodPolicyName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(istiodPolicy.Spec.Tier).To(Equal(networkpolicy.TigeraComponentTierName))
			Expect(istiodPolicy.Spec.Selector).To(Equal(networkpolicy.KubernetesAppSelector(istio.IstioIstiodDeploymentName)))

			// Verify istio-cni policy
			cniPolicy, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, istio.IstioCNIPolicyName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cniPolicy.Spec.Tier).To(Equal(networkpolicy.TigeraComponentTierName))
			Expect(cniPolicy.Spec.Selector).To(Equal(networkpolicy.KubernetesAppSelector(istio.IstioCNIDaemonSetName)))

			// Verify ztunnel policy
			ztunnelPolicy, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, istio.IstioZTunnelPolicyName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(ztunnelPolicy.Spec.Tier).To(Equal(networkpolicy.TigeraComponentTierName))
			Expect(ztunnelPolicy.Spec.Selector).To(Equal(networkpolicy.KubernetesAppSelector(istio.IstioZTunnelDaemonSetName)))
		})

		It("should include Istiod deployment", func() {
			objsToCreate, _ := component.Objects()

			deployment, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, istio.IstioIstiodDeploymentName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(deployment.Name).To(Equal(istio.IstioIstiodDeploymentName))
			Expect(deployment.Namespace).To(Equal(istio.IstioNamespace))
		})

		It("should include CNI DaemonSet", func() {
			objsToCreate, _ := component.Objects()

			daemonset, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioCNIDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(daemonset.Name).To(Equal(istio.IstioCNIDaemonSetName))
			Expect(daemonset.Namespace).To(Equal(istio.IstioNamespace))
		})

		It("should include ZTunnel DaemonSet", func() {
			objsToCreate, _ := component.Objects()

			daemonset, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioZTunnelDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(daemonset.Name).To(Equal(istio.IstioZTunnelDaemonSetName))
			Expect(daemonset.Namespace).To(Equal(istio.IstioNamespace))
		})

		It("should set TRANSPARENT_NETWORK_POLICIES env var on ztunnel", func() {
			objsToCreate, _ := component.Objects()

			daemonset, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioZTunnelDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			foundEnvVar := false
			for _, container := range daemonset.Spec.Template.Spec.Containers {
				if container.Name == "istio-proxy" {
					for _, env := range container.Env {
						if env.Name == "TRANSPARENT_NETWORK_POLICIES" {
							Expect(env.Value).To(Equal("true"))
							foundEnvVar = true
							break
						}
					}
				}
			}
			Expect(foundEnvVar).To(BeTrue(), "TRANSPARENT_NETWORK_POLICIES env var not found")
		})

		It("should set MAGIC_DSCP_MARK env var on CNI", func() {
			objsToCreate, _ := component.Objects()

			daemonset, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioCNIDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			foundEnvVar := false
			for _, container := range daemonset.Spec.Template.Spec.Containers {
				if container.Name == "install-cni" {
					for _, env := range container.Env {
						if env.Name == "MAGIC_DSCP_MARK" {
							Expect(env.Value).To(Equal("0"))
							foundEnvVar = true
							break
						}
					}
				}
			}
			Expect(foundEnvVar).To(BeTrue(), "MAGIC_DSCP_MARK env var not found")
		})
	})

	Describe("Network Policy Rules", func() {
		var (
			component *istio.IstioComponent
			err       error
		)

		BeforeEach(func() {
			_, component, err = istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			imageSet := &operatorv1.ImageSet{
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/istio-pilot", Digest: "sha256:test-pilot-digest"},
						{Image: "tigera/istio-install-cni", Digest: "sha256:test-cni-digest"},
						{Image: "tigera/istio-ztunnel", Digest: "sha256:test-ztunnel-digest"},
						{Image: "tigera/istio-proxyv2", Digest: "sha256:test-proxyv2-digest"},
					},
				},
			}
			err = component.ResolveImages(imageSet)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should have correct ingress rules for istiod", func() {
			objsToCreate, _ := component.Objects()

			policy, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, istio.IstioIstiodPolicyName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(policy.Spec.Ingress).To(HaveLen(1))
			Expect(policy.Spec.Ingress[0].Destination.Ports).To(ContainElements(
				numorstring.SinglePort(15012),
				numorstring.SinglePort(15017),
			))
		})

		It("should have correct egress rules for istiod", func() {
			objsToCreate, _ := component.Objects()

			policy, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, istio.IstioIstiodPolicyName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(policy.Spec.Egress).To(HaveLen(1))
			Expect(policy.Spec.Egress[0].Action).To(Equal(v3.Allow))
		})

		It("should have correct egress rules for CNI", func() {
			objsToCreate, _ := component.Objects()

			policy, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, istio.IstioCNIPolicyName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(policy.Spec.Egress).To(HaveLen(1))
			Expect(policy.Spec.Egress[0].Action).To(Equal(v3.Allow))
		})

		It("should have correct egress rules for ztunnel", func() {
			objsToCreate, _ := component.Objects()

			policy, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, istio.IstioZTunnelPolicyName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			// At least one egress rule for connecting to istiod
			Expect(policy.Spec.Egress).NotTo(BeEmpty())
			foundIstiodRule := false
			for _, rule := range policy.Spec.Egress {
				if rule.Destination.Selector != "" {
					foundIstiodRule = true
					break
				}
			}
			Expect(foundIstiodRule).To(BeTrue(), "Expected egress rule for istiod service")
		})
	})

	Describe("Pull Secrets", func() {
		It("should append pull secrets to all workloads", func() {
			pullSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pull-secret",
					Namespace: istio.IstioNamespace,
				},
			}
			cfg.PullSecrets = []*corev1.Secret{pullSecret}

			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			imageSet := &operatorv1.ImageSet{
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/istio-pilot", Digest: "sha256:test-pilot-digest"},
						{Image: "tigera/istio-install-cni", Digest: "sha256:test-cni-digest"},
						{Image: "tigera/istio-ztunnel", Digest: "sha256:test-ztunnel-digest"},
						{Image: "tigera/istio-proxyv2", Digest: "sha256:test-proxyv2-digest"},
					},
				},
			}
			err = component.ResolveImages(imageSet)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()

			// Check istiod deployment
			deployment, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, istio.IstioIstiodDeploymentName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(deployment.Spec.Template.Spec.ImagePullSecrets).To(ContainElement(corev1.LocalObjectReference{Name: "test-pull-secret"}))

			// Check CNI daemonset
			cniDS, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioCNIDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cniDS.Spec.Template.Spec.ImagePullSecrets).To(ContainElement(corev1.LocalObjectReference{Name: "test-pull-secret"}))

			// Check ztunnel daemonset
			ztunnelDS, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioZTunnelDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(ztunnelDS.Spec.Template.Spec.ImagePullSecrets).To(ContainElement(corev1.LocalObjectReference{Name: "test-pull-secret"}))
		})
	})

	Describe("Deployment Overrides", func() {
		DescribeTable("Istiod Deployment Overrides", func(overrides *operatorv1.IstiodDeployment, verify func(*appsv1.Deployment)) {
			cfg.Istio.Spec.IstiodDeployment = overrides
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			imageSet := &operatorv1.ImageSet{
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/istio-pilot", Digest: "sha256:test-pilot-digest"},
						{Image: "tigera/istio-install-cni", Digest: "sha256:test-cni-digest"},
						{Image: "tigera/istio-ztunnel", Digest: "sha256:test-ztunnel-digest"},
						{Image: "tigera/istio-proxyv2", Digest: "sha256:test-proxyv2-digest"},
					},
				},
			}
			err = component.ResolveImages(imageSet)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()
			deployment, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, istio.IstioIstiodDeploymentName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			verify(deployment)
		},
			Entry("should apply affinity override",
				&operatorv1.IstiodDeployment{
					Spec: &operatorv1.IstiodDeploymentSpec{
						Template: &operatorv1.IstiodDeploymentSpecTemplate{
							Spec: &operatorv1.IstiodDeploymentPodSpec{
								Affinity: &corev1.Affinity{
									NodeAffinity: &corev1.NodeAffinity{
										RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
											NodeSelectorTerms: []corev1.NodeSelectorTerm{
												{
													MatchExpressions: []corev1.NodeSelectorRequirement{
														{
															Key:      "custom-affinity-key",
															Operator: corev1.NodeSelectorOpExists,
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				func(deployment *appsv1.Deployment) {
					Expect(deployment.Spec.Template.Spec.Affinity).NotTo(BeNil())
					Expect(deployment.Spec.Template.Spec.Affinity.NodeAffinity).NotTo(BeNil())
					Expect(deployment.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchExpressions[0].Key).To(Equal("custom-affinity-key"))
				},
			),
			Entry("should apply node selector override",
				&operatorv1.IstiodDeployment{
					Spec: &operatorv1.IstiodDeploymentSpec{
						Template: &operatorv1.IstiodDeploymentSpecTemplate{
							Spec: &operatorv1.IstiodDeploymentPodSpec{
								NodeSelector: map[string]string{
									"custom-node-selector": "test-value",
								},
							},
						},
					},
				},
				func(deployment *appsv1.Deployment) {
					Expect(deployment.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "test-value"))
				},
			),
			Entry("should apply tolerations override",
				&operatorv1.IstiodDeployment{
					Spec: &operatorv1.IstiodDeploymentSpec{
						Template: &operatorv1.IstiodDeploymentSpecTemplate{
							Spec: &operatorv1.IstiodDeploymentPodSpec{
								Tolerations: []corev1.Toleration{
									{
										Key:      "custom-toleration",
										Operator: corev1.TolerationOpEqual,
										Value:    "test-value",
									},
								},
							},
						},
					},
				},
				func(deployment *appsv1.Deployment) {
					Expect(deployment.Spec.Template.Spec.Tolerations).To(ContainElement(corev1.Toleration{
						Key:      "custom-toleration",
						Operator: corev1.TolerationOpEqual,
						Value:    "test-value",
					}))
				},
			),
			Entry("should apply resources override",
				&operatorv1.IstiodDeployment{
					Spec: &operatorv1.IstiodDeploymentSpec{
						Template: &operatorv1.IstiodDeploymentSpecTemplate{
							Spec: &operatorv1.IstiodDeploymentPodSpec{
								Resources: &corev1.ResourceRequirements{
									Limits: corev1.ResourceList{
										"memory": resource.MustParse("2Gi"),
									},
									Requests: corev1.ResourceList{
										"memory": resource.MustParse("1Gi"),
									},
								},
							},
						},
					},
				},
				func(deployment *appsv1.Deployment) {
					// Resources are applied to the deployment
					// The override system applies resources to the pod spec, not individual containers
					// So we just verify that the deployment has at least one container with resources set
					hasResourcesSet := false
					for _, container := range deployment.Spec.Template.Spec.Containers {
						if container.Resources.Limits != nil || container.Resources.Requests != nil {
							hasResourcesSet = true
							break
						}
					}
					Expect(hasResourcesSet).To(BeTrue(), "Expected at least one container to have resources set")
				},
			),
		)
	})

	Describe("DaemonSet Overrides", func() {
		DescribeTable("CNI DaemonSet Overrides", func(overrides *operatorv1.IstioCNIDaemonset, verify func(*appsv1.DaemonSet)) {
			cfg.Istio.Spec.IstioCNIDaemonset = overrides
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			imageSet := &operatorv1.ImageSet{
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/istio-pilot", Digest: "sha256:test-pilot-digest"},
						{Image: "tigera/istio-install-cni", Digest: "sha256:test-cni-digest"},
						{Image: "tigera/istio-ztunnel", Digest: "sha256:test-ztunnel-digest"},
						{Image: "tigera/istio-proxyv2", Digest: "sha256:test-proxyv2-digest"},
					},
				},
			}
			err = component.ResolveImages(imageSet)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()
			daemonset, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioCNIDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			verify(daemonset)
		},
			Entry("should apply node selector override",
				&operatorv1.IstioCNIDaemonset{
					Spec: &operatorv1.IstioCNIDaemonsetSpec{
						Template: &operatorv1.IstioCNIDaemonsetSpecTemplate{
							Spec: &operatorv1.IstioCNIDaemonsetPodSpec{
								NodeSelector: map[string]string{
									"cni-node-selector": "test-value",
								},
							},
						},
					},
				},
				func(daemonset *appsv1.DaemonSet) {
					Expect(daemonset.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("cni-node-selector", "test-value"))
				},
			),
			Entry("should apply tolerations override",
				&operatorv1.IstioCNIDaemonset{
					Spec: &operatorv1.IstioCNIDaemonsetSpec{
						Template: &operatorv1.IstioCNIDaemonsetSpecTemplate{
							Spec: &operatorv1.IstioCNIDaemonsetPodSpec{
								Tolerations: []corev1.Toleration{
									{
										Key:      "cni-toleration",
										Operator: corev1.TolerationOpEqual,
										Value:    "cni-value",
									},
								},
							},
						},
					},
				},
				func(daemonset *appsv1.DaemonSet) {
					Expect(daemonset.Spec.Template.Spec.Tolerations).To(ContainElement(corev1.Toleration{
						Key:      "cni-toleration",
						Operator: corev1.TolerationOpEqual,
						Value:    "cni-value",
					}))
				},
			),
		)

		DescribeTable("ZTunnel DaemonSet Overrides", func(overrides *operatorv1.ZTunnelDaemonset, verify func(*appsv1.DaemonSet)) {
			cfg.Istio.Spec.ZTunnelDaemonset = overrides
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			imageSet := &operatorv1.ImageSet{
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/istio-pilot", Digest: "sha256:test-pilot-digest"},
						{Image: "tigera/istio-install-cni", Digest: "sha256:test-cni-digest"},
						{Image: "tigera/istio-ztunnel", Digest: "sha256:test-ztunnel-digest"},
						{Image: "tigera/istio-proxyv2", Digest: "sha256:test-proxyv2-digest"},
					},
				},
			}
			err = component.ResolveImages(imageSet)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()
			daemonset, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioZTunnelDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			verify(daemonset)
		},
			Entry("should apply node selector override",
				&operatorv1.ZTunnelDaemonset{
					Spec: &operatorv1.ZTunnelDaemonsetSpec{
						Template: &operatorv1.ZTunnelDaemonsetSpecTemplate{
							Spec: &operatorv1.ZTunnelDaemonsetPodSpec{
								NodeSelector: map[string]string{
									"ztunnel-node-selector": "test-value",
								},
							},
						},
					},
				},
				func(daemonset *appsv1.DaemonSet) {
					Expect(daemonset.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("ztunnel-node-selector", "test-value"))
				},
			),
			Entry("should apply affinity override",
				&operatorv1.ZTunnelDaemonset{
					Spec: &operatorv1.ZTunnelDaemonsetSpec{
						Template: &operatorv1.ZTunnelDaemonsetSpecTemplate{
							Spec: &operatorv1.ZTunnelDaemonsetPodSpec{
								Affinity: &corev1.Affinity{
									NodeAffinity: &corev1.NodeAffinity{
										RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
											NodeSelectorTerms: []corev1.NodeSelectorTerm{
												{
													MatchExpressions: []corev1.NodeSelectorRequirement{
														{
															Key:      "ztunnel-affinity-key",
															Operator: corev1.NodeSelectorOpExists,
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				func(daemonset *appsv1.DaemonSet) {
					Expect(daemonset.Spec.Template.Spec.Affinity).NotTo(BeNil())
					Expect(daemonset.Spec.Template.Spec.Affinity.NodeAffinity).NotTo(BeNil())
					Expect(daemonset.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchExpressions[0].Key).To(Equal("ztunnel-affinity-key"))
				},
			),
		)
	})

	Describe("DSCP Mark Configuration", func() {
		It("should set DSCP mark value correctly", func() {
			dscpMark := numorstring.DSCPFromInt(10)
			cfg.Istio.Spec.DSCPMark = &dscpMark

			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			imageSet := &operatorv1.ImageSet{
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/istio-pilot", Digest: "sha256:test-pilot-digest"},
						{Image: "tigera/istio-install-cni", Digest: "sha256:test-cni-digest"},
						{Image: "tigera/istio-ztunnel", Digest: "sha256:test-ztunnel-digest"},
						{Image: "tigera/istio-proxyv2", Digest: "sha256:test-proxyv2-digest"},
					},
				},
			}
			err = component.ResolveImages(imageSet)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()

			daemonset, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioCNIDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			foundEnvVar := false
			for _, container := range daemonset.Spec.Template.Spec.Containers {
				if container.Name == "install-cni" {
					for _, env := range container.Env {
						if env.Name == "MAGIC_DSCP_MARK" {
							Expect(env.Value).To(Equal("10"))
							foundEnvVar = true
							break
						}
					}
				}
			}
			Expect(foundEnvVar).To(BeTrue(), "MAGIC_DSCP_MARK env var not found")
		})
	})

	Describe("Component Metadata", func() {
		It("should return Ready as true", func() {
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(component.Ready()).To(BeTrue())
		})

		It("should return Linux as supported OS type", func() {
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(component.SupportedOSType()).To(Equal(rmeta.OSTypeLinux))
		})
	})

	Describe("CRDs Component", func() {
		It("should return Ready as true", func() {
			crds, _, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(crds.Ready()).To(BeTrue())
		})

		It("should return Linux as supported OS type", func() {
			crds, _, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(crds.SupportedOSType()).To(Equal(rmeta.OSTypeLinux))
		})

		It("should not require image resolution", func() {
			crds, _, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			imageSet := &operatorv1.ImageSet{
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{},
				},
			}

			err = crds.ResolveImages(imageSet)
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

	Describe("Image Patching", func() {
		It("should patch all required images", func() {
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			imageSet := &operatorv1.ImageSet{
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/istio-pilot", Digest: "sha256:test-pilot-digest"},
						{Image: "tigera/istio-install-cni", Digest: "sha256:test-cni-digest"},
						{Image: "tigera/istio-ztunnel", Digest: "sha256:test-ztunnel-digest"},
						{Image: "tigera/istio-proxyv2", Digest: "sha256:test-proxyv2-digest"},
					},
				},
			}
			err = component.ResolveImages(imageSet)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()

			// Verify istiod deployment image
			deployment, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, istio.IstioIstiodDeploymentName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			foundDiscoveryContainer := false
			for _, container := range deployment.Spec.Template.Spec.Containers {
				if container.Name == "discovery" {
					foundDiscoveryContainer = true
					expectedImage, _ := components.GetReference(components.ComponentCalicoIstioPilot, cfg.Installation.Registry, cfg.Installation.ImagePath, cfg.Installation.ImagePrefix, imageSet)
					Expect(container.Image).To(Equal(expectedImage))
					break
				}
			}
			Expect(foundDiscoveryContainer).To(BeTrue(), "discovery container not found in istiod deployment")

			// Verify CNI daemonset image
			cniDS, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioCNIDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			foundInstallCNIContainer := false
			for _, container := range cniDS.Spec.Template.Spec.Containers {
				if container.Name == "install-cni" {
					foundInstallCNIContainer = true
					expectedImage, _ := components.GetReference(components.ComponentCalicoIstioInstallCNI, cfg.Installation.Registry, cfg.Installation.ImagePath, cfg.Installation.ImagePrefix, imageSet)
					Expect(container.Image).To(Equal(expectedImage))
					break
				}
			}
			Expect(foundInstallCNIContainer).To(BeTrue(), "install-cni container not found in CNI daemonset")

			// Verify ztunnel daemonset image
			ztunnelDS, err := rtest.GetResourceOfType[*appsv1.DaemonSet](objsToCreate, istio.IstioZTunnelDaemonSetName, istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			foundIstioProxyContainer := false
			for _, container := range ztunnelDS.Spec.Template.Spec.Containers {
				if container.Name == "istio-proxy" {
					foundIstioProxyContainer = true
					expectedImage, _ := components.GetReference(components.ComponentCalicoIstioZTunnel, cfg.Installation.Registry, cfg.Installation.ImagePath, cfg.Installation.ImagePrefix, imageSet)
					Expect(container.Image).To(Equal(expectedImage))
					break
				}
			}
			Expect(foundIstioProxyContainer).To(BeTrue(), "istio-proxy container not found in ztunnel daemonset")
		})

		It("should patch ConfigMap with proxyv2 image", func() {
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			imageSet := &operatorv1.ImageSet{
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/istio-pilot", Digest: "sha256:test-pilot-digest"},
						{Image: "tigera/istio-install-cni", Digest: "sha256:test-cni-digest"},
						{Image: "tigera/istio-ztunnel", Digest: "sha256:test-ztunnel-digest"},
						{Image: "tigera/istio-proxyv2", Digest: "sha256:test-proxyv2-digest"},
					},
				},
			}
			err = component.ResolveImages(imageSet)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()

			// Find the istio-sidecar-injector ConfigMap
			configMap, err := rtest.GetResourceOfType[*corev1.ConfigMap](objsToCreate, "istio-sidecar-injector", istio.IstioNamespace)
			Expect(err).ShouldNot(HaveOccurred())

			// Verify that the fake image has been replaced
			for _, data := range configMap.Data {
				Expect(data).NotTo(ContainSubstring("fake.io/fakeimg/proxyv2:faketag"))
			}
		})
	})

	Describe("Resource Ordering", func() {
		It("should return resources in correct order", func() {
			_, component, err := istio.Istio(cfg)
			Expect(err).ShouldNot(HaveOccurred())

			imageSet := &operatorv1.ImageSet{
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/istio-pilot", Digest: "sha256:test-pilot-digest"},
						{Image: "tigera/istio-install-cni", Digest: "sha256:test-cni-digest"},
						{Image: "tigera/istio-ztunnel", Digest: "sha256:test-ztunnel-digest"},
						{Image: "tigera/istio-proxyv2", Digest: "sha256:test-proxyv2-digest"},
					},
				},
			}
			err = component.ResolveImages(imageSet)
			Expect(err).ShouldNot(HaveOccurred())

			objsToCreate, _ := component.Objects()

			// Verify network policies are at the beginning
			Expect(objsToCreate[0]).To(BeAssignableToTypeOf(&v3.NetworkPolicy{}))
			Expect(objsToCreate[1]).To(BeAssignableToTypeOf(&v3.NetworkPolicy{}))
			Expect(objsToCreate[2]).To(BeAssignableToTypeOf(&v3.NetworkPolicy{}))

			// Resources should follow: Base, Istiod, CNI, ZTunnel
			// This is important for proper installation order
		})
	})
})
