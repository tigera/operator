// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gapi "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml" // gopkg.in/yaml.v2 didn't parse all the fields but this package did
)

var _ = Describe("Gateway API rendering tests", func() {

	It("should read Gateway API resources from YAML", func() {
		resources := GatewayAPIResources()
		Expect(resources.namespace.Name).To(Equal("tigera-gateway"))
	})

	It("should apply overrides from GatewayAPI CR", func() {
		installation := &operatorv1.InstallationSpec{}
		five := int32(5)
		affinity := &corev1.Affinity{}
		resourceRequirements := &corev1.ResourceRequirements{
			Claims: []corev1.ResourceClaim{{
				Name: "whatnot",
			}},
		}
		tolerations := []corev1.Toleration{}
		rollingUpdate := &appsv1.RollingUpdateDeployment{}
		topologySpreadConstraints := []corev1.TopologySpreadConstraint{}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayControllerDeployment: &operatorv1.GatewayControllerDeployment{
					Metadata: &operatorv1.Metadata{
						Labels: map[string]string{
							"x":     "y",
							"white": "black",
						},
						Annotations: map[string]string{
							"up":    "down",
							"round": "flat",
						},
					},
					Spec: &operatorv1.GatewayControllerDeploymentSpec{
						MinReadySeconds: &five,
						Template: &operatorv1.GatewayControllerDeploymentPodTemplate{
							Metadata: &operatorv1.Metadata{
								Labels: map[string]string{
									"rural": "urban",
								},
								Annotations: map[string]string{
									"haste": "speed",
								},
							},
							Spec: &operatorv1.GatewayControllerDeploymentPodSpec{
								Affinity: affinity,
								Containers: []operatorv1.GatewayControllerDeploymentContainer{{
									Name:      "envoy-gateway",
									Resources: resourceRequirements,
								}},
								NodeSelector: map[string]string{
									"fast": "slow",
								},
								Tolerations: tolerations,
							},
						},
					},
				},
				GatewayClasses: []operatorv1.GatewayClassSpec{{
					Name: "tigera-gateway-class",
					GatewayDeployment: &operatorv1.GatewayDeployment{
						Spec: &operatorv1.GatewayDeploymentSpec{
							Template: &operatorv1.GatewayDeploymentPodTemplate{
								Metadata: &operatorv1.Metadata{
									Labels: map[string]string{
										"g-rural": "urban",
									},
									Annotations: map[string]string{
										"g-haste": "speed",
									},
								},
								Spec: &operatorv1.GatewayDeploymentPodSpec{
									Affinity: affinity,
									Containers: []operatorv1.GatewayDeploymentContainer{{
										Name:      "envoy",
										Resources: resourceRequirements,
									}},
									NodeSelector: map[string]string{
										"g-fast": "slow",
									},
									Tolerations:               tolerations,
									TopologySpreadConstraints: topologySpreadConstraints,
								},
							},
							Strategy: &operatorv1.GatewayDeploymentStrategy{
								RollingUpdate: rollingUpdate,
							},
						},
					},
				}},
				GatewayCertgenJob: &operatorv1.GatewayCertgenJob{
					Metadata: &operatorv1.Metadata{
						Labels: map[string]string{
							"job-x":     "y",
							"job-white": "black",
						},
						Annotations: map[string]string{
							"job-up":    "down",
							"job-round": "flat",
						},
					},
					Spec: &operatorv1.GatewayCertgenJobSpec{
						Template: &operatorv1.GatewayCertgenJobPodTemplate{
							Metadata: &operatorv1.Metadata{
								Labels: map[string]string{
									"job-rural": "urban",
								},
								Annotations: map[string]string{
									"job-haste": "speed",
								},
							},
							Spec: &operatorv1.GatewayCertgenJobPodSpec{
								Affinity: affinity,
								Containers: []operatorv1.GatewayCertgenJobContainer{{
									Name:      "envoy-gateway-certgen",
									Resources: resourceRequirements,
								}},
								NodeSelector: map[string]string{
									"job-fast": "slow",
								},
								Tolerations: tolerations,
							},
						},
					},
				},
			},
		}
		gatewayComp := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Installation: installation,
			GatewayAPI:   gatewayAPI,
		})
		objsToCreate, objsToDelete := gatewayComp.Objects()
		Expect(objsToDelete).To(HaveLen(0))
		rtest.ExpectResources(objsToCreate, []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator-secrets", Namespace: "tigera-gateway"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: "tigera-gateway"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway-config", Namespace: "tigera-gateway"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-envoy-gateway-role"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-envoy-gateway-rolebinding"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-infra-manager", Namespace: "tigera-gateway"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-leader-election-role", Namespace: "tigera-gateway"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-infra-manager", Namespace: "tigera-gateway"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-leader-election-rolebinding", Namespace: "tigera-gateway"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: "tigera-gateway"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: "tigera-gateway"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "tigera-gateway"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "tigera-gateway"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "tigera-gateway"}},
			&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "tigera-gateway"}},
			&envoyapi.EnvoyProxy{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-class", Namespace: "tigera-gateway"}},
			&gapi.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-class", Namespace: "tigera-gateway"}},
		})

		deploy, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, "envoy-gateway", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		Expect(deploy.Labels).To(HaveKeyWithValue("x", "y"))
		Expect(deploy.Labels).To(HaveKeyWithValue("white", "black"))
		Expect(deploy.Annotations).To(HaveKeyWithValue("up", "down"))
		Expect(deploy.Annotations).To(HaveKeyWithValue("round", "flat"))
		Expect(deploy.Spec.MinReadySeconds).To(BeNumerically("==", 5))
		Expect(deploy.Spec.Template.Labels).To(HaveKeyWithValue("rural", "urban"))
		Expect(deploy.Spec.Template.Annotations).To(HaveKeyWithValue("haste", "speed"))
		Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(affinity))
		Expect(deploy.Spec.Template.Spec.Containers).To(ContainElement(And(
			HaveField("Name", "envoy-gateway"),
			HaveField("Resources", *resourceRequirements),
		)))
		Expect(deploy.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("fast", "slow"))
		Expect(deploy.Spec.Template.Spec.Tolerations).To(Equal(tolerations))

		job, err := rtest.GetResourceOfType[*batchv1.Job](objsToCreate, "tigera-gateway-api-gateway-helm-certgen", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		Expect(job.Labels).To(HaveKeyWithValue("job-x", "y"))
		Expect(job.Labels).To(HaveKeyWithValue("job-white", "black"))
		Expect(job.Annotations).To(HaveKeyWithValue("job-up", "down"))
		Expect(job.Annotations).To(HaveKeyWithValue("job-round", "flat"))
		Expect(job.Spec.Template.Labels).To(HaveKeyWithValue("job-rural", "urban"))
		Expect(job.Spec.Template.Annotations).To(HaveKeyWithValue("job-haste", "speed"))
		Expect(job.Spec.Template.Spec.Affinity).To(Equal(affinity))
		Expect(job.Spec.Template.Spec.Containers).To(ContainElement(And(
			HaveField("Name", "envoy-gateway-certgen"),
			HaveField("Resources", *resourceRequirements),
		)))
		Expect(job.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("job-fast", "slow"))
		Expect(job.Spec.Template.Spec.Tolerations).To(Equal(tolerations))

		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, "tigera-gateway-class", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Labels).To(HaveKeyWithValue("g-rural", "urban"))
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Annotations).To(HaveKeyWithValue("g-haste", "speed"))
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Affinity).To(Equal(affinity))
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.NodeSelector).To(HaveKeyWithValue("g-fast", "slow"))
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Tolerations).To(Equal(tolerations))
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.TopologySpreadConstraints).To(Equal(topologySpreadConstraints))
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.Resources).To(Equal(resourceRequirements))
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Strategy.RollingUpdate).To(Equal(rollingUpdate))
	})

	It("should honour private registry (OSS)", func() {
		pullSecretRefs := []corev1.LocalObjectReference{{
			Name: "secret1",
		}}
		pullSecrets := []*corev1.Secret{}
		for _, ref := range pullSecretRefs {
			pullSecrets = append(pullSecrets, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: "tigera-gateway"},
			})
		}
		installation := &operatorv1.InstallationSpec{
			Registry:         "myregistry.io/",
			ImagePullSecrets: pullSecretRefs,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
			},
		}
		gatewayComp := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Installation: installation,
			GatewayAPI:   gatewayAPI,
			PullSecrets:  pullSecrets,
		})

		Expect(gatewayComp.ResolveImages(nil)).NotTo(HaveOccurred())
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyGatewayImage).To(Equal("myregistry.io/calico/envoy-gateway:" + components.ComponentCalicoEnvoyGateway.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyRatelimitImage).To(Equal("myregistry.io/calico/envoy-ratelimit:" + components.ComponentCalicoEnvoyRatelimit.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyProxyImage).To(Equal("myregistry.io/calico/envoy-proxy:" + components.ComponentCalicoEnvoyProxy.Version))

		objsToCreate, objsToDelete := gatewayComp.Objects()
		Expect(objsToDelete).To(HaveLen(0))
		rtest.ExpectResources(objsToCreate, []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator-secrets", Namespace: "tigera-gateway"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: "tigera-gateway"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway-config", Namespace: "tigera-gateway"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-envoy-gateway-role"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-envoy-gateway-rolebinding"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-infra-manager", Namespace: "tigera-gateway"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-leader-election-role", Namespace: "tigera-gateway"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-infra-manager", Namespace: "tigera-gateway"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-leader-election-rolebinding", Namespace: "tigera-gateway"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: "tigera-gateway"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: "tigera-gateway"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "tigera-gateway"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "tigera-gateway"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "tigera-gateway"}},
			&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "tigera-gateway"}},
			&envoyapi.EnvoyProxy{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-class", Namespace: "tigera-gateway"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret1", Namespace: "tigera-gateway"}},
			&gapi.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-class", Namespace: "tigera-gateway"}},
		})

		deploy, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, "envoy-gateway", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		Expect(deploy.Spec.Template.Spec.Containers).To(ContainElement(And(
			HaveField("Name", "envoy-gateway"),
			HaveField("Image", "myregistry.io/calico/envoy-gateway:"+components.ComponentCalicoEnvoyGateway.Version),
		)))
		Expect(deploy.Spec.Template.Spec.ImagePullSecrets).To(ContainElement(pullSecretRefs[0]))

		job, err := rtest.GetResourceOfType[*batchv1.Job](objsToCreate, "tigera-gateway-api-gateway-helm-certgen", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		Expect(job.Spec.Template.Spec.Containers).To(ContainElement(And(
			HaveField("Name", "envoy-gateway-certgen"),
			HaveField("Image", "myregistry.io/calico/envoy-gateway:"+components.ComponentCalicoEnvoyGateway.Version),
		)))
		Expect(job.Spec.Template.Spec.ImagePullSecrets).To(ContainElement(pullSecretRefs[0]))

		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, "tigera-gateway-class", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		Expect(*proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.Image).To(Equal("myregistry.io/calico/envoy-proxy:" + components.ComponentCalicoEnvoyProxy.Version))
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.ImagePullSecrets).To(ContainElement(pullSecretRefs[0]))

		gatewayCM, err := rtest.GetResourceOfType[*corev1.ConfigMap](objsToCreate, "envoy-gateway-config", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		gatewayConfig := &envoyapi.EnvoyGateway{}
		Expect(yaml.Unmarshal([]byte(gatewayCM.Data[EnvoyGatewayConfigKey]), gatewayConfig)).NotTo(HaveOccurred())
		Expect(gatewayConfig.APIVersion).NotTo(Equal(""), fmt.Sprintf("gatewayConfig = %#v", *gatewayConfig))
		Expect(gatewayConfig.Provider.Kubernetes.RateLimitDeployment).NotTo(BeNil())
		Expect(gatewayConfig.Provider.Kubernetes.RateLimitDeployment.Container).NotTo(BeNil())
		Expect(*gatewayConfig.Provider.Kubernetes.RateLimitDeployment.Container.Image).To(Equal("myregistry.io/calico/envoy-ratelimit:" + components.ComponentCalicoEnvoyRatelimit.Version))
		Expect(gatewayConfig.Provider.Kubernetes.RateLimitDeployment.Pod.ImagePullSecrets).To(ContainElement(pullSecretRefs[0]))
		Expect(*gatewayConfig.Provider.Kubernetes.ShutdownManager.Image).To(Equal("myregistry.io/calico/envoy-gateway:" + components.ComponentCalicoEnvoyGateway.Version))
		Expect(gatewayConfig.ExtensionAPIs).NotTo(BeNil())
		Expect(gatewayConfig.ExtensionAPIs.EnableBackend).To(BeTrue())
	})

	It("should honour private registry (Enterprise)", func() {
		pullSecretRefs := []corev1.LocalObjectReference{{
			Name: "secret1",
		}}
		pullSecrets := []*corev1.Secret{}
		for _, ref := range pullSecretRefs {
			pullSecrets = append(pullSecrets, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: "tigera-gateway"},
			})
		}
		installation := &operatorv1.InstallationSpec{
			Registry:         "myregistry.io/",
			ImagePullSecrets: pullSecretRefs,
			Variant:          operatorv1.TigeraSecureEnterprise,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
			},
		}
		gatewayComp := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Installation: installation,
			GatewayAPI:   gatewayAPI,
			PullSecrets:  pullSecrets,
		})

		Expect(gatewayComp.ResolveImages(nil)).NotTo(HaveOccurred())
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyGatewayImage).To(Equal("myregistry.io/tigera/envoy-gateway:" + components.ComponentGatewayAPIEnvoyGateway.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyRatelimitImage).To(Equal("myregistry.io/tigera/envoy-ratelimit:" + components.ComponentGatewayAPIEnvoyRatelimit.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyProxyImage).To(Equal("myregistry.io/tigera/envoy-proxy:" + components.ComponentGatewayAPIEnvoyProxy.Version))

		objsToCreate, objsToDelete := gatewayComp.Objects()
		Expect(objsToDelete).To(HaveLen(0))
		rtest.ExpectResources(objsToCreate, []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator-secrets", Namespace: "tigera-gateway"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: "tigera-gateway"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway-config", Namespace: "tigera-gateway"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-envoy-gateway-role"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-envoy-gateway-rolebinding"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-infra-manager", Namespace: "tigera-gateway"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-leader-election-role", Namespace: "tigera-gateway"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-infra-manager", Namespace: "tigera-gateway"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-leader-election-rolebinding", Namespace: "tigera-gateway"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: "tigera-gateway"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: "tigera-gateway"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "tigera-gateway"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "tigera-gateway"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "tigera-gateway"}},
			&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen", Namespace: "tigera-gateway"}},
			&envoyapi.EnvoyProxy{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-class", Namespace: "tigera-gateway"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret1", Namespace: "tigera-gateway"}},
			&gapi.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-class", Namespace: "tigera-gateway"}},
		})

		deploy, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, "envoy-gateway", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		Expect(deploy.Spec.Template.Spec.Containers).To(ContainElement(And(
			HaveField("Name", "envoy-gateway"),
			HaveField("Image", "myregistry.io/tigera/envoy-gateway:"+components.ComponentGatewayAPIEnvoyGateway.Version),
		)))
		Expect(deploy.Spec.Template.Spec.ImagePullSecrets).To(ContainElement(pullSecretRefs[0]))

		job, err := rtest.GetResourceOfType[*batchv1.Job](objsToCreate, "tigera-gateway-api-gateway-helm-certgen", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		Expect(job.Spec.Template.Spec.Containers).To(ContainElement(And(
			HaveField("Name", "envoy-gateway-certgen"),
			HaveField("Image", "myregistry.io/tigera/envoy-gateway:"+components.ComponentGatewayAPIEnvoyGateway.Version),
		)))
		Expect(job.Spec.Template.Spec.ImagePullSecrets).To(ContainElement(pullSecretRefs[0]))

		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, "tigera-gateway-class", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		Expect(*proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.Image).To(Equal("myregistry.io/tigera/envoy-proxy:" + components.ComponentGatewayAPIEnvoyProxy.Version))
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.ImagePullSecrets).To(ContainElement(pullSecretRefs[0]))

		gatewayCM, err := rtest.GetResourceOfType[*corev1.ConfigMap](objsToCreate, "envoy-gateway-config", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		gatewayConfig := &envoyapi.EnvoyGateway{}
		Expect(yaml.Unmarshal([]byte(gatewayCM.Data[EnvoyGatewayConfigKey]), gatewayConfig)).NotTo(HaveOccurred())
		Expect(gatewayConfig.APIVersion).NotTo(Equal(""), fmt.Sprintf("gatewayConfig = %#v", *gatewayConfig))
		Expect(gatewayConfig.Provider.Kubernetes.RateLimitDeployment).NotTo(BeNil())
		Expect(gatewayConfig.Provider.Kubernetes.RateLimitDeployment.Container).NotTo(BeNil())
		Expect(*gatewayConfig.Provider.Kubernetes.RateLimitDeployment.Container.Image).To(Equal("myregistry.io/tigera/envoy-ratelimit:" + components.ComponentGatewayAPIEnvoyRatelimit.Version))
		Expect(gatewayConfig.Provider.Kubernetes.RateLimitDeployment.Pod.ImagePullSecrets).To(ContainElement(pullSecretRefs[0]))
		Expect(*gatewayConfig.Provider.Kubernetes.ShutdownManager.Image).To(Equal("myregistry.io/tigera/envoy-gateway:" + components.ComponentGatewayAPIEnvoyGateway.Version))
	})

	It("honours gateway controller customizations", func() {
		installation := &operatorv1.InstallationSpec{
			Registry: "myregistry.io/",
			Variant:  operatorv1.TigeraSecureEnterprise,
		}
		threeReplicas := int32(3)
		topologySpreadConstraints := []corev1.TopologySpreadConstraint{{
			MaxSkew:     2,
			TopologyKey: "balanced",
		}}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
				GatewayControllerDeployment: &operatorv1.GatewayControllerDeployment{
					Spec: &operatorv1.GatewayControllerDeploymentSpec{
						Replicas: &threeReplicas,
						Template: &operatorv1.GatewayControllerDeploymentPodTemplate{
							Metadata: &operatorv1.Metadata{},
							Spec: &operatorv1.GatewayControllerDeploymentPodSpec{
								TopologySpreadConstraints: topologySpreadConstraints,
							},
						},
					},
				},
			},
		}
		customName := "my-gateway-controller"
		gatewayComp := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Installation: installation,
			GatewayAPI:   gatewayAPI,
			CustomEnvoyGateway: &envoyapi.EnvoyGateway{
				EnvoyGatewaySpec: envoyapi.EnvoyGatewaySpec{
					Provider: &envoyapi.EnvoyGatewayProvider{
						Type: envoyapi.ProviderTypeKubernetes,
						Kubernetes: &envoyapi.EnvoyGatewayKubernetesProvider{
							RateLimitDeployment: &envoyapi.KubernetesDeploymentSpec{
								Name: &customName,
							},
						},
					},
					ExtensionAPIs: &envoyapi.ExtensionAPISettings{
						EnableEnvoyPatchPolicy: true,
					},
				},
			},
		})

		Expect(gatewayComp.ResolveImages(nil)).NotTo(HaveOccurred())
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyGatewayImage).To(Equal("myregistry.io/tigera/envoy-gateway:" + components.ComponentGatewayAPIEnvoyGateway.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyRatelimitImage).To(Equal("myregistry.io/tigera/envoy-ratelimit:" + components.ComponentGatewayAPIEnvoyRatelimit.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyProxyImage).To(Equal("myregistry.io/tigera/envoy-proxy:" + components.ComponentGatewayAPIEnvoyProxy.Version))

		objsToCreate, objsToDelete := gatewayComp.Objects()
		Expect(objsToDelete).To(HaveLen(0))

		deploy, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, "envoy-gateway", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		Expect(deploy.Spec.Replicas).NotTo(BeNil())
		Expect(*deploy.Spec.Replicas).To(BeNumerically("==", threeReplicas))
		Expect(deploy.Spec.Template.Spec.TopologySpreadConstraints).NotTo(BeNil())
		Expect(deploy.Spec.Template.Spec.TopologySpreadConstraints).To(Equal(topologySpreadConstraints))

		gatewayCM, err := rtest.GetResourceOfType[*corev1.ConfigMap](objsToCreate, "envoy-gateway-config", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		gatewayConfig := &envoyapi.EnvoyGateway{}
		Expect(yaml.Unmarshal([]byte(gatewayCM.Data[EnvoyGatewayConfigKey]), gatewayConfig)).NotTo(HaveOccurred())
		Expect(gatewayConfig.Provider.Kubernetes.RateLimitDeployment).NotTo(BeNil())
		Expect(gatewayConfig.Provider.Kubernetes.RateLimitDeployment.Name).NotTo(BeNil())
		Expect(*gatewayConfig.Provider.Kubernetes.RateLimitDeployment.Name).To(Equal(customName))
		Expect(*gatewayConfig.Provider.Kubernetes.ShutdownManager.Image).To(Equal("myregistry.io/tigera/envoy-gateway:" + components.ComponentGatewayAPIEnvoyGateway.Version))
		Expect(gatewayConfig.ExtensionAPIs).NotTo(BeNil())
		Expect(gatewayConfig.ExtensionAPIs.EnableBackend).To(BeTrue())
		Expect(gatewayConfig.ExtensionAPIs.EnableEnvoyPatchPolicy).To(BeTrue())
	})

	It("honours GatewayClass and EnvoyProxy customizations", func() {
		installation := &operatorv1.InstallationSpec{
			Registry: "myregistry.io/",
			Variant:  operatorv1.TigeraSecureEnterprise,
		}
		twoReplicas := int32(2)
		topologySpreadConstraints := []corev1.TopologySpreadConstraint{{
			MaxSkew:     2,
			TopologyKey: "balanced",
		}}
		lbClass := "upper"
		lbIP := "10.4.10.4"
		resourceRequirements := &corev1.ResourceRequirements{
			Claims: []corev1.ResourceClaim{{
				Name: "whatnot",
			}},
		}
		daemonSet := operatorv1.GatewayKindDaemonSet
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{
					Name: "custom-class-1",
					EnvoyProxyRef: &operatorv1.NamespacedName{
						Namespace: "default",
						Name:      "my-proxy-1",
					},
					GatewayService: &operatorv1.GatewayService{
						Metadata: &operatorv1.Metadata{
							Annotations: map[string]string{
								"service.beta.kubernetes.io/aws-load-balancer-type":            "external",
								"service.beta.kubernetes.io/aws-load-balancer-nlb-target-type": "instance",
								"service.beta.kubernetes.io/aws-load-balancer-scheme":          "internet-facing",
							},
						},
					},
				}, {
					Name: "custom-class-2",
					EnvoyProxyRef: &operatorv1.NamespacedName{
						Namespace: "default",
						Name:      "my-proxy-2", // Daemonset instead of Deployment
					},
					GatewayDaemonSet: &operatorv1.GatewayDaemonSet{
						Spec: &operatorv1.GatewayDaemonSetSpec{
							Template: &operatorv1.GatewayDaemonSetPodTemplate{
								Spec: &operatorv1.GatewayDaemonSetPodSpec{
									TopologySpreadConstraints: topologySpreadConstraints,
								},
							},
						},
					},
				}, {
					Name: "custom-class-3",
					// No custom EnvoyProxy for this class.
					GatewayDeployment: &operatorv1.GatewayDeployment{
						Spec: &operatorv1.GatewayDeploymentSpec{
							Replicas: &twoReplicas,
							Template: &operatorv1.GatewayDeploymentPodTemplate{
								Metadata: &operatorv1.Metadata{
									Labels: map[string]string{
										"envoy-proxy": "standard",
									},
								},
								Spec: &operatorv1.GatewayDeploymentPodSpec{
									Containers: []operatorv1.GatewayDeploymentContainer{{
										Name:      "envoy",
										Resources: resourceRequirements,
									}},
									NodeSelector: map[string]string{
										"east": "west",
									},
								},
							},
						},
					},
					GatewayService: &operatorv1.GatewayService{
						Spec: &operatorv1.GatewayServiceSpec{
							LoadBalancerClass: &lbClass,
							LoadBalancerSourceRanges: []string{
								"182.98.44.55/24",
							},
							LoadBalancerIP: &lbIP,
						},
					},
				}, {
					Name: "custom-class-4",
					// Same as custom-class-3 but with DaemonSet.
					GatewayKind: &daemonSet,
					GatewayDaemonSet: &operatorv1.GatewayDaemonSet{
						Spec: &operatorv1.GatewayDaemonSetSpec{
							Template: &operatorv1.GatewayDaemonSetPodTemplate{
								Metadata: &operatorv1.Metadata{
									Labels: map[string]string{
										"envoy-proxy": "standard",
									},
								},
								Spec: &operatorv1.GatewayDaemonSetPodSpec{
									Containers: []operatorv1.GatewayDaemonSetContainer{{
										Name:      "envoy",
										Resources: resourceRequirements,
									}},
									NodeSelector: map[string]string{
										"east": "west",
									},
								},
							},
						},
					},
					GatewayService: &operatorv1.GatewayService{
						Spec: &operatorv1.GatewayServiceSpec{
							LoadBalancerClass: &lbClass,
							LoadBalancerSourceRanges: []string{
								"182.98.44.55/24",
							},
							LoadBalancerIP: &lbIP,
						},
					},
				}},
			},
		}

		envoyProxy1 := &envoyapi.EnvoyProxy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "EnvoyProxy",
				APIVersion: "gateway.envoyproxy.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-proxy-1",
				Namespace: "default",
			},
			Spec: envoyapi.EnvoyProxySpec{
				Logging: envoyapi.ProxyLogging{
					Level: map[envoyapi.ProxyLogComponent]envoyapi.LogLevel{
						envoyapi.LogComponentAdmin: envoyapi.LogLevelWarn,
					},
				},
			},
		}
		envoyProxy2 := &envoyapi.EnvoyProxy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "EnvoyProxy",
				APIVersion: "gateway.envoyproxy.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-proxy-2",
				Namespace: "default",
			},
			Spec: envoyapi.EnvoyProxySpec{
				Provider: &envoyapi.EnvoyProxyProvider{
					Type: envoyapi.ProviderTypeKubernetes,
					Kubernetes: &envoyapi.EnvoyProxyKubernetesProvider{
						EnvoyDaemonSet: &envoyapi.KubernetesDaemonSetSpec{
							Pod: &envoyapi.KubernetesPodSpec{
								NodeSelector: map[string]string{
									"x": "y",
								},
							},
						},
					},
				},
			},
		}

		gatewayComp := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Installation: installation,
			GatewayAPI:   gatewayAPI,
			CustomEnvoyProxies: map[string]*envoyapi.EnvoyProxy{
				"custom-class-1": envoyProxy1,
				"custom-class-2": envoyProxy2,
			},
		})

		Expect(gatewayComp.ResolveImages(nil)).NotTo(HaveOccurred())
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyGatewayImage).To(Equal("myregistry.io/tigera/envoy-gateway:" + components.ComponentGatewayAPIEnvoyGateway.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyRatelimitImage).To(Equal("myregistry.io/tigera/envoy-ratelimit:" + components.ComponentGatewayAPIEnvoyRatelimit.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyProxyImage).To(Equal("myregistry.io/tigera/envoy-proxy:" + components.ComponentGatewayAPIEnvoyProxy.Version))

		objsToCreate, objsToDelete := gatewayComp.Objects()
		Expect(objsToDelete).To(HaveLen(0))

		// The default GatewayClass should not exist.
		_, err := rtest.GetResourceOfType[*gapi.GatewayClass](objsToCreate, "tigera-gateway-class", "tigera-gateway")
		Expect(err).To(HaveOccurred())

		// Get the four expected GatewayClasses.
		gc1, err := rtest.GetResourceOfType[*gapi.GatewayClass](objsToCreate, "custom-class-1", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		gc2, err := rtest.GetResourceOfType[*gapi.GatewayClass](objsToCreate, "custom-class-2", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		gc3, err := rtest.GetResourceOfType[*gapi.GatewayClass](objsToCreate, "custom-class-3", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		gc4, err := rtest.GetResourceOfType[*gapi.GatewayClass](objsToCreate, "custom-class-4", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())

		// Get their four EnvoyProxies.
		Expect(gc1.Spec.ParametersRef).NotTo(BeNil())
		ep1, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, gc1.Spec.ParametersRef.Name, string(*gc1.Spec.ParametersRef.Namespace))
		Expect(err).NotTo(HaveOccurred())
		ep2, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, gc2.Spec.ParametersRef.Name, string(*gc2.Spec.ParametersRef.Namespace))
		Expect(err).NotTo(HaveOccurred())
		ep3, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, gc3.Spec.ParametersRef.Name, string(*gc3.Spec.ParametersRef.Namespace))
		Expect(err).NotTo(HaveOccurred())
		ep4, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, gc4.Spec.ParametersRef.Name, string(*gc4.Spec.ParametersRef.Namespace))
		Expect(err).NotTo(HaveOccurred())

		// Check customizations from custom EnvoyProxies.
		Expect(ep1.Spec.Logging.Level).To(Equal(envoyProxy1.Spec.Logging.Level))

		Expect(ep2.Spec.Provider.Kubernetes.EnvoyDaemonSet).NotTo(BeNil())
		Expect(ep2.Spec.Provider.Kubernetes.EnvoyDeployment).To(BeNil())
		Expect(ep2.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.NodeSelector).To(Equal(envoyProxy2.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.NodeSelector))
		Expect(ep2.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.TopologySpreadConstraints).To(Equal(topologySpreadConstraints))

		// Check customizations from class-specific customization structs.
		Expect(ep1.Spec.Provider.Kubernetes.EnvoyService.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-type", "external"))
		Expect(ep1.Spec.Provider.Kubernetes.EnvoyService.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-nlb-target-type", "instance"))
		Expect(ep1.Spec.Provider.Kubernetes.EnvoyService.Annotations).To(HaveKeyWithValue("service.beta.kubernetes.io/aws-load-balancer-scheme", "internet-facing"))

		Expect(ep3.Spec.Provider.Kubernetes.EnvoyDeployment).NotTo(BeNil())
		Expect(*ep3.Spec.Provider.Kubernetes.EnvoyDeployment.Replicas).To(Equal(*gatewayAPI.Spec.GatewayClasses[2].GatewayDeployment.Spec.Replicas))
		Expect(ep3.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Labels).To(HaveKeyWithValue("envoy-proxy", "standard"))
		Expect(ep3.Spec.Provider.Kubernetes.EnvoyDeployment.Container.Resources).To(Equal(resourceRequirements))
		Expect(ep3.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.NodeSelector).To(HaveKeyWithValue("east", "west"))
		Expect(*ep3.Spec.Provider.Kubernetes.EnvoyService.LoadBalancerClass).To(Equal(lbClass))
		Expect(ep3.Spec.Provider.Kubernetes.EnvoyService.LoadBalancerSourceRanges).To(ConsistOf("182.98.44.55/24"))
		Expect(*ep3.Spec.Provider.Kubernetes.EnvoyService.LoadBalancerIP).To(Equal(lbIP))

		Expect(ep4.Spec.Provider.Kubernetes.EnvoyDeployment).To(BeNil())
		Expect(ep4.Spec.Provider.Kubernetes.EnvoyDaemonSet).NotTo(BeNil())
		Expect(ep4.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.Labels).To(HaveKeyWithValue("envoy-proxy", "standard"))
		Expect(ep4.Spec.Provider.Kubernetes.EnvoyDaemonSet.Container.Resources).To(Equal(resourceRequirements))
		Expect(ep4.Spec.Provider.Kubernetes.EnvoyDaemonSet.Pod.NodeSelector).To(HaveKeyWithValue("east", "west"))
		Expect(*ep4.Spec.Provider.Kubernetes.EnvoyService.LoadBalancerClass).To(Equal(lbClass))
		Expect(ep4.Spec.Provider.Kubernetes.EnvoyService.LoadBalancerSourceRanges).To(ConsistOf("182.98.44.55/24"))
		Expect(*ep4.Spec.Provider.Kubernetes.EnvoyService.LoadBalancerIP).To(Equal(lbIP))
	})

	It("should not deploy waf-http-filter for open-source", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.Calico,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
			},
		}
		gatewayComp := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Installation: installation,
			GatewayAPI:   gatewayAPI,
		})

		objsToCreate, _ := gatewayComp.Objects()
		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, "tigera-gateway-class", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		envoyDeployment := proxy.Spec.Provider.Kubernetes.EnvoyDeployment
		Expect(envoyDeployment).ToNot(BeNil())
		Expect(envoyDeployment.InitContainers).To(BeNil())
		Expect(envoyDeployment.Container).ToNot(BeNil())
		Expect(envoyDeployment.Container.VolumeMounts).To(BeNil())
	})

	It("should deploy waf-http-filter for Enterprise", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.TigeraSecureEnterprise,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
			},
		}
		gatewayComp := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Installation: installation,
			GatewayAPI:   gatewayAPI,
		})

		objsToCreate, _ := gatewayComp.Objects()
		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, "tigera-gateway-class", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())

		envoyDeployment := proxy.Spec.Provider.Kubernetes.EnvoyDeployment
		Expect(envoyDeployment).ToNot(BeNil())

		Expect(envoyDeployment.Pod).ToNot(BeNil())
		Expect(envoyDeployment.Pod.Volumes).To(HaveLen(2))
		Expect(envoyDeployment.Pod.Volumes[0].Name).To(Equal("var-log-calico"))
		Expect(envoyDeployment.Pod.Volumes[0].HostPath.Path).To(Equal("/var/log/calico"))
		Expect(envoyDeployment.Pod.Volumes[1].Name).To(Equal("waf-http-filter"))
		Expect(envoyDeployment.Pod.Volumes[1].EmptyDir).ToNot(BeNil())

		Expect(envoyDeployment.InitContainers[0].Name).To(Equal("waf-http-filter"))
		Expect(*envoyDeployment.InitContainers[0].RestartPolicy).To(Equal(corev1.ContainerRestartPolicyAlways))
		Expect(envoyDeployment.InitContainers[0].VolumeMounts).To(HaveLen(2))
		Expect(envoyDeployment.InitContainers[0].VolumeMounts).To(ContainElements([]corev1.VolumeMount{
			{
				Name:      "waf-http-filter",
				MountPath: "/var/run/waf-http-filter",
			},
			{
				Name:      "var-log-calico",
				MountPath: "/var/log/calico",
			},
		}))

		Expect(envoyDeployment.Container).ToNot(BeNil())
		Expect(envoyDeployment.Container.VolumeMounts).To(HaveLen(1))
		Expect(envoyDeployment.Container.VolumeMounts).To(ContainElement(corev1.VolumeMount{
			Name:      "waf-http-filter",
			MountPath: "/var/run/waf-http-filter",
		}))

		// logger gateway name and namespace are set from the k8s downward api pod metadata.
		Expect(envoyDeployment.Container.Env).To(ContainElement(corev1.EnvVar{
			Name: "LOGGER_GATEWAY_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.name",
				},
			},
		}))
		Expect(envoyDeployment.Container.Env).To(ContainElement(corev1.EnvVar{
			Name: "LOGGER_GATEWAY_NAMESPACE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.namespace",
				},
			},
		}))

	})

	It("should deploy waf-http-filter for Enterprise when using a custom proxy", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.TigeraSecureEnterprise,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{
					Name: "custom-class",
					EnvoyProxyRef: &operatorv1.NamespacedName{
						Namespace: "default",
						Name:      "my-proxy",
					},
				}},
			},
		}
		envoyProxy := &envoyapi.EnvoyProxy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "EnvoyProxy",
				APIVersion: "gateway.envoyproxy.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-proxy",
				Namespace: "default",
			},
			Spec: envoyapi.EnvoyProxySpec{
				Provider: &envoyapi.EnvoyProxyProvider{
					Type: envoyapi.ProviderTypeKubernetes,
					Kubernetes: &envoyapi.EnvoyProxyKubernetesProvider{
						EnvoyDeployment: &envoyapi.KubernetesDeploymentSpec{
							InitContainers: []corev1.Container{
								{
									Name:          "some-other-sidecar",
									RestartPolicy: ptr.ToPtr[corev1.ContainerRestartPolicy](corev1.ContainerRestartPolicyAlways),
									VolumeMounts: []corev1.VolumeMount{
										{
											Name:      "some-other-volume",
											MountPath: "/test",
										},
									},
								},
							},
							Container: &envoyapi.KubernetesContainerSpec{
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "some-other-volume",
										MountPath: "/test",
									},
								},
							},
							Pod: &envoyapi.KubernetesPodSpec{
								Volumes: []corev1.Volume{
									{
										Name: "some-other-volume",
										VolumeSource: corev1.VolumeSource{
											EmptyDir: &corev1.EmptyDirVolumeSource{},
										},
									},
								},
							},
						},
					},
				},
			},
		}
		gatewayComp := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Installation: installation,
			GatewayAPI:   gatewayAPI,
			CustomEnvoyProxies: map[string]*envoyapi.EnvoyProxy{
				"custom-class": envoyProxy,
			},
		})

		objsToCreate, _ := gatewayComp.Objects()

		// Get the four expected GatewayClasses.
		gc, err := rtest.GetResourceOfType[*gapi.GatewayClass](objsToCreate, "custom-class", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())

		// Get their four EnvoyProxies.
		Expect(gc.Spec.ParametersRef).NotTo(BeNil())
		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, gc.Spec.ParametersRef.Name, string(*gc.Spec.ParametersRef.Namespace))
		Expect(err).NotTo(HaveOccurred())

		envoyDeployment := proxy.Spec.Provider.Kubernetes.EnvoyDeployment
		Expect(envoyDeployment).ToNot(BeNil())

		Expect(envoyDeployment.InitContainers).To(HaveLen(2))
		Expect(envoyDeployment.InitContainers[0].Name).To(Equal("some-other-sidecar"))
		Expect(envoyDeployment.InitContainers[1].Name).To(Equal("waf-http-filter"))
		Expect(*envoyDeployment.InitContainers[1].RestartPolicy).To(Equal(corev1.ContainerRestartPolicyAlways))
		Expect(envoyDeployment.InitContainers[1].VolumeMounts).To(HaveLen(2))
		Expect(envoyDeployment.InitContainers[1].VolumeMounts).To(ContainElements([]corev1.VolumeMount{
			{
				Name:      "waf-http-filter",
				MountPath: "/var/run/waf-http-filter",
			},
			{
				Name:      "var-log-calico",
				MountPath: "/var/log/calico",
			},
		}))

		Expect(envoyDeployment.Container).ToNot(BeNil())
		Expect(envoyDeployment.Container.VolumeMounts).To(ContainElements(
			corev1.VolumeMount{
				Name:      "some-other-volume",
				MountPath: "/test",
			}, corev1.VolumeMount{
				Name:      "waf-http-filter",
				MountPath: "/var/run/waf-http-filter",
			},
		))

		Expect(envoyDeployment.Pod).ToNot(BeNil())
		Expect(envoyDeployment.Pod.Volumes).To(HaveLen(3))
		Expect(envoyDeployment.Pod.Volumes[0].Name).To(Equal("some-other-volume"))
		Expect(envoyDeployment.Pod.Volumes[0].EmptyDir).ToNot(BeNil())
		Expect(envoyDeployment.Pod.Volumes[1].Name).To(Equal("var-log-calico"))
		Expect(envoyDeployment.Pod.Volumes[1].HostPath.Path).To(Equal("/var/log/calico"))
		Expect(envoyDeployment.Pod.Volumes[2].Name).To(Equal("waf-http-filter"))
		Expect(envoyDeployment.Pod.Volumes[2].EmptyDir).ToNot(BeNil())

	})

})
