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
			&envoyapi.EnvoyProxy{ObjectMeta: metav1.ObjectMeta{Name: "envoy-proxy-config", Namespace: "tigera-gateway"}},
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

		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, "envoy-proxy-config", "tigera-gateway")
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

	It("should honour private registry", func() {
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
		gatewayAPI := &operatorv1.GatewayAPI{}
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
			&envoyapi.EnvoyProxy{ObjectMeta: metav1.ObjectMeta{Name: "envoy-proxy-config", Namespace: "tigera-gateway"}},
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

		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, "envoy-proxy-config", "tigera-gateway")
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
})
