// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package gatewayapi

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"k8s.io/utils/set"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gapi "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"
)

type matchObject struct {
	name string
}

func (m *matchObject) Match(actual any) (success bool, err error) {
	return actual.(client.Object).GetName() == m.name, nil
}

func (m *matchObject) FailureMessage(actual any) (message string) {
	return "" // not used within ContainElement
}

func (m *matchObject) NegatedFailureMessage(actual any) (message string) {
	return "" // not used within ContainElement
}

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	Expect(scheme.AddToScheme(s)).ShouldNot(HaveOccurred())
	Expect(apiextenv1.AddToScheme(s)).ShouldNot(HaveOccurred())
	Expect(admissionregv1.AddToScheme(s)).ShouldNot(HaveOccurred())
	return s
}

var _ = Describe("Gateway API rendering tests", func() {
	AccessLogSettings := []envoyapi.ProxyAccessLogSetting{
		{
			Sinks: []envoyapi.ProxyAccessLogSink{
				{
					Type: envoyapi.ProxyAccessLogSinkTypeFile,
					File: &envoyapi.FileEnvoyProxyAccessLog{
						Path: "/access_logs/access.log",
					},
				},
			},
			Format: &envoyapi.ProxyAccessLogFormat{
				Type: ptr.To(envoyapi.ProxyAccessLogFormatTypeJSON),
				JSON: map[string]string{
					"reporter":                         "gateway",
					"start_time":                       "%START_TIME%",
					"duration":                         "%DURATION%",
					"response_code":                    "%RESPONSE_CODE%",
					"bytes_sent":                       "%BYTES_SENT%",
					"bytes_received":                   "%BYTES_RECEIVED%",
					"user_agent":                       "%REQ(USER-AGENT)%",
					"request_path":                     "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%",
					"request_method":                   "%REQ(:METHOD)%",
					"request_id":                       "%REQ(X-REQUEST-ID)%",
					"type":                             "{{.}}",
					"downstream_remote_address":        "%DOWNSTREAM_REMOTE_ADDRESS%",
					"downstream_local_address":         "%DOWNSTREAM_LOCAL_ADDRESS%",
					"downstream_direct_remote_address": "%DOWNSTREAM_DIRECT_REMOTE_ADDRESS%",
					"domain":                           "%REQ(HOST?:AUTHORITY)%",
					"upstream_host":                    "%UPSTREAM_HOST%",
					"upstream_local_address":           "%UPSTREAM_LOCAL_ADDRESS%",
					"upstream_service_time":            "%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%",
					"route_name":                       "%ROUTE_NAME%",
				},
			},
			Type: &AccessLogType,
		},
	}

	It("should render Gateway API resources from helm chart", func() {
		s := testScheme()
		resources, err := renderChart(s, "")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(resources.controllerDeployment).NotTo(BeNil())
		Expect(resources.controllerDeployment.Namespace).To(Equal(ControllerModeNamespace))
	})

	It("should report UDPRoute as required when platform is not OpenShift", func() {
		s := testScheme()
		essentialCRDs, optionalCRDs, err := GatewayAPICRDs(operatorv1.ProviderAKS, s)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(essentialCRDs).To(ContainElement(&matchObject{name: "udproutes.gateway.networking.k8s.io"}))
		Expect(optionalCRDs).NotTo(ContainElement(&matchObject{name: "udproutes.gateway.networking.k8s.io"}))
	})

	It("should report UDPRoute as optional when platform is OpenShift", func() {
		s := testScheme()
		essentialCRDs, optionalCRDs, err := GatewayAPICRDs(operatorv1.ProviderOpenShift, s)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(essentialCRDs).NotTo(ContainElement(&matchObject{name: "udproutes.gateway.networking.k8s.io"}))
		Expect(optionalCRDs).To(ContainElement(&matchObject{name: "udproutes.gateway.networking.k8s.io"}))
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
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: installation,
			GatewayAPI:   gatewayAPI,
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())
		By("resolving images")
		objsToCreate, objsToDelete := gatewayComp.Objects()
		// 2 GatewayNamespace-only CRs + 2 opposite-mode certgen CR/CRB + 2 deprecated waf-http-filter CR/CRB.
		Expect(objsToDelete).To(HaveLen(6))
		Expect(objsToCreate).NotTo(BeEmpty())
		Expect(objsToCreate).To(HaveLen(23 + len(gatewayAPI.Spec.GatewayClasses))) // 23 core objects plus one per GatewayClass

		rtest.ExpectResources(objsToCreate, []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator-secrets", Namespace: "tigera-gateway"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: "tigera-gateway"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway-config", Namespace: "tigera-gateway"}},
			&admissionregv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway-topology-injector.tigera-gateway"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-envoy-gateway-role"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen:tigera-gateway"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-envoy-gateway-rolebinding"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen:tigera-gateway"}},
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
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.default-deny", Namespace: "tigera-gateway"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: ControllerPolicyName, Namespace: "tigera-gateway"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: GatewayAPIProxyPolicyName, Namespace: "tigera-gateway"}},
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
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: installation,
			GatewayAPI:   gatewayAPI,
			PullSecrets:  pullSecrets,
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		Expect(gatewayComp.ResolveImages(nil)).NotTo(HaveOccurred())
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyGatewayImage).To(Equal("myregistry.io/calico/envoy-gateway:" + components.ComponentCalicoEnvoyGateway.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyRatelimitImage).To(Equal("myregistry.io/calico/envoy-ratelimit:" + components.ComponentCalicoEnvoyRatelimit.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyProxyImage).To(Equal("myregistry.io/calico/envoy-proxy:" + components.ComponentCalicoEnvoyProxy.Version))

		objsToCreate, objsToDelete := gatewayComp.Objects()
		// 2 GatewayNamespace-only CRs + 2 opposite-mode certgen CR/CRB + 2 deprecated waf-http-filter CR/CRB.
		Expect(objsToDelete).To(HaveLen(6))
		rtest.ExpectResources(objsToCreate, []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator-secrets", Namespace: "tigera-gateway"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: "tigera-gateway"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway-config", Namespace: "tigera-gateway"}},
			&admissionregv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway-topology-injector.tigera-gateway"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-envoy-gateway-role"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen:tigera-gateway"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-envoy-gateway-rolebinding"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen:tigera-gateway"}},
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
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.default-deny", Namespace: "tigera-gateway"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: ControllerPolicyName, Namespace: "tigera-gateway"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: GatewayAPIProxyPolicyName, Namespace: "tigera-gateway"}},
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
			Variant:          operatorv1.CalicoEnterprise,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
			},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: installation,
			GatewayAPI:   gatewayAPI,
			PullSecrets:  pullSecrets,
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		Expect(gatewayComp.ResolveImages(nil)).NotTo(HaveOccurred())
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyGatewayImage).To(Equal("myregistry.io/tigera/envoy-gateway:" + components.ComponentGatewayAPIEnvoyGateway.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyRatelimitImage).To(Equal("myregistry.io/tigera/envoy-ratelimit:" + components.ComponentGatewayAPIEnvoyRatelimit.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyProxyImage).To(Equal("myregistry.io/tigera/envoy-proxy:" + components.ComponentGatewayAPIEnvoyProxy.Version))

		objsToCreate, objsToDelete := gatewayComp.Objects()
		// 2 GatewayNamespace-only CRs + 2 opposite-mode certgen CR/CRB + 2 deprecated waf-http-filter CR/CRB.
		Expect(objsToDelete).To(HaveLen(6))
		rtest.ExpectResources(objsToCreate, []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator-secrets", Namespace: "tigera-gateway"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: "tigera-gateway"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway-config", Namespace: "tigera-gateway"}},
			&admissionregv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway-topology-injector.tigera-gateway"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-envoy-gateway-role"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen:tigera-gateway"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-envoy-gateway-rolebinding"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen:tigera-gateway"}},
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
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "waf-http-filter", Namespace: "tigera-gateway"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "waf-http-filter-cluster-scoped"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "waf-http-filter-gateway-resources"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "waf-http-filter-cluster-scoped"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "waf-http-filter-gateway-resources"}},
			&envoyapi.EnvoyProxy{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-class", Namespace: "tigera-gateway"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret1", Namespace: "tigera-gateway"}},
			&gapi.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-class", Namespace: "tigera-gateway"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "calico-system.default-deny", Namespace: "tigera-gateway"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: ControllerPolicyName, Namespace: "tigera-gateway"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: GatewayAPIProxyPolicyName, Namespace: "tigera-gateway"}},
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
			Variant:  operatorv1.CalicoEnterprise,
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
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
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
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		Expect(gatewayComp.ResolveImages(nil)).NotTo(HaveOccurred())
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyGatewayImage).To(Equal("myregistry.io/tigera/envoy-gateway:" + components.ComponentGatewayAPIEnvoyGateway.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyRatelimitImage).To(Equal("myregistry.io/tigera/envoy-ratelimit:" + components.ComponentGatewayAPIEnvoyRatelimit.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyProxyImage).To(Equal("myregistry.io/tigera/envoy-proxy:" + components.ComponentGatewayAPIEnvoyProxy.Version))

		objsToCreate, objsToDelete := gatewayComp.Objects()
		// 2 GatewayNamespace-only CRs + 2 opposite-mode certgen CR/CRB + 2 deprecated waf-http-filter CR/CRB.
		Expect(objsToDelete).To(HaveLen(6))

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
			Variant:  operatorv1.CalicoEnterprise,
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
					Type: envoyapi.EnvoyProxyProviderTypeKubernetes,
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

		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: installation,
			GatewayAPI:   gatewayAPI,
			CustomEnvoyProxies: map[string]*envoyapi.EnvoyProxy{
				"custom-class-1": envoyProxy1,
				"custom-class-2": envoyProxy2,
			},
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		Expect(gatewayComp.ResolveImages(nil)).NotTo(HaveOccurred())
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyGatewayImage).To(Equal("myregistry.io/tigera/envoy-gateway:" + components.ComponentGatewayAPIEnvoyGateway.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyRatelimitImage).To(Equal("myregistry.io/tigera/envoy-ratelimit:" + components.ComponentGatewayAPIEnvoyRatelimit.Version))
		Expect(gatewayComp.(*gatewayAPIImplementationComponent).envoyProxyImage).To(Equal("myregistry.io/tigera/envoy-proxy:" + components.ComponentGatewayAPIEnvoyProxy.Version))

		objsToCreate, objsToDelete := gatewayComp.Objects()
		// 2 GatewayNamespace-only CRs + 2 opposite-mode certgen CR/CRB + 2 deprecated waf-http-filter CR/CRB.
		Expect(objsToDelete).To(HaveLen(6))

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

	It("should not deploy waf-http-filter or l7-log-collector for open-source", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.Calico,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
			},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: installation,
			GatewayAPI:   gatewayAPI,
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

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
			Variant: operatorv1.CalicoEnterprise,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
			},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: installation,
			GatewayAPI:   gatewayAPI,
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		objsToCreate, _ := gatewayComp.Objects()
		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, "tigera-gateway-class", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())

		envoyDeployment := proxy.Spec.Provider.Kubernetes.EnvoyDeployment
		Expect(envoyDeployment).ToNot(BeNil())

		Expect(envoyDeployment.Pod).ToNot(BeNil())
		Expect(envoyDeployment.Pod.Volumes).To(HaveLen(4))
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

		Expect(envoyDeployment.InitContainers[1].Name).To(Equal("l7-log-collector"))
		Expect(*envoyDeployment.InitContainers[1].RestartPolicy).To(Equal(corev1.ContainerRestartPolicyAlways))
		Expect(envoyDeployment.InitContainers[1].VolumeMounts).To(HaveLen(2))
		Expect(envoyDeployment.InitContainers[1].VolumeMounts).To(ContainElements([]corev1.VolumeMount{
			{
				Name:      "access-logs",
				MountPath: "/access_logs",
			},
			{
				Name:      "felix-sync",
				MountPath: "/var/run/felix",
			},
		}))

		// logger gateway name and namespace are set from the k8s downward api pod metadata.
		Expect(envoyDeployment.InitContainers[0].Env).To(ContainElements(GatewayNameEnvVar, GatewayNamespaceEnvVar))

		Expect(envoyDeployment.Container).ToNot(BeNil())
		Expect(envoyDeployment.Container.VolumeMounts).To(HaveLen(2))
		Expect(envoyDeployment.Container.VolumeMounts).To(ContainElement(corev1.VolumeMount{
			Name:      "waf-http-filter",
			MountPath: "/var/run/waf-http-filter",
		}))
		Expect(envoyDeployment.Container.VolumeMounts).To(ContainElement(corev1.VolumeMount{
			Name:      "access-logs",
			MountPath: "/access_logs",
		}))

		Expect(proxy.Spec.Telemetry.AccessLog.Settings).To(Equal(AccessLogSettings))
	})

	It("should deploy waf-http-filter for Enterprise when using a custom proxy", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.CalicoEnterprise,
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
					Type: envoyapi.EnvoyProxyProviderTypeKubernetes,
					Kubernetes: &envoyapi.EnvoyProxyKubernetesProvider{
						EnvoyDeployment: &envoyapi.KubernetesDeploymentSpec{
							InitContainers: []corev1.Container{
								{
									Name:          "some-other-sidecar",
									RestartPolicy: ptr.To(corev1.ContainerRestartPolicyAlways),
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
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: installation,
			GatewayAPI:   gatewayAPI,
			CustomEnvoyProxies: map[string]*envoyapi.EnvoyProxy{
				"custom-class": envoyProxy,
			},
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

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

		Expect(envoyDeployment.InitContainers).To(HaveLen(3))
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

		Expect(envoyDeployment.InitContainers[2].Name).To(Equal("l7-log-collector"))
		Expect(*envoyDeployment.InitContainers[2].RestartPolicy).To(Equal(corev1.ContainerRestartPolicyAlways))
		Expect(envoyDeployment.InitContainers[2].VolumeMounts).To(HaveLen(2))
		Expect(envoyDeployment.InitContainers[2].VolumeMounts).To(ContainElements([]corev1.VolumeMount{
			{
				Name:      "access-logs",
				MountPath: "/access_logs",
			},
			{
				Name:      "felix-sync",
				MountPath: "/var/run/felix",
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
			}, corev1.VolumeMount{
				Name:      "access-logs",
				MountPath: "/access_logs",
			},
		))

		Expect(envoyDeployment.Pod).ToNot(BeNil())
		Expect(envoyDeployment.Pod.Volumes).To(HaveLen(5))
		Expect(envoyDeployment.Pod.Volumes[0].Name).To(Equal("some-other-volume"))
		Expect(envoyDeployment.Pod.Volumes[0].EmptyDir).ToNot(BeNil())
		Expect(envoyDeployment.Pod.Volumes[1].Name).To(Equal("var-log-calico"))
		Expect(envoyDeployment.Pod.Volumes[1].HostPath.Path).To(Equal("/var/log/calico"))
		Expect(envoyDeployment.Pod.Volumes[2].Name).To(Equal("waf-http-filter"))
		Expect(envoyDeployment.Pod.Volumes[2].EmptyDir).ToNot(BeNil())
		Expect(envoyDeployment.Pod.Volumes[3].Name).To(Equal("access-logs"))
		Expect(envoyDeployment.Pod.Volumes[3].EmptyDir).ToNot(BeNil())
		Expect(envoyDeployment.Pod.Volumes[4].Name).To(Equal("felix-sync"))
		Expect(envoyDeployment.Pod.Volumes[4].CSI.Driver).To(Equal("csi.tigera.io"))
		Expect(proxy.Spec.Telemetry.AccessLog.Settings).To(Equal(AccessLogSettings))
	})

	It("should set owning gateway environment variables in l7-log-collector for Enterprise", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.CalicoEnterprise,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
			},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: installation,
			GatewayAPI:   gatewayAPI,
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		objsToCreate, _ := gatewayComp.Objects()
		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, "tigera-gateway-class", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())

		envoyDeployment := proxy.Spec.Provider.Kubernetes.EnvoyDeployment
		Expect(envoyDeployment).ToNot(BeNil())
		Expect(envoyDeployment.InitContainers).To(HaveLen(2))

		// Find the l7-log-collector init container
		var l7LogCollector *corev1.Container
		for i := range envoyDeployment.InitContainers {
			if envoyDeployment.InitContainers[i].Name == "l7-log-collector" {
				l7LogCollector = &envoyDeployment.InitContainers[i]
				break
			}
		}

		Expect(l7LogCollector).ToNot(BeNil(), "l7-log-collector container should exist")

		// Verify the owning gateway environment variables are present
		Expect(l7LogCollector.Env).To(ContainElement(OwningGatewayNameEnvVar))
		Expect(l7LogCollector.Env).To(ContainElement(OwningGatewayNamespaceEnvVar))

		// Verify the structure of the environment variables
		var foundNameEnvVar, foundNamespaceEnvVar bool
		for _, env := range l7LogCollector.Env {
			if env.Name == "OWNING_GATEWAY_NAME" {
				foundNameEnvVar = true
				Expect(env.ValueFrom).ToNot(BeNil())
				Expect(env.ValueFrom.FieldRef).ToNot(BeNil())
				Expect(env.ValueFrom.FieldRef.FieldPath).To(Equal("metadata.labels['gateway.envoyproxy.io/owning-gateway-name']"))
			}
			if env.Name == "OWNING_GATEWAY_NAMESPACE" {
				foundNamespaceEnvVar = true
				Expect(env.ValueFrom).ToNot(BeNil())
				Expect(env.ValueFrom.FieldRef).ToNot(BeNil())
				Expect(env.ValueFrom.FieldRef.FieldPath).To(Equal("metadata.labels['gateway.envoyproxy.io/owning-gateway-namespace']"))
			}
		}
		Expect(foundNameEnvVar).To(BeTrue(), "OWNING_GATEWAY_NAME environment variable should be set")
		Expect(foundNamespaceEnvVar).To(BeTrue(), "OWNING_GATEWAY_NAMESPACE environment variable should be set")
	})

	It("should set owning gateway environment variables in l7-log-collector when using custom proxy", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.CalicoEnterprise,
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
					Type: envoyapi.EnvoyProxyProviderTypeKubernetes,
					Kubernetes: &envoyapi.EnvoyProxyKubernetesProvider{
						EnvoyDeployment: &envoyapi.KubernetesDeploymentSpec{
							InitContainers: []corev1.Container{
								{
									Name:          "some-other-sidecar",
									RestartPolicy: ptr.To(corev1.ContainerRestartPolicyAlways),
									Env: []corev1.EnvVar{
										{
											Name:  "OTHER_VAR",
											Value: "other-value",
										},
									},
								},
							},
						},
					},
				},
			},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: installation,
			GatewayAPI:   gatewayAPI,
			CustomEnvoyProxies: map[string]*envoyapi.EnvoyProxy{
				"custom-class": envoyProxy,
			},
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		objsToCreate, _ := gatewayComp.Objects()

		gc, err := rtest.GetResourceOfType[*gapi.GatewayClass](objsToCreate, "custom-class", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())

		Expect(gc.Spec.ParametersRef).NotTo(BeNil())
		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, gc.Spec.ParametersRef.Name, string(*gc.Spec.ParametersRef.Namespace))
		Expect(err).NotTo(HaveOccurred())

		envoyDeployment := proxy.Spec.Provider.Kubernetes.EnvoyDeployment
		Expect(envoyDeployment).ToNot(BeNil())

		// Find the l7-log-collector init container
		var l7LogCollector *corev1.Container
		for i := range envoyDeployment.InitContainers {
			if envoyDeployment.InitContainers[i].Name == "l7-log-collector" {
				l7LogCollector = &envoyDeployment.InitContainers[i]
				break
			}
		}

		Expect(l7LogCollector).ToNot(BeNil(), "l7-log-collector container should exist")

		// Verify the owning gateway environment variables are present
		Expect(l7LogCollector.Env).To(ContainElement(OwningGatewayNameEnvVar))
		Expect(l7LogCollector.Env).To(ContainElement(OwningGatewayNamespaceEnvVar))

		// Verify environment variables include all expected values
		envVarNames := make([]string, len(l7LogCollector.Env))
		for i, env := range l7LogCollector.Env {
			envVarNames[i] = env.Name
		}
		Expect(envVarNames).To(ContainElement("LOG_LEVEL"))
		Expect(envVarNames).To(ContainElement("FELIX_DIAL_TARGET"))
		Expect(envVarNames).To(ContainElement("ENVOY_ACCESS_LOG_PATH"))
		Expect(envVarNames).To(ContainElement("OWNING_GATEWAY_NAME"))
		Expect(envVarNames).To(ContainElement("OWNING_GATEWAY_NAMESPACE"))
	})

	It("should verify owning gateway env vars use correct field paths", func() {
		// Test the global env var definitions
		Expect(OwningGatewayNameEnvVar.Name).To(Equal("OWNING_GATEWAY_NAME"))
		Expect(OwningGatewayNameEnvVar.ValueFrom).ToNot(BeNil())
		Expect(OwningGatewayNameEnvVar.ValueFrom.FieldRef).ToNot(BeNil())
		Expect(OwningGatewayNameEnvVar.ValueFrom.FieldRef.FieldPath).To(Equal("metadata.labels['gateway.envoyproxy.io/owning-gateway-name']"))

		Expect(OwningGatewayNamespaceEnvVar.Name).To(Equal("OWNING_GATEWAY_NAMESPACE"))
		Expect(OwningGatewayNamespaceEnvVar.ValueFrom).ToNot(BeNil())
		Expect(OwningGatewayNamespaceEnvVar.ValueFrom.FieldRef).ToNot(BeNil())
		Expect(OwningGatewayNamespaceEnvVar.ValueFrom.FieldRef.FieldPath).To(Equal("metadata.labels['gateway.envoyproxy.io/owning-gateway-namespace']"))
	})

	It("should not set owning gateway env vars in l7-log-collector for DaemonSet deployments", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.CalicoEnterprise,
		}
		daemonSet := operatorv1.GatewayKindDaemonSet
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{
					Name:        "tigera-gateway-class-daemonset",
					GatewayKind: &daemonSet,
				}},
			},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: installation,
			GatewayAPI:   gatewayAPI,
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		objsToCreate, _ := gatewayComp.Objects()
		proxy, err := rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, "tigera-gateway-class-daemonset", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())

		// DaemonSet should not have l7-log-collector or waf-http-filter
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDaemonSet).ToNot(BeNil())
		Expect(proxy.Spec.Provider.Kubernetes.EnvoyDeployment).To(BeNil())
		// DaemonSet init containers are not supported, so these should not be present
		// This is expected behavior as mentioned in the code comments
	})

	It("should create correct RBAC for L7 log collector enrichment", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.CalicoEnterprise,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
			},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: installation,
			GatewayAPI:   gatewayAPI,
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		objsToCreate, _ := gatewayComp.Objects()

		// Verify cluster-scoped ClusterRole exists with license key + token review rules.
		csRole, err := rtest.GetResourceOfType[*rbacv1.ClusterRole](objsToCreate, "waf-http-filter-cluster-scoped", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(csRole.Rules).To(HaveLen(2))
		Expect(csRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{"licensekeys"},
			Verbs:     []string{"get", "watch"},
		}))
		Expect(csRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"authentication.k8s.io"},
			Resources: []string{"tokenreviews"},
			Verbs:     []string{"create"},
		}))

		// Verify gateway-resources ClusterRole exists with route rules only.
		grRole, err := rtest.GetResourceOfType[*rbacv1.ClusterRole](objsToCreate, "waf-http-filter-gateway-resources", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(grRole.Rules).To(HaveLen(1))
		Expect(grRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"gateway.networking.k8s.io"},
			Resources: []string{"gateways", "httproutes", "grpcroutes"},
			Verbs:     []string{"get", "list", "watch"},
		}))

		// Verify both ClusterRoleBindings exist (controller-namespace SA bound to both roles cluster-wide).
		csCRB, err := rtest.GetResourceOfType[*rbacv1.ClusterRoleBinding](objsToCreate, "waf-http-filter-cluster-scoped", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(csCRB.RoleRef.Name).To(Equal("waf-http-filter-cluster-scoped"))
		Expect(csCRB.Subjects[0].Namespace).To(Equal("tigera-gateway"))

		grCRB, err := rtest.GetResourceOfType[*rbacv1.ClusterRoleBinding](objsToCreate, "waf-http-filter-gateway-resources", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(grCRB.RoleRef.Name).To(Equal("waf-http-filter-gateway-resources"))
		Expect(grCRB.Subjects[0].Namespace).To(Equal("tigera-gateway"))

		// Verify ServiceAccount exists
		serviceAccount, err := rtest.GetResourceOfType[*corev1.ServiceAccount](objsToCreate, "waf-http-filter", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		Expect(serviceAccount.Name).To(Equal("waf-http-filter"))
		Expect(serviceAccount.Namespace).To(Equal("tigera-gateway"))
	})

	It("should create per-namespace resources for GatewayNamespace mode (Enterprise)", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.CalicoEnterprise,
		}
		pullSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: "tigera-operator"},
			Data:       map[string][]byte{".dockerconfigjson": []byte("{}")},
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses:        []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
				GatewayDeploymentMode: ptr.To(operatorv1.GatewayDeploymentModeGatewayNamespace),
			},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:            testScheme(),
			Installation:      installation,
			GatewayAPI:        gatewayAPI,
			PullSecrets:       []*corev1.Secret{pullSecret},
			GatewayNamespaces: []string{"default", "app-ns"},
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		objsToCreate, _ := gatewayComp.Objects()

		// Verify per-namespace ServiceAccounts.
		sa1, err := rtest.GetResourceOfType[*corev1.ServiceAccount](objsToCreate, "waf-http-filter", "default")
		Expect(err).NotTo(HaveOccurred())
		Expect(sa1.Namespace).To(Equal("default"))

		sa2, err := rtest.GetResourceOfType[*corev1.ServiceAccount](objsToCreate, "waf-http-filter", "app-ns")
		Expect(err).NotTo(HaveOccurred())
		Expect(sa2.Namespace).To(Equal("app-ns"))

		// Verify a single shared ClusterRoleBinding (cluster-scoped role) with one Subject per namespace.
		crb, err := rtest.GetResourceOfType[*rbacv1.ClusterRoleBinding](objsToCreate, GatewayNamespacesCRBName, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(crb.RoleRef.Name).To(Equal("waf-http-filter-cluster-scoped"))
		Expect(crb.Subjects).To(HaveLen(2))
		nsSubjects := []string{crb.Subjects[0].Namespace, crb.Subjects[1].Namespace}
		Expect(nsSubjects).To(ConsistOf("default", "app-ns"))

		// Verify per-namespace RoleBindings for gateway resources scoped to that namespace.
		rb1, err := rtest.GetResourceOfType[*rbacv1.RoleBinding](objsToCreate, "waf-http-filter-gateway-resources", "default")
		Expect(err).NotTo(HaveOccurred())
		Expect(rb1.RoleRef.Name).To(Equal("waf-http-filter-gateway-resources"))
		Expect(rb1.Subjects).To(HaveLen(1))
		Expect(rb1.Subjects[0].Namespace).To(Equal("default"))

		rb2, err := rtest.GetResourceOfType[*rbacv1.RoleBinding](objsToCreate, "waf-http-filter-gateway-resources", "app-ns")
		Expect(err).NotTo(HaveOccurred())
		Expect(rb2.Subjects[0].Namespace).To(Equal("app-ns"))

		// Verify pull secrets copied to each namespace.
		_, err = rtest.GetResourceOfType[*corev1.Secret](objsToCreate, "tigera-pull-secret", "default")
		Expect(err).NotTo(HaveOccurred())
		_, err = rtest.GetResourceOfType[*corev1.Secret](objsToCreate, "tigera-pull-secret", "app-ns")
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not create per-namespace resources for ControllerNamespace mode (Enterprise)", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.CalicoEnterprise,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
			},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: installation,
			GatewayAPI:   gatewayAPI,
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		objsToCreate, _ := gatewayComp.Objects()

		// Should NOT have the shared per-namespace CRB.
		_, err := rtest.GetResourceOfType[*rbacv1.ClusterRoleBinding](objsToCreate, GatewayNamespacesCRBName, "")
		Expect(err).To(HaveOccurred())

		// But should still have the controller-namespace CRBs (cluster-scoped + gateway-resources).
		_, err = rtest.GetResourceOfType[*rbacv1.ClusterRoleBinding](objsToCreate, "waf-http-filter-cluster-scoped", "")
		Expect(err).NotTo(HaveOccurred())
		_, err = rtest.GetResourceOfType[*rbacv1.ClusterRoleBinding](objsToCreate, "waf-http-filter-gateway-resources", "")
		Expect(err).NotTo(HaveOccurred())
	})

	It("should deploy the controller into calico-system in GatewayNamespace mode", func() {
		installation := &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses:        []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
				GatewayDeploymentMode: ptr.To(operatorv1.GatewayDeploymentModeGatewayNamespace),
			},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: installation,
			GatewayAPI:   gatewayAPI,
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		objsToCreate, _ := gatewayComp.Objects()

		// Controller Deployment, Service, and ServiceAccount should all be in calico-system.
		_, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, "envoy-gateway", "calico-system")
		Expect(err).NotTo(HaveOccurred())
		_, err = rtest.GetResourceOfType[*corev1.Service](objsToCreate, "envoy-gateway", "calico-system")
		Expect(err).NotTo(HaveOccurred())
		_, err = rtest.GetResourceOfType[*corev1.ServiceAccount](objsToCreate, "envoy-gateway", "calico-system")
		Expect(err).NotTo(HaveOccurred())

		// EnvoyProxy co-locates with the controller.
		_, err = rtest.GetResourceOfType[*envoyapi.EnvoyProxy](objsToCreate, "tigera-gateway-class", "calico-system")
		Expect(err).NotTo(HaveOccurred())

		// calico-system is owned by the core Installation controller — we must not
		// try to (re)create the Namespace, tigera-operator-secrets RoleBinding, or
		// copy the pull secret there.
		_, err = rtest.GetResourceOfType[*corev1.Namespace](objsToCreate, "calico-system", "")
		Expect(err).To(HaveOccurred())
		_, err = rtest.GetResourceOfType[*rbacv1.RoleBinding](objsToCreate, "tigera-operator-secrets", "calico-system")
		Expect(err).To(HaveOccurred())
		_, err = rtest.GetResourceOfType[*corev1.Secret](objsToCreate, "tigera-pull-secret", "calico-system")
		Expect(err).To(HaveOccurred())

		// And nothing should land in tigera-gateway in this mode.
		for _, obj := range objsToCreate {
			Expect(obj.GetNamespace()).NotTo(Equal("tigera-gateway"),
				"unexpected resource in tigera-gateway for GatewayNamespace mode: %T %s", obj, obj.GetName())
		}

		// calico-system has a default-deny policy — the controller and its certgen
		// Job need an allow policy to reach the Kubernetes API. We must not render
		// a default-deny ourselves here: that one is owned by the core Installation.
		policy, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, ControllerPolicyName, common.CalicoNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(policy.Spec.Tier).To(Equal("calico-system"))
		Expect(policy.Spec.Selector).To(Equal("app.kubernetes.io/name == 'gateway-helm' || app == 'certgen'"))
		_, err = rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, "calico-system.default-deny", common.CalicoNamespace)
		Expect(err).To(HaveOccurred(), "must not render default-deny in calico-system")

		// Proxies live in user namespaces in GatewayNamespace mode — no proxy policy here.
		_, err = rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, GatewayAPIProxyPolicyName, common.CalicoNamespace)
		Expect(err).To(HaveOccurred())
	})

	It("should deploy the controller into tigera-gateway in ControllerNamespace mode", func() {
		installation := &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
				// GatewayDeploymentMode unset → defaults to ControllerNamespace.
			},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: installation,
			GatewayAPI:   gatewayAPI,
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		objsToCreate, _ := gatewayComp.Objects()

		_, err := rtest.GetResourceOfType[*appsv1.Deployment](objsToCreate, "envoy-gateway", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		_, err = rtest.GetResourceOfType[*corev1.Namespace](objsToCreate, "tigera-gateway", "")
		Expect(err).NotTo(HaveOccurred())

		// We own tigera-gateway: install default-deny + controller allow + proxy allow.
		_, err = rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, "calico-system.default-deny", "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		policy, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, ControllerPolicyName, "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		Expect(policy.Spec.Tier).To(Equal("calico-system"))
		proxyPolicy, err := rtest.GetResourceOfType[*v3.NetworkPolicy](objsToCreate, GatewayAPIProxyPolicyName, "tigera-gateway")
		Expect(err).NotTo(HaveOccurred())
		Expect(proxyPolicy.Spec.Selector).To(Equal("app.kubernetes.io/managed-by == 'envoy-gateway'"))
	})

	It("should not create per-namespace resources for GatewayNamespace mode (open-source)", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.Calico,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses:        []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
				GatewayDeploymentMode: ptr.To(operatorv1.GatewayDeploymentModeGatewayNamespace),
			},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:            testScheme(),
			Installation:      installation,
			GatewayAPI:        gatewayAPI,
			GatewayNamespaces: []string{"default"},
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		objsToCreate, _ := gatewayComp.Objects()

		// Open-source should NOT have the shared per-namespace CRB.
		_, err := rtest.GetResourceOfType[*rbacv1.ClusterRoleBinding](objsToCreate, GatewayNamespacesCRBName, "")
		Expect(err).To(HaveOccurred())

		// Open-source should NOT have waf-http-filter SA at all.
		_, err = rtest.GetResourceOfType[*corev1.ServiceAccount](objsToCreate, "waf-http-filter", "default")
		Expect(err).To(HaveOccurred())
	})

	It("should clean up stale per-namespace resources when Gateways are removed", func() {
		installation := &operatorv1.InstallationSpec{
			Variant: operatorv1.CalicoEnterprise,
		}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses:        []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
				GatewayDeploymentMode: ptr.To(operatorv1.GatewayDeploymentModeGatewayNamespace),
			},
		}
		pullSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: "tigera-operator"},
			Data:       map[string][]byte{".dockerconfigjson": []byte("{}")},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: installation,
			GatewayAPI:   gatewayAPI,
			PullSecrets:  []*corev1.Secret{pullSecret},
			// "default" still has a Gateway, but "removed-ns" no longer does.
			GatewayNamespaces:        []string{"default"},
			CurrentGatewayNamespaces: set.New("default", "removed-ns"),
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		objsToCreate, objsToDelete := gatewayComp.Objects()

		// "default" resources should be created.
		_, err := rtest.GetResourceOfType[*corev1.ServiceAccount](objsToCreate, "waf-http-filter", "default")
		Expect(err).NotTo(HaveOccurred())

		// Shared CRB should still be created with only the "default" subject.
		crb, err := rtest.GetResourceOfType[*rbacv1.ClusterRoleBinding](objsToCreate, GatewayNamespacesCRBName, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(crb.Subjects).To(HaveLen(1))
		Expect(crb.Subjects[0].Namespace).To(Equal("default"))

		// Verify stale "removed-ns" resources and standard cleanup are in the delete list.
		rtest.ExpectResources(objsToDelete, []client.Object{
			// Deprecated combined waf-http-filter cleanup.
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "waf-http-filter"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "waf-http-filter"}},
			// Opposite-mode certgen CR/CRB (name embeds the ControllerNamespace-mode namespace).
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen:tigera-gateway"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway-api-gateway-helm-certgen:tigera-gateway"}},
			// Stale per-namespace resources for "removed-ns".
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator-secrets", Namespace: "removed-ns"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "waf-http-filter", Namespace: "removed-ns"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "waf-http-filter-gateway-resources", Namespace: "removed-ns"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: "removed-ns"}},
		})

		// Secret must be deleted before the RoleBinding that grants us delete perms (else 403).
		secretIdx, rbIdx := -1, -1
		for i, obj := range objsToDelete {
			if obj.GetNamespace() != "removed-ns" {
				continue
			}
			switch obj.(type) {
			case *corev1.Secret:
				if obj.GetName() == "tigera-pull-secret" {
					secretIdx = i
				}
			case *rbacv1.RoleBinding:
				if obj.GetName() == "tigera-operator-secrets" {
					rbIdx = i
				}
			}
		}
		Expect(secretIdx).NotTo(Equal(-1))
		Expect(rbIdx).NotTo(Equal(-1))
		Expect(secretIdx).To(BeNumerically("<", rbIdx),
			"tigera-pull-secret must be deleted before tigera-operator-secrets RoleBinding")
	})

	It("must not create or delete core-owned shared resources in reserved namespaces", func() {
		installation := &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise}
		gatewayAPI := &operatorv1.GatewayAPI{
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses:        []operatorv1.GatewayClassSpec{{Name: "tigera-gateway-class"}},
				GatewayDeploymentMode: ptr.To(operatorv1.GatewayDeploymentModeGatewayNamespace),
			},
		}
		pullSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: "tigera-operator"},
			Data:       map[string][]byte{".dockerconfigjson": []byte("{}")},
		}
		gatewayComp, gatewayCompErr := GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:       testScheme(),
			Installation: installation,
			GatewayAPI:   gatewayAPI,
			PullSecrets:  []*corev1.Secret{pullSecret},
			// Gateways in reserved namespaces (odd but possible) plus a normal one.
			GatewayNamespaces:        []string{common.CalicoNamespace, common.OperatorNamespace(), "app-ns"},
			CurrentGatewayNamespaces: set.New(common.CalicoNamespace, common.OperatorNamespace(), "app-ns"),
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		objsToCreate, _ := gatewayComp.Objects()

		// app-ns gets the full treatment — WAF SA + both RoleBindings + pull secret.
		_, err := rtest.GetResourceOfType[*rbacv1.RoleBinding](objsToCreate, "tigera-operator-secrets", "app-ns")
		Expect(err).NotTo(HaveOccurred())
		_, err = rtest.GetResourceOfType[*corev1.Secret](objsToCreate, "tigera-pull-secret", "app-ns")
		Expect(err).NotTo(HaveOccurred())

		// Reserved namespaces get WAF-specific resources but not the shared ones.
		for _, ns := range []string{common.CalicoNamespace, common.OperatorNamespace()} {
			_, err = rtest.GetResourceOfType[*corev1.ServiceAccount](objsToCreate, "waf-http-filter", ns)
			Expect(err).NotTo(HaveOccurred(), "WAF SA should still be created in %s", ns)
			_, err = rtest.GetResourceOfType[*rbacv1.RoleBinding](objsToCreate, "waf-http-filter-gateway-resources", ns)
			Expect(err).NotTo(HaveOccurred(), "WAF gateway-resources RB should still be created in %s", ns)

			_, err = rtest.GetResourceOfType[*rbacv1.RoleBinding](objsToCreate, "tigera-operator-secrets", ns)
			Expect(err).To(HaveOccurred(), "must not create tigera-operator-secrets in reserved namespace %s", ns)
			_, err = rtest.GetResourceOfType[*corev1.Secret](objsToCreate, "tigera-pull-secret", ns)
			Expect(err).To(HaveOccurred(), "must not copy tigera-pull-secret into reserved namespace %s", ns)
		}

		// Delete path: never queue shared resources in reserved namespaces.
		gatewayComp, gatewayCompErr = GatewayAPIImplementationComponent(&GatewayAPIImplementationConfig{
			Scheme:                   testScheme(),
			Installation:             installation,
			GatewayAPI:               gatewayAPI,
			PullSecrets:              []*corev1.Secret{pullSecret},
			GatewayNamespaces:        nil,
			CurrentGatewayNamespaces: set.New(common.CalicoNamespace, common.OperatorNamespace()),
		})
		Expect(gatewayCompErr).NotTo(HaveOccurred())

		_, objsToDelete := gatewayComp.Objects()
		for _, obj := range objsToDelete {
			ns := obj.GetNamespace()
			if ns != common.CalicoNamespace && ns != common.OperatorNamespace() {
				continue
			}
			switch o := obj.(type) {
			case *rbacv1.RoleBinding:
				Expect(o.Name).NotTo(Equal("tigera-operator-secrets"),
					"must not delete tigera-operator-secrets in reserved namespace %s", ns)
			case *corev1.Secret:
				Expect(o.Name).NotTo(Equal("tigera-pull-secret"),
					"must not delete tigera-pull-secret in reserved namespace %s", ns)
			}
		}
	})
})
