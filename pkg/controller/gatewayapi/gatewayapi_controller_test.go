// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gatewayapi

import (
	"context"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"github.com/stretchr/testify/mock"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	admregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/yaml" // gopkg.in/yaml.v2 didn't parse all the fields but this package did

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/gatewayapi"
)

var _ = Describe("Gateway API controller tests", func() {
	var c client.Client
	var ctx context.Context
	var r *ReconcileGatewayAPI
	var scheme *runtime.Scheme
	var mockStatus *status.MockStatus
	var installation *operatorv1.Installation

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(admregv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		// Create a client that will have a CRUD interface of k8s objects.
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()
		installation = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operatorv1.InstallationSpec{
				Variant:  operatorv1.TigeraSecureEnterprise,
				Registry: "some.registry.org/",
			},
			Status: operatorv1.InstallationStatus{
				Variant: operatorv1.TigeraSecureEnterprise,
				Computed: &operatorv1.InstallationSpec{
					Registry: "my-reg",
					// The test is provider agnostic.
					KubernetesProvider: operatorv1.ProviderNone,
				},
			},
		}
		mockStatus = &status.MockStatus{}
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("AddDaemonsets", mock.Anything).Return()
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("OnCRNotFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()

		fakeComponentHandlers = nil
		r = &ReconcileGatewayAPI{
			client:              c,
			scheme:              scheme,
			status:              mockStatus,
			newComponentHandler: FakeComponentHandler,
			watchEnvoyProxy:     func(namespacedName operatorv1.NamespacedName) error { return nil },
			watchEnvoyGateway:   func(namespacedName operatorv1.NamespacedName) error { return nil },
		}
	})

	Context("with real component handler", func() {
		BeforeEach(func() {
			// Use the real component handler for the following test because we want to
			// verify if an existing Gateway CRD gets left as is, or overwritten; and
			// that relies on the create-only (or not) behaviour of the real component
			// handler.  Possibly this should actually be in a UT for the component
			// handler, rather than here; but it's easier to leave this as already
			// coded, and it means we're also covering `render.GatewayAPICRDs`.
			r.newComponentHandler = utils.NewComponentHandler
		})

		DescribeTable("CRD management",
			func(gwapiMod func(*operatorv1.GatewayAPI), expectReplace bool) {
				Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

				By("installing a pre-existing Gateway CRD with an improbable version")
				crdName := "gateways.gateway.networking.k8s.io"
				existingCRD := &apiextenv1.CustomResourceDefinition{
					ObjectMeta: metav1.ObjectMeta{Name: crdName},
					Spec: apiextenv1.CustomResourceDefinitionSpec{
						Versions: []apiextenv1.CustomResourceDefinitionVersion{{
							Name: "v0123456789",
						}},
					},
				}
				Expect(c.Create(ctx, existingCRD)).NotTo(HaveOccurred())

				By("applying the GatewayAPI CR to the fake cluster")
				gwapi := &operatorv1.GatewayAPI{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
					Spec:       operatorv1.GatewayAPISpec{},
				}
				gwapiMod(gwapi)
				Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

				By("triggering a reconcile")
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				By("examining the Gateway CRD that is now present")
				gatewayCRD := &apiextenv1.CustomResourceDefinition{}
				Expect(c.Get(ctx, client.ObjectKey{Name: crdName}, gatewayCRD)).NotTo(HaveOccurred())
				if expectReplace {
					Expect(gatewayCRD.Spec.Versions).NotTo(ContainElement(MatchFields(IgnoreExtras, Fields{"Name": Equal("v0123456789")})))
				} else {
					Expect(gatewayCRD.Spec.Versions).To(ContainElement(MatchFields(IgnoreExtras, Fields{"Name": Equal("v0123456789")})))
				}

				if gwapi.Spec.CRDManagement == nil {
					By("checking that CRDManagement field has been updated to PreferExisting")
					Expect(c.Get(ctx, utils.DefaultTSEEInstanceKey, gwapi)).NotTo(HaveOccurred())
					Expect(gwapi.Spec.CRDManagement).NotTo(BeNil())
					Expect(*gwapi.Spec.CRDManagement).To(Equal(operatorv1.CRDManagementPreferExisting))
				}
			},
			Entry("default", func(_ *operatorv1.GatewayAPI) {}, false),
			Entry("Reconcile", func(gwapi *operatorv1.GatewayAPI) {
				setting := operatorv1.CRDManagementReconcile
				gwapi.Spec.CRDManagement = &setting
			}, true),
			Entry("PreferExisting", func(gwapi *operatorv1.GatewayAPI) {
				setting := operatorv1.CRDManagementPreferExisting
				gwapi.Spec.CRDManagement = &setting
			}, false),
		)
	})

	It("handles a custom EnvoyGateway", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		By("creating a custom EnvoyGateway")
		envoyGateway := &envoyapi.EnvoyGateway{
			EnvoyGatewaySpec: envoyapi.EnvoyGatewaySpec{
				Telemetry: &envoyapi.EnvoyGatewayTelemetry{
					Metrics: &envoyapi.EnvoyGatewayMetrics{
						Sinks: []envoyapi.EnvoyGatewayMetricSink{{
							Type: envoyapi.MetricSinkTypeOpenTelemetry,
						}},
					},
				},
				ExtensionAPIs: &envoyapi.ExtensionAPISettings{
					EnableEnvoyPatchPolicy: true,
					EnableBackend:          true,
				},
			},
		}
		envoyGatewayYAML, err := yaml.Marshal(*envoyGateway)
		Expect(err).NotTo(HaveOccurred())
		envoyGatewayConfigMap := &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ConfigMap",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-envoy-gateway",
				Namespace: "default",
			},
			Data: map[string]string{
				"envoy-gateway.yaml": string(envoyGatewayYAML),
			},
		}
		Expect(c.Create(ctx, envoyGatewayConfigMap)).NotTo(HaveOccurred())

		By("applying the GatewayAPI CR to the fake cluster")
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.GatewayAPISpec{
				EnvoyGatewayConfigRef: &operatorv1.NamespacedName{
					Namespace: "default",
					Name:      "my-envoy-gateway",
				},
			},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		_, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())

		By("checking the component handlers")
		Expect(fakeComponentHandlers).To(HaveLen(2))
		Expect(fakeComponentHandlers[0].createOnly).To(BeTrue())
		Expect(fakeComponentHandlers[1].createOnly).To(BeFalse())

		By("checking that the custom EnvoyGateway was passed through")
		gatewayAPIImplementationConfig := fakeComponentHandlers[1].lastComponent.(gatewayapi.GatewayAPIImplementationConfigInterface).GetConfig()
		Expect(gatewayAPIImplementationConfig.CustomEnvoyGateway).NotTo(BeNil())
		Expect(*gatewayAPIImplementationConfig.CustomEnvoyGateway).To(Equal(*envoyGateway))
	})

	It("handles when a custom EnvoyGateway is referenced but does not exist yet, then created later", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		By("applying the GatewayAPI CR to the fake cluster")
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.GatewayAPISpec{
				EnvoyGatewayConfigRef: &operatorv1.NamespacedName{
					Namespace: "default",
					Name:      "my-envoy-gateway",
				},
			},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		mockStatus.On(
			"SetDegraded",
			operatorv1.ResourceReadError,
			"Error reading EnvoyGatewayConfigRef",
			"configmaps \"my-envoy-gateway\" not found",
			mock.Anything,
		).Return()
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).Should(HaveOccurred())

		By("now creating the custom EnvoyGateway")
		envoyGateway := &envoyapi.EnvoyGateway{
			EnvoyGatewaySpec: envoyapi.EnvoyGatewaySpec{
				Telemetry: &envoyapi.EnvoyGatewayTelemetry{
					Metrics: &envoyapi.EnvoyGatewayMetrics{
						Sinks: []envoyapi.EnvoyGatewayMetricSink{{
							Type: envoyapi.MetricSinkTypeOpenTelemetry,
						}},
					},
				},
				ExtensionAPIs: &envoyapi.ExtensionAPISettings{
					EnableEnvoyPatchPolicy: true,
					EnableBackend:          true,
				},
			},
		}
		envoyGatewayYAML, err := yaml.Marshal(*envoyGateway)
		Expect(err).NotTo(HaveOccurred())
		envoyGatewayConfigMap := &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ConfigMap",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-envoy-gateway",
				Namespace: "default",
			},
			Data: map[string]string{
				"envoy-gateway.yaml": string(envoyGatewayYAML),
			},
		}
		Expect(c.Create(ctx, envoyGatewayConfigMap)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		fakeComponentHandlers = nil
		_, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())

		By("checking that the custom EnvoyGateway was passed through")
		gatewayAPIImplementationConfig := fakeComponentHandlers[1].lastComponent.(gatewayapi.GatewayAPIImplementationConfigInterface).GetConfig()
		Expect(gatewayAPIImplementationConfig.CustomEnvoyGateway).NotTo(BeNil())
		Expect(*gatewayAPIImplementationConfig.CustomEnvoyGateway).To(Equal(*envoyGateway))
	})

	It("handles when a custom EnvoyGateway is referenced and exists but does not have the right key", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		By("creating a custom EnvoyGateway")
		envoyGatewayConfigMap := &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ConfigMap",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-envoy-gateway",
				Namespace: "default",
			},
			Data: map[string]string{
				"wrong-key": "doesn't matter",
			},
		}
		Expect(c.Create(ctx, envoyGatewayConfigMap)).NotTo(HaveOccurred())

		By("applying the GatewayAPI CR to the fake cluster")
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.GatewayAPISpec{
				EnvoyGatewayConfigRef: &operatorv1.NamespacedName{
					Namespace: "default",
					Name:      "my-envoy-gateway",
				},
			},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		mockStatus.On(
			"SetDegraded",
			operatorv1.ResourceReadError,
			"Error reading EnvoyGatewayConfigRef",
			"missing 'envoy-gateway.yaml' key",
			mock.Anything,
		).Return()
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).Should(HaveOccurred())
	})

	It("handles when a custom EnvoyGateway is referenced and exists but holds invalid YAML", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		By("creating a custom EnvoyGateway")
		envoyGatewayConfigMap := &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ConfigMap",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-envoy-gateway",
				Namespace: "default",
			},
			Data: map[string]string{
				"envoy-gateway.yaml": "invalid YAML",
			},
		}
		Expect(c.Create(ctx, envoyGatewayConfigMap)).NotTo(HaveOccurred())

		By("applying the GatewayAPI CR to the fake cluster")
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.GatewayAPISpec{
				EnvoyGatewayConfigRef: &operatorv1.NamespacedName{
					Namespace: "default",
					Name:      "my-envoy-gateway",
				},
			},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		mockStatus.On(
			"SetDegraded",
			operatorv1.ResourceReadError,
			"Error reading EnvoyGatewayConfigRef",
			"error unmarshaling JSON: while decoding JSON: json: cannot unmarshal string into Go value of type v1alpha1.EnvoyGateway",
			mock.Anything,
		).Return()
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).Should(HaveOccurred())
	})

	It("handles custom EnvoyProxies", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		By("creating custom EnvoyProxy #1")
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
		Expect(c.Create(ctx, envoyProxy1)).NotTo(HaveOccurred())

		By("creating custom EnvoyProxy #2")
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
		Expect(c.Create(ctx, envoyProxy2)).NotTo(HaveOccurred())

		By("applying the GatewayAPI CR to the fake cluster")
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{
					Name: "custom-class-1",
					EnvoyProxyRef: &operatorv1.NamespacedName{
						Namespace: "default",
						Name:      "my-proxy-1",
					},
				}, {
					Name: "custom-class-2",
					EnvoyProxyRef: &operatorv1.NamespacedName{
						Namespace: "default",
						Name:      "my-proxy-2",
					},
				}},
			},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())

		By("checking the component handlers")
		Expect(fakeComponentHandlers).To(HaveLen(2))
		Expect(fakeComponentHandlers[0].createOnly).To(BeTrue())
		Expect(fakeComponentHandlers[1].createOnly).To(BeFalse())

		By("checking that the custom EnvoyProxies were passed through")
		gatewayAPIImplementationConfig := fakeComponentHandlers[1].lastComponent.(gatewayapi.GatewayAPIImplementationConfigInterface).GetConfig()
		Expect(gatewayAPIImplementationConfig.CustomEnvoyProxies).NotTo(BeNil())
		Expect(gatewayAPIImplementationConfig.CustomEnvoyProxies).To(HaveKeyWithValue("custom-class-1", envoyProxy1))
		Expect(gatewayAPIImplementationConfig.CustomEnvoyProxies).To(HaveKeyWithValue("custom-class-2", envoyProxy2))
	})

	It("handles when a custom EnvoyProxy is referenced but does not exist", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		By("creating custom EnvoyProxy #1")
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
		Expect(c.Create(ctx, envoyProxy1)).NotTo(HaveOccurred())

		By("NOT creating custom EnvoyProxy #2")

		By("applying the GatewayAPI CR to the fake cluster")
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{
					Name: "custom-class-1",
					EnvoyProxyRef: &operatorv1.NamespacedName{
						Namespace: "default",
						Name:      "my-proxy-1",
					},
				}, {
					Name: "custom-class-2",
					EnvoyProxyRef: &operatorv1.NamespacedName{
						Namespace: "default",
						Name:      "my-proxy-2",
					},
				}},
			},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		mockStatus.On(
			"SetDegraded",
			operatorv1.ResourceReadError,
			"Error reading EnvoyProxyRef",
			"envoyproxies.gateway.envoyproxy.io \"my-proxy-2\" not found",
			mock.Anything,
		).Return()
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).Should(HaveOccurred())
	})

	It("handles when both GatewayKind and an incompatible EnvoyProxy are specified", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		By("creating custom EnvoyProxy")
		three := int32(3)
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
				Provider: &envoyapi.EnvoyProxyProvider{
					Type: envoyapi.ProviderTypeKubernetes,
					Kubernetes: &envoyapi.EnvoyProxyKubernetesProvider{
						EnvoyDeployment: &envoyapi.KubernetesDeploymentSpec{
							Replicas: &three,
						},
					},
				},
			},
		}
		Expect(c.Create(ctx, envoyProxy1)).NotTo(HaveOccurred())

		By("applying the GatewayAPI CR to the fake cluster")
		daemonSet := operatorv1.GatewayKindDaemonSet
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.GatewayAPISpec{
				GatewayClasses: []operatorv1.GatewayClassSpec{{
					Name: "custom-class-1",
					EnvoyProxyRef: &operatorv1.NamespacedName{
						Namespace: "default",
						Name:      "my-proxy-1",
					},
					GatewayKind: &daemonSet,
				}},
			},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		mockStatus.On(
			"SetDegraded",
			operatorv1.ResourceReadError,
			"Conflict between EnvoyProxyRef and GatewayKind",
			"GatewayKind (for class 'custom-class-1') cannot be 'DaemonSet' when EnvoyProxyRef already indicates that gateways will be provisioned as a Deployment",
			mock.Anything,
		).Return()
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).Should(HaveOccurred())
	})

	It("writes back defaults to the GatewayAPI CR", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		By("applying the GatewayAPI CR to the fake cluster")
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())

		By("re-reading the GatewayAPI")
		err = c.Get(ctx, utils.DefaultTSEEInstanceKey, gwapi)
		Expect(err).NotTo(HaveOccurred())

		By("checking default GatewayClasses")
		Expect(gwapi.Spec.GatewayClasses).To(HaveLen(1))
		Expect(gwapi.Spec.GatewayClasses[0].Name).To(Equal("tigera-gateway-class"))
		Expect(gwapi.Spec.GatewayClasses[0].EnvoyProxyRef).To(BeNil())
		Expect(gwapi.Spec.GatewayClasses[0].GatewayKind).To(BeNil())
		Expect(gwapi.Spec.GatewayClasses[0].GatewayDeployment).To(BeNil())
		Expect(gwapi.Spec.GatewayClasses[0].GatewayDaemonSet).To(BeNil())
		Expect(gwapi.Spec.GatewayClasses[0].GatewayService).To(BeNil())

		By("checking default CRDManagement")
		Expect(gwapi.Spec.CRDManagement).NotTo(BeNil())
		Expect(*gwapi.Spec.CRDManagement).To(Equal(operatorv1.CRDManagementReconcile))
	})

	It("Check felix configuration patching is set if it's not alreadyconfigured", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		felixConfig := &crdv1.FelixConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       crdv1.FelixConfigurationSpec{
				// PolicySyncPathPrefix is not set.
			},
		}

		Expect(c.Create(ctx, felixConfig)).NotTo(HaveOccurred())

		By("applying the GatewayAPI CR to the fake cluster")
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())

		By("checking felix configuration has been patched")
		actualFelixConfig := &crdv1.FelixConfiguration{}
		err = c.Get(ctx, client.ObjectKey{Name: "default"}, actualFelixConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(actualFelixConfig.Spec.PolicySyncPathPrefix).To(Equal(DefaultPolicySyncPrefix))

	})

	It("Check felix configuration patching is set if it's not set", func() {
		Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

		felixConfig := &crdv1.FelixConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: crdv1.FelixConfigurationSpec{
				// PolicySyncPathPrefix is not set.
				PolicySyncPathPrefix: "/dev/null",
			},
		}

		Expect(c.Create(ctx, felixConfig)).NotTo(HaveOccurred())

		By("applying the GatewayAPI CR to the fake cluster")
		gwapi := &operatorv1.GatewayAPI{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		Expect(c.Create(ctx, gwapi)).NotTo(HaveOccurred())

		By("triggering a reconcile")
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())

		By("checking felix configuration has been patched")
		actualFelixConfig := &crdv1.FelixConfiguration{}
		err = c.Get(ctx, client.ObjectKey{Name: "default"}, actualFelixConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(actualFelixConfig.Spec.PolicySyncPathPrefix).ToNot(Equal(DefaultPolicySyncPrefix))
		Expect(actualFelixConfig.Spec.PolicySyncPathPrefix).To(Equal("/dev/null"))

	})
})

var fakeComponentHandlers []*fakeComponentHandler

func FakeComponentHandler(log logr.Logger, client client.Client, scheme *runtime.Scheme, cr metav1.Object, _ *operatorv1.ProductVariant) utils.ComponentHandler {
	h := &fakeComponentHandler{
		client: client,
		scheme: scheme,
		cr:     cr,
		log:    log,
	}
	fakeComponentHandlers = append(fakeComponentHandlers, h)
	return h
}

type fakeComponentHandler struct {
	client        client.Client
	scheme        *runtime.Scheme
	cr            metav1.Object
	log           logr.Logger
	createOnly    bool
	lastComponent render.Component
}

func (t *fakeComponentHandler) CreateOrUpdateOrDelete(_ context.Context, component render.Component, _ status.StatusManager) error {
	t.lastComponent = component
	return nil
}

func (t *fakeComponentHandler) SetCreateOnly() {
	t.createOnly = true
}
