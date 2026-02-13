// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/internal/controller"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/utils"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	gapi "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml" // gopkg.in/yaml.v2 didn't parse all the fields but this package did
)

var _ = Describe("GatewayAPI tests", func() {
	var log logr.Logger
	var c client.Client
	var clientset *kubernetes.Clientset
	var mgr manager.Manager
	var shutdownContext context.Context
	var cancel context.CancelFunc
	var operatorDone chan struct{}
	BeforeEach(func() {
		log = logf.Log.WithName("gatewayapi-test-logger")
		c, clientset, mgr = setupManagerNoControllers()

		// Start the GatewayAPI controller.
		shutdownContext, cancel = context.WithCancel(context.TODO())
		err := (&controller.GatewayAPIReconciler{
			Client: c,
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr, options.ControllerOptions{
			DetectedProvider:    operator.ProviderNone,
			EnterpriseCRDExists: EnterpriseCRDsExist,
			ManageCRDs:          ManageCRDsDisable,
			ShutdownContext:     shutdownContext,
			K8sClientset:        clientset,
			MultiTenant:         SingleTenant,
		})
		Expect(err).NotTo(HaveOccurred())

		By("Cleaning up resources before the test")
		cleanupGatewayResources(c)
		cleanupResources(c)

		By("Verifying CRDs are installed")
		verifyCRDsExist(c, operator.TigeraSecureEnterprise)

		By("Creating the tigera-operator namespace, if it doesn't exist")
		ns := &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator"},
			Spec:       corev1.NamespaceSpec{},
		}
		err = c.Create(context.Background(), ns)
		if err != nil && !kerror.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}

		By("Checking no Installation is left over from previous tests")
		instance := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}
		err = c.Get(context.Background(), types.NamespacedName{Name: "default"}, instance)
		Expect(kerror.IsNotFound(err)).To(BeTrue(), fmt.Sprintf("Expected Installation not to exist, but got: %s", err))

		operatorDone = RunOperator(mgr, shutdownContext)
	})

	AfterEach(func() {
		defer func() {
			cancel()
			Eventually(func() error {
				select {
				case <-operatorDone:
					return nil
				default:
					return fmt.Errorf("operator did not shutdown")
				}
			}, 60*time.Second).ShouldNot(HaveOccurred())
		}()

		By("Cleaning up resources after the test")
		cleanupGatewayResources(c)
		cleanupResources(c)

		// Clean up Calico data that might be left behind.
		Eventually(func() error {
			cs := kubernetes.NewForConfigOrDie(mgr.GetConfig())
			nodes, err := cs.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			if err != nil {
				return err
			}
			if len(nodes.Items) == 0 {
				return fmt.Errorf("No nodes found")
			}
			for _, n := range nodes.Items {
				for k := range n.ObjectMeta.Annotations {
					if strings.Contains(k, "projectcalico") {
						delete(n.ObjectMeta.Annotations, k)
					}
				}
				_, err = cs.CoreV1().Nodes().Update(context.Background(), &n, metav1.UpdateOptions{})
				if err != nil {
					return err
				}
			}
			return nil
		}, 30*time.Second).Should(BeNil())

		mgr = nil
	})

	It("cleans up GatewayClass and EnvoyProxy resources when no longer wanted", func() {
		By("Creating Installation")
		instance := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operator.InstallationSpec{
				Registry: "myregistry.io/",
				Variant:  operator.TigeraSecureEnterprise,
			},
		}
		err := c.Create(shutdownContext, instance)
		Expect(err).NotTo(HaveOccurred())

		// Read it back again.
		err = c.Get(shutdownContext, utils.DefaultInstanceKey, instance)
		Expect(err).NotTo(HaveOccurred())

		// Update the status to set variant to Enterprise.
		instance.Status.Variant = operator.TigeraSecureEnterprise
		err = c.Status().Update(shutdownContext, instance)
		Expect(err).NotTo(HaveOccurred())

		By("Creating the default GatewayAPI")
		gatewayAPI := &operator.GatewayAPI{
			TypeMeta:   metav1.TypeMeta{Kind: "GatewayAPI", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		err = c.Create(shutdownContext, gatewayAPI)
		Expect(err).NotTo(HaveOccurred())

		getGatewayClassNames := func() (gcepNames []string) {
			var gcList gapi.GatewayClassList
			err = c.List(shutdownContext, &gcList)
			if err != nil {
				return []string{err.Error()}
			}
			for i := range gcList.Items {
				log.Info(fmt.Sprintf("GatewayClass = %#v", gcList.Items[i]))
				gcepNames = append(gcepNames, gcList.Items[i].Name+":"+gcList.Items[i].Spec.ParametersRef.Name)
			}
			return
		}

		By("Checking for the default tigera-gateway-class and its EnvoyProxy")
		Eventually(getGatewayClassNames, "10s").Should(ConsistOf("tigera-gateway-class:tigera-gateway-class"))

		By("Now configuring two custom classes")
		err = c.Get(shutdownContext, utils.DefaultTSEEInstanceKey, gatewayAPI)
		Expect(err).NotTo(HaveOccurred())
		gatewayAPI.Spec.GatewayClasses = []operator.GatewayClassSpec{{
			Name: "custom-class-1",
		}, {
			Name: "custom-class-2",
		}}
		err = c.Update(shutdownContext, gatewayAPI)
		Expect(err).NotTo(HaveOccurred())

		By("Checking that we now just have the two custom gateway classes")
		Eventually(getGatewayClassNames, "10s").Should(ConsistOf("custom-class-1:custom-class-1", "custom-class-2:custom-class-2"))

		By("Deconfiguring one of the custom classes")
		err = c.Get(shutdownContext, utils.DefaultTSEEInstanceKey, gatewayAPI)
		Expect(err).NotTo(HaveOccurred())
		gatewayAPI.Spec.GatewayClasses = []operator.GatewayClassSpec{{
			Name: "custom-class-1",
		}}
		err = c.Update(shutdownContext, gatewayAPI)
		Expect(err).NotTo(HaveOccurred())

		By("Checking that the second custom class has gone")
		Eventually(getGatewayClassNames, "10s").Should(ConsistOf("custom-class-1:custom-class-1"))

		By("Reverting to the default GatewayAPI")
		err = c.Get(shutdownContext, utils.DefaultTSEEInstanceKey, gatewayAPI)
		Expect(err).NotTo(HaveOccurred())
		gatewayAPI.Spec.GatewayClasses = nil
		err = c.Update(shutdownContext, gatewayAPI)
		Expect(err).NotTo(HaveOccurred())

		By("Checking that we now only have the default tigera-gateway-class")
		Eventually(getGatewayClassNames, "10s").Should(ConsistOf("tigera-gateway-class:tigera-gateway-class"))
	})

	It("watches custom EnvoyProxy resources", func() {
		By("Creating Installation")
		instance := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operator.InstallationSpec{
				Registry: "myregistry.io/",
				Variant:  operator.TigeraSecureEnterprise,
			},
		}
		err := c.Create(shutdownContext, instance)
		Expect(err).NotTo(HaveOccurred())

		// Read it back again.
		err = c.Get(shutdownContext, utils.DefaultInstanceKey, instance)
		Expect(err).NotTo(HaveOccurred())

		// Update the status to set variant to Enterprise.
		instance.Status.Variant = operator.TigeraSecureEnterprise
		err = c.Status().Update(shutdownContext, instance)
		Expect(err).NotTo(HaveOccurred())

		// We need to create the default GatewayAPI first, to ensure that the EnvoyProxy CRD
		// is available in the cluster.
		By("Creating the default GatewayAPI")
		gatewayAPI := &operator.GatewayAPI{
			TypeMeta:   metav1.TypeMeta{Kind: "GatewayAPI", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		err = c.Create(shutdownContext, gatewayAPI)
		Expect(err).NotTo(HaveOccurred())

		By("Creating a custom EnvoyProxy")
		envoyProxy := &envoyapi.EnvoyProxy{
			TypeMeta: metav1.TypeMeta{Kind: "EnvoyProxy", APIVersion: "gateway.envoyproxy.io/v1alpha1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "custom-ep",
				Namespace: "default",
			},
			Spec: envoyapi.EnvoyProxySpec{
				Logging: envoyapi.ProxyLogging{
					Level: map[envoyapi.ProxyLogComponent]envoyapi.LogLevel{
						envoyapi.LogComponentAdmin: envoyapi.LogLevelInfo,
					},
				},
			},
		}
		Eventually(func() error {
			return c.Create(shutdownContext, envoyProxy)
		}, "10s").ShouldNot(HaveOccurred())

		By("Updating GatewayAPI with that custom EnvoyProxy")
		err = c.Get(shutdownContext, utils.DefaultTSEEInstanceKey, gatewayAPI)
		Expect(err).NotTo(HaveOccurred())
		gatewayAPI.Spec.GatewayClasses = []operator.GatewayClassSpec{{
			Name: "custom-gc",
			EnvoyProxyRef: &operator.NamespacedName{
				Namespace: "default",
				Name:      "custom-ep",
			},
		}}
		err = c.Update(shutdownContext, gatewayAPI)
		Expect(err).NotTo(HaveOccurred())

		getEPLoggingLevels := func() (map[envoyapi.ProxyLogComponent]envoyapi.LogLevel, error) {
			var ep envoyapi.EnvoyProxy
			err = c.Get(shutdownContext, types.NamespacedName{Namespace: "tigera-gateway", Name: "custom-gc"}, &ep)
			if err != nil {
				return nil, err
			}
			return ep.Spec.Logging.Level, nil
		}

		By("Checking for that EnvoyProxy in tigera-gateway namespace")
		Eventually(getEPLoggingLevels, "10s").Should(HaveKeyWithValue(envoyapi.LogComponentAdmin, envoyapi.LogLevelInfo))

		By("Updating the custom EnvoyProxy to add another logging level")
		err = c.Get(shutdownContext, types.NamespacedName{Namespace: "default", Name: "custom-ep"}, envoyProxy)
		Expect(err).NotTo(HaveOccurred())
		envoyProxy.Spec.Logging.Level[envoyapi.LogComponentConnection] = envoyapi.LogLevelDebug
		err = c.Update(shutdownContext, envoyProxy)
		Expect(err).NotTo(HaveOccurred())

		By("Checking that EnvoyProxy in tigera-gateway namespace gets the additional level")
		Eventually(getEPLoggingLevels, "10s").Should(HaveKeyWithValue(envoyapi.LogComponentConnection, envoyapi.LogLevelDebug))
		Consistently(getEPLoggingLevels, "60s", "10s").Should(HaveKeyWithValue(envoyapi.LogComponentConnection, envoyapi.LogLevelDebug))
	})

	It("creates EnvoyProxy with owning gateway env vars in l7-log-collector", func() {
		By("Creating Installation")
		instance := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operator.InstallationSpec{
				Registry: "myregistry.io/",
				Variant:  operator.TigeraSecureEnterprise,
			},
		}
		err := c.Create(shutdownContext, instance)
		Expect(err).NotTo(HaveOccurred())

		// Read it back again.
		err = c.Get(shutdownContext, utils.DefaultInstanceKey, instance)
		Expect(err).NotTo(HaveOccurred())

		// Update the status to set variant to Enterprise.
		instance.Status.Variant = operator.TigeraSecureEnterprise
		err = c.Status().Update(shutdownContext, instance)
		Expect(err).NotTo(HaveOccurred())

		By("Creating the default GatewayAPI")
		gatewayAPI := &operator.GatewayAPI{
			TypeMeta:   metav1.TypeMeta{Kind: "GatewayAPI", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		err = c.Create(shutdownContext, gatewayAPI)
		Expect(err).NotTo(HaveOccurred())

		By("Verifying EnvoyProxy is created with l7-log-collector containing owning gateway env vars")
		Eventually(func() error {
			var ep envoyapi.EnvoyProxy
			err := c.Get(shutdownContext, types.NamespacedName{Namespace: "tigera-gateway", Name: "tigera-gateway-class"}, &ep)
			if err != nil {
				return err
			}

			// Check that EnvoyDeployment has init containers configured
			if ep.Spec.Provider == nil || ep.Spec.Provider.Kubernetes == nil ||
				ep.Spec.Provider.Kubernetes.EnvoyDeployment == nil {
				return errors.New("EnvoyProxy does not have EnvoyDeployment configured")
			}

			initContainers := ep.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers
			if len(initContainers) == 0 {
				return errors.New("EnvoyProxy has no init containers")
			}

			// Find l7-log-collector init container
			var l7LogCollector *corev1.Container
			for i := range initContainers {
				if initContainers[i].Name == "l7-log-collector" {
					l7LogCollector = &initContainers[i]
					break
				}
			}
			if l7LogCollector == nil {
				return errors.New("l7-log-collector init container not found")
			}

			// Verify owning gateway env vars are present
			var foundName, foundNamespace bool
			for _, env := range l7LogCollector.Env {
				if env.Name == "OWNING_GATEWAY_NAME" {
					if env.ValueFrom == nil || env.ValueFrom.FieldRef == nil {
						return errors.New("OWNING_GATEWAY_NAME env var does not use FieldRef")
					}
					if env.ValueFrom.FieldRef.FieldPath != "metadata.labels['gateway.envoyproxy.io/owning-gateway-name']" {
						return fmt.Errorf("OWNING_GATEWAY_NAME has wrong field path: %s", env.ValueFrom.FieldRef.FieldPath)
					}
					foundName = true
				}
				if env.Name == "OWNING_GATEWAY_NAMESPACE" {
					if env.ValueFrom == nil || env.ValueFrom.FieldRef == nil {
						return errors.New("OWNING_GATEWAY_NAMESPACE env var does not use FieldRef")
					}
					if env.ValueFrom.FieldRef.FieldPath != "metadata.labels['gateway.envoyproxy.io/owning-gateway-namespace']" {
						return fmt.Errorf("OWNING_GATEWAY_NAMESPACE has wrong field path: %s", env.ValueFrom.FieldRef.FieldPath)
					}
					foundNamespace = true
				}
			}

			if !foundName {
				return errors.New("OWNING_GATEWAY_NAME env var not found in l7-log-collector")
			}
			if !foundNamespace {
				return errors.New("OWNING_GATEWAY_NAMESPACE env var not found in l7-log-collector")
			}

			return nil
		}, "30s").ShouldNot(HaveOccurred())
	})

	It("watches the custom EnvoyGateway ConfigMap", func() {
		By("Creating Installation")
		instance := &operator.Installation{
			TypeMeta:   metav1.TypeMeta{Kind: "Installation", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operator.InstallationSpec{
				Registry: "myregistry.io/",
				Variant:  operator.TigeraSecureEnterprise,
			},
		}
		err := c.Create(shutdownContext, instance)
		Expect(err).NotTo(HaveOccurred())

		// Read it back again.
		err = c.Get(shutdownContext, utils.DefaultInstanceKey, instance)
		Expect(err).NotTo(HaveOccurred())

		// Update the status to set variant to Enterprise.
		instance.Status.Variant = operator.TigeraSecureEnterprise
		err = c.Status().Update(shutdownContext, instance)
		Expect(err).NotTo(HaveOccurred())

		By("Creating GatewayAPI, with EnvoyGatewayConfigRef that doesn't exist yet")
		gatewayAPI := &operator.GatewayAPI{
			TypeMeta:   metav1.TypeMeta{Kind: "GatewayAPI", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operator.GatewayAPISpec{
				EnvoyGatewayConfigRef: &operator.NamespacedName{
					Namespace: "default",
					Name:      "my-envoy-gateway",
				},
			},
		}
		err = c.Create(shutdownContext, gatewayAPI)
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the gatewayapi status is degraded")
		Eventually(func() error {
			ts, err := getTigeraStatus(c, "gatewayapi")
			if err != nil {
				return err
			}
			return assertDegraded(ts)
		}, 10*time.Second).Should(BeNil())

		By("Now creating the custom EnvoyGateway")
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
		Expect(c.Create(shutdownContext, envoyGatewayConfigMap)).NotTo(HaveOccurred())

		By("Verifying the gatewayapi status is no longer degraded")
		Eventually(func() error {
			ts, err := getTigeraStatus(c, "gatewayapi")
			if err != nil {
				return err
			}
			_, degraded, _ := readStatus(ts)
			if degraded {
				return errors.New("still degraded")
			}
			return nil
		}, 10*time.Second).Should(BeNil())

		By("Verifying the expected envoy-gateway-config")
		Eventually(func() error {
			var eg corev1.ConfigMap
			err := c.Get(shutdownContext, types.NamespacedName{Name: "envoy-gateway-config", Namespace: "tigera-gateway"}, &eg)
			if err != nil {
				return err
			}
			if !strings.Contains(eg.Data["envoy-gateway.yaml"], "type: OpenTelemetry") {
				return errors.New("envoy-gateway-config does not contain expected text")
			}
			return nil
		}, 10*time.Second).ShouldNot(HaveOccurred())
	})
})

func cleanupGatewayResources(c client.Client) {
	By("Cleaning up custom EnvoyGateway")
	Eventually(func() error {
		var eg corev1.ConfigMap
		err := c.Get(context.Background(), types.NamespacedName{Name: "my-envoy-gateway", Namespace: "default"}, &eg)
		if err == nil {
			By(fmt.Sprintf("Deleting EnvoyGateway %s", eg.Name))
			err = c.Delete(context.Background(), &eg)
			if err != nil {
				return err
			}
		}
		return nil
	}, 30*time.Second).ShouldNot(HaveOccurred())

	By("Cleaning up GatewayAPIs")
	Eventually(func() error {
		objs := &operator.GatewayAPIList{}
		err := c.List(context.Background(), objs)
		if err != nil {
			return err
		}

		for _, p := range objs.Items {
			By(fmt.Sprintf("Deleting GatewayAPI %s", p.Name))
			err = c.Delete(context.Background(), &p)
			if err != nil {
				return err
			}
		}
		return nil
	}, 30*time.Second).ShouldNot(HaveOccurred())

	By("Cleaning up EnvoyProxies")
	Eventually(func() error {
		objs := &envoyapi.EnvoyProxyList{}
		err := c.List(context.Background(), objs)
		if err != nil {
			if strings.Contains(err.Error(), "no matches for kind \"EnvoyProxy\"") {
				// CRD has not been created yet.
				return nil
			}
			return err
		}

		for _, p := range objs.Items {
			By(fmt.Sprintf("Deleting EnvoyProxy %s", p.Name))
			err = c.Delete(context.Background(), &p)
			if err != nil {
				return err
			}
		}
		return nil
	}, 30*time.Second).ShouldNot(HaveOccurred())

	By("Expecting tigera-gateway namespace to disappear")
	Eventually(func() error {
		ns := &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-gateway"},
		}
		err := GetResource(c, ns)
		if err == nil {
			return fmt.Errorf("tigera-gateway namespace still exists")
		}
		if !kerror.IsNotFound(err) {
			return err
		}
		return nil
	}, "60s").ShouldNot(HaveOccurred())
}
