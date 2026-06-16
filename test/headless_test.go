// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/istio"
	gapi "sigs.k8s.io/gateway-api/apis/v1"
)

// These tests exercise headless installations (spec.calicoNetwork.linuxDataplane: None with
// spec.cni omitted): the operator deploys no Calico dataplane and standalone components
// (Calico Ingress Gateway, Calico Istio service mesh) install on top of a third-party CNI.
//
// They require a kind cluster with the default CNI (kindnet) enabled, which the regular FV
// cluster does not have — run them with `make fv-headless`, which provisions a suitable
// cluster from deploy/kind-config-headless.yaml. The `headless` label keeps them out of the
// regular `make fv` run.
var _ = Describe("Headless installation FV tests", Label("headless"), func() {
	var c client.Client
	var mgr manager.Manager
	var shutdownContext context.Context
	var cancel context.CancelFunc
	var operatorDone chan struct{}

	headlessInstallationSpec := func(variant operator.ProductVariant) *operator.InstallationSpec {
		dpNone := operator.LinuxDataplaneNone
		return &operator.InstallationSpec{
			Variant: variant,
			CalicoNetwork: &operator.CalicoNetworkSpec{
				LinuxDataplane: &dpNone,
			},
		}
	}

	// verifyHeadlessInstallation waits for the headless Installation to become Available and
	// asserts that none of the Calico dataplane workloads have been rendered.
	verifyHeadlessInstallation := func() {
		By("Waiting for the Installation TigeraStatus to become Available with no dataplane")
		Eventually(func() error {
			ts, err := getTigeraStatus(c, "calico")
			if err != nil {
				return err
			}
			return assertAvailable(ts)
		}, 120*time.Second).Should(BeNil())

		By("Verifying no Calico dataplane workloads were rendered")
		err := GetResource(c, &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace}})
		Expect(kerror.IsNotFound(err)).To(BeTrue(), "expected no calico-node DaemonSet")
		err = GetResource(c, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: common.TyphaDeploymentName, Namespace: common.CalicoNamespace}})
		Expect(kerror.IsNotFound(err)).To(BeTrue(), "expected no calico-typha Deployment")
		err = GetResource(c, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: common.KubeControllersDeploymentName, Namespace: common.CalicoNamespace}})
		Expect(kerror.IsNotFound(err)).To(BeTrue(), "expected no calico-kube-controllers Deployment")
		err = GetResource(c, &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: render.CSIDaemonSetName, Namespace: common.CalicoNamespace}})
		Expect(kerror.IsNotFound(err)).To(BeTrue(), "expected no csi-node-driver DaemonSet")
	}

	expectNoFelixConfiguration := func() {
		err := c.Get(context.Background(), types.NamespacedName{Name: "default"}, &v3.FelixConfiguration{})
		Expect(kerror.IsNotFound(err)).To(BeTrue(), "expected no default FelixConfiguration in a headless cluster")
	}

	// cleanupStaleGatewayClasses removes any leftover default GatewayClass. A GatewayClass
	// can be left stuck terminating if envoy-gateway (which holds the gateway-exists
	// finalizer while a Gateway references the class) is torn down before processing the
	// Gateway's deletion; with the controller gone, nothing removes the finalizer, so we
	// strip it here to give each spec a clean slate.
	cleanupStaleGatewayClasses := func() {
		Eventually(func() error {
			var gc gapi.GatewayClass
			err := c.Get(context.Background(), types.NamespacedName{Name: "tigera-gateway-class"}, &gc)
			if kerror.IsNotFound(err) || apimeta.IsNoMatchError(err) {
				// Not present, or the Gateway API CRDs haven't been installed yet
				// (a fresh cluster has them only after a GatewayAPI CR is reconciled).
				return nil
			}
			if err != nil {
				return err
			}
			if gc.DeletionTimestamp == nil {
				_ = c.Delete(context.Background(), &gc)
			}
			if len(gc.Finalizers) > 0 {
				gc.Finalizers = nil
				if err := c.Update(context.Background(), &gc); err != nil && !kerror.IsNotFound(err) {
					return err
				}
			}
			return fmt.Errorf("GatewayClass tigera-gateway-class still present")
		}, 60*time.Second).ShouldNot(HaveOccurred())
	}

	BeforeEach(func() {
		c, shutdownContext, cancel, mgr = setupManager(ManageCRDsDisable, SingleTenant, EnterpriseCRDsExist)

		By("Verifying the cluster has a working third-party CNI")
		// CoreDNS can only become ready if pod networking works without Calico; this fails
		// fast (with a useful message) when these tests are pointed at the regular FV
		// cluster, which has no default CNI.
		Eventually(func() error {
			d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "coredns", Namespace: "kube-system"}}
			if err := GetResource(c, d); err != nil {
				return err
			}
			if d.Status.AvailableReplicas < 1 {
				return fmt.Errorf("coredns has no available replicas; headless FV needs a cluster with a default CNI (use `make fv-headless`)")
			}
			return nil
		}, 120*time.Second).Should(BeNil())

		By("Cleaning up resources before the test")
		cleanupGatewayResources(c)
		cleanupStaleGatewayClasses()
		cleanupResources(c)

		By("Verifying CRDs are installed")
		verifyCRDsExist(c, operator.CalicoEnterprise)

		By("Creating the tigera-operator namespace, if it doesn't exist")
		ns := &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-operator"},
		}
		err := c.Create(context.Background(), ns)
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
	})

	AfterEach(func() {
		defer func() {
			cancel()

			By("Waiting for the operator to shutdown")
			Eventually(func() error {
				select {
				case <-operatorDone:
					return nil
				default:
					return fmt.Errorf("operator did not shutdown")
				}
			}, 60*time.Second).ShouldNot(HaveOccurred())
		}()

		// All cleanup must happen while the operator is still running, since CR deletion
		// relies on the operator processing finalizers.
		By("Cleaning up resources after the test")

		// Delete any Istio CR; in headless mode its finalizer is removed without touching
		// FelixConfiguration, so deletion must complete.
		istioCR := &operator.Istio{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
		if err := c.Delete(context.Background(), istioCR); err == nil || !kerror.IsNotFound(err) {
			Eventually(func() error {
				err := c.Get(context.Background(), types.NamespacedName{Name: "default"}, &operator.Istio{})
				if kerror.IsNotFound(err) {
					return nil
				}
				if err != nil {
					return err
				}
				return fmt.Errorf("Istio CR still exists")
			}, 120*time.Second).ShouldNot(HaveOccurred())
		}

		cleanupGatewayResources(c)
		cleanupStaleGatewayClasses()
		cleanupResources(c)
	})

	It("installs the Calico Ingress Gateway with no Calico dataplane", func() {
		operatorDone = createInstallation(c, mgr, shutdownContext, headlessInstallationSpec(operator.Calico))
		verifyHeadlessInstallation()

		By("Creating the default GatewayAPI")
		gatewayAPI := &operator.GatewayAPI{
			TypeMeta:   metav1.TypeMeta{Kind: "GatewayAPI", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		Expect(c.Create(shutdownContext, gatewayAPI)).NotTo(HaveOccurred())

		By("Waiting for the envoy-gateway controller Deployment to become available")
		Eventually(func() error {
			d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway", Namespace: common.CalicoNamespace}}
			if err := GetResource(c, d); err != nil {
				return err
			}
			if d.Status.AvailableReplicas < 1 {
				return fmt.Errorf("envoy-gateway has no available replicas yet")
			}
			return nil
		}, 300*time.Second).ShouldNot(HaveOccurred())

		By("Waiting for the gatewayapi TigeraStatus to become Available")
		Eventually(func() error {
			ts, err := getTigeraStatus(c, "gatewayapi")
			if err != nil {
				return err
			}
			return assertAvailable(ts)
		}, 120*time.Second).Should(BeNil())

		By("Waiting for the default tigera-gateway-class GatewayClass")
		Eventually(func() error {
			var gc gapi.GatewayClass
			return c.Get(shutdownContext, types.NamespacedName{Name: "tigera-gateway-class"}, &gc)
		}, 60*time.Second).ShouldNot(HaveOccurred())

		By("Creating a Gateway as a smoke test")
		// The Gateway is created in calico-system, where the trusted CA bundle and pull
		// secrets that envoy proxy pods mount already exist (the core controller renders
		// them even in headless mode). Per-namespace provisioning of those resources for
		// user Gateway namespaces is currently Enterprise-only, and Enterprise images are
		// not publicly pullable in this test environment.
		const testNs = common.CalicoNamespace
		gw := &gapi.Gateway{
			TypeMeta:   metav1.TypeMeta{Kind: "Gateway", APIVersion: "gateway.networking.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "headless-gw", Namespace: testNs},
			Spec: gapi.GatewaySpec{
				GatewayClassName: "tigera-gateway-class",
				Listeners: []gapi.Listener{{
					Name:     "http",
					Port:     80,
					Protocol: gapi.HTTPProtocolType,
				}},
			},
		}
		Expect(c.Create(shutdownContext, gw)).NotTo(HaveOccurred())
		defer func() {
			_ = c.Delete(context.Background(), gw)
		}()

		By("Waiting for the Gateway to be Accepted by the envoy-gateway controller")
		Eventually(func() error {
			var got gapi.Gateway
			if err := c.Get(shutdownContext, types.NamespacedName{Name: "headless-gw", Namespace: testNs}, &got); err != nil {
				return err
			}
			for _, cond := range got.Status.Conditions {
				if cond.Type == string(gapi.GatewayConditionAccepted) && cond.Status == metav1.ConditionTrue {
					return nil
				}
			}
			return fmt.Errorf("Gateway not yet Accepted: %+v", got.Status.Conditions)
		}, 120*time.Second).ShouldNot(HaveOccurred())

		By("Waiting for an available envoy proxy Deployment for the Gateway")
		Eventually(func() error {
			deployments := &appsv1.DeploymentList{}
			if err := c.List(shutdownContext, deployments, client.MatchingLabels{
				"gateway.envoyproxy.io/owning-gateway-name": "headless-gw",
			}); err != nil {
				return err
			}
			if len(deployments.Items) == 0 {
				return fmt.Errorf("no envoy proxy Deployment for the Gateway yet")
			}
			for _, d := range deployments.Items {
				if d.Status.AvailableReplicas >= 1 {
					return nil
				}
			}
			return fmt.Errorf("envoy proxy Deployment has no available replicas yet")
		}, 300*time.Second).ShouldNot(HaveOccurred())

		By("Verifying FelixConfiguration was not touched (no PolicySync patch in headless mode)")
		expectNoFelixConfiguration()
	})

	It("installs the Calico Istio service mesh with no Calico dataplane", func() {
		// OSS Calico variant, so that between the two specs both product variants get
		// headless coverage.
		operatorDone = createInstallation(c, mgr, shutdownContext, headlessInstallationSpec(operator.Calico))
		verifyHeadlessInstallation()

		By("Creating the default Istio CR")
		istioCR := &operator.Istio{
			TypeMeta:   metav1.TypeMeta{Kind: "Istio", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}
		Expect(c.Create(shutdownContext, istioCR)).NotTo(HaveOccurred())

		By("Waiting for the istiod Deployment to become available")
		Eventually(func() error {
			d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: istio.IstioIstiodDeploymentName, Namespace: istio.IstioNamespace}}
			if err := GetResource(c, d); err != nil {
				return err
			}
			if d.Status.AvailableReplicas < 1 {
				return fmt.Errorf("istiod has no available replicas yet")
			}
			return nil
		}, 300*time.Second).ShouldNot(HaveOccurred())

		// The istio TigeraStatus only reports Available once both DaemonSets are fully
		// rolled out on every node, so wait for full readiness rather than a single pod.
		By("Waiting for the istio-cni and ztunnel DaemonSets to become ready")
		waitForDaemonSetReady(c, istio.IstioNamespace, istio.IstioCNIDaemonSetName, 300*time.Second)
		waitForDaemonSetReady(c, istio.IstioNamespace, istio.IstioZTunnelDaemonSetName, 300*time.Second)

		By("Waiting for the istio TigeraStatus to become Available")
		Eventually(func() error {
			ts, err := getTigeraStatus(c, "istio")
			if err != nil {
				return err
			}
			return assertAvailable(ts)
		}, 120*time.Second).Should(BeNil())

		By("Verifying FelixConfiguration was not touched (Calico dataplane integration is disabled)")
		expectNoFelixConfiguration()

		By("Deleting the Istio CR and verifying its finalizer is removed without a Felix cleanup")
		Expect(c.Delete(shutdownContext, &operator.Istio{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).NotTo(HaveOccurred())
		Eventually(func() error {
			err := c.Get(shutdownContext, types.NamespacedName{Name: "default"}, &operator.Istio{})
			if kerror.IsNotFound(err) {
				return nil
			}
			if err != nil {
				return err
			}
			return fmt.Errorf("Istio CR still exists")
		}, 120*time.Second).ShouldNot(HaveOccurred())
		expectNoFelixConfiguration()
	})

	// ----------------------------------------------------------------------------------
	// Real-life usage specs. The specs above assert that the headless control-plane
	// components install and report Available. The two below go further and exercise the
	// data path: they deploy real (publicly-pullable) workloads and drive real HTTP
	// traffic between in-cluster pods, asserting on the observable behaviour of the
	// Calico Ingress Gateway and the Calico Istio ambient mesh.
	//
	// Traffic is generated by exec'ing curl from an in-cluster client pod (the standard
	// Kubernetes e2e pattern): the FV harness cannot reliably reach pod/Service IPs
	// directly, and ambient-mesh capture only applies to traffic that originates from a
	// pod on a mesh-enrolled node.
	// ----------------------------------------------------------------------------------

	It("routes real HTTP traffic through the Calico Ingress Gateway to path-based backends", func() {
		const appNs = "ig-fv-usage"
		cfg := mgr.GetConfig()

		operatorDone = createInstallation(c, mgr, shutdownContext, headlessInstallationSpec(operator.Calico))
		verifyHeadlessInstallation()

		By("Creating the default GatewayAPI and waiting for the envoy-gateway controller")
		Expect(c.Create(shutdownContext, &operator.GatewayAPI{
			TypeMeta:   metav1.TypeMeta{Kind: "GatewayAPI", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		})).NotTo(HaveOccurred())
		waitForDeploymentAvailable(c, common.CalicoNamespace, "envoy-gateway", 300*time.Second)
		Eventually(func() error {
			var gc gapi.GatewayClass
			return c.Get(shutdownContext, types.NamespacedName{Name: "tigera-gateway-class"}, &gc)
		}, 60*time.Second).ShouldNot(HaveOccurred())

		By("Deploying two http-echo backends and a curl client in the application namespace")
		ensureNamespace(c, appNs, nil)
		DeferCleanup(func() { deleteNamespace(c, appNs) })
		deployHTTPEcho(c, appNs, "echo-a", "hello-from-A")
		deployHTTPEcho(c, appNs, "echo-b", "hello-from-B")
		deployCurlClient(c, appNs, "curl-client")
		waitForDeploymentAvailable(c, appNs, "echo-a", 120*time.Second)
		waitForDeploymentAvailable(c, appNs, "echo-b", 120*time.Second)
		waitForPodReady(c, appNs, "curl-client", 120*time.Second)

		By("Creating a Gateway in calico-system that accepts routes from any namespace")
		// The Gateway lives in calico-system, where the trusted CA bundle and pull
		// secrets that envoy proxy pods mount already exist; allowing routes from all
		// namespaces lets the HTTPRoute (and its backends) live in the application
		// namespace, away from the operator-managed calico-system teardown.
		fromAll := gapi.NamespacesFromAll
		gw := &gapi.Gateway{
			TypeMeta:   metav1.TypeMeta{Kind: "Gateway", APIVersion: "gateway.networking.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "usage-gw", Namespace: common.CalicoNamespace},
			Spec: gapi.GatewaySpec{
				GatewayClassName: "tigera-gateway-class",
				Listeners: []gapi.Listener{{
					Name:     "http",
					Port:     80,
					Protocol: gapi.HTTPProtocolType,
					AllowedRoutes: &gapi.AllowedRoutes{
						Namespaces: &gapi.RouteNamespaces{From: &fromAll},
					},
				}},
			},
		}
		Expect(c.Create(shutdownContext, gw)).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = c.Delete(context.Background(), gw) })

		By("Creating an HTTPRoute mapping /a to echo-a and /b to echo-b")
		pathPrefix := gapi.PathMatchPathPrefix
		gwNs := gapi.Namespace(common.CalicoNamespace)
		echoBackendPort := gapi.PortNumber(echoPort)
		pathRule := func(prefix, backend string) gapi.HTTPRouteRule {
			value := prefix
			return gapi.HTTPRouteRule{
				Matches: []gapi.HTTPRouteMatch{{
					Path: &gapi.HTTPPathMatch{Type: &pathPrefix, Value: &value},
				}},
				BackendRefs: []gapi.HTTPBackendRef{{
					BackendRef: gapi.BackendRef{BackendObjectReference: gapi.BackendObjectReference{
						Name: gapi.ObjectName(backend),
						Port: &echoBackendPort,
					}},
				}},
			}
		}
		route := &gapi.HTTPRoute{
			TypeMeta:   metav1.TypeMeta{Kind: "HTTPRoute", APIVersion: "gateway.networking.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "echo-route", Namespace: appNs},
			Spec: gapi.HTTPRouteSpec{
				CommonRouteSpec: gapi.CommonRouteSpec{
					ParentRefs: []gapi.ParentReference{{Namespace: &gwNs, Name: gapi.ObjectName("usage-gw")}},
				},
				Rules: []gapi.HTTPRouteRule{pathRule("/a", "echo-a"), pathRule("/b", "echo-b")},
			},
		}
		Expect(c.Create(shutdownContext, route)).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = c.Delete(context.Background(), route) })

		By("Waiting for the Gateway's envoy proxy Deployment to become available")
		Eventually(func() error {
			deployments := &appsv1.DeploymentList{}
			if err := c.List(shutdownContext, deployments, client.MatchingLabels{
				"gateway.envoyproxy.io/owning-gateway-name": "usage-gw",
			}); err != nil {
				return err
			}
			for i := range deployments.Items {
				if deployments.Items[i].Status.AvailableReplicas >= 1 {
					return nil
				}
			}
			return fmt.Errorf("no available envoy proxy Deployment for the Gateway yet")
		}, 300*time.Second).ShouldNot(HaveOccurred())

		By("Discovering the Gateway's data-plane Service ClusterIP")
		var gatewayIP string
		Eventually(func() error {
			ip, err := gatewayServiceClusterIP(c, common.CalicoNamespace, "usage-gw")
			if err != nil {
				return err
			}
			gatewayIP = ip
			return nil
		}, 120*time.Second).ShouldNot(HaveOccurred())

		By("Verifying GET /a is routed to echo-a through the gateway")
		Eventually(func() error {
			res, err := runCurl(cfg, appNs, "curl-client", fmt.Sprintf("http://%s/a", gatewayIP))
			if err != nil {
				return err
			}
			if res.Code != "200" {
				return fmt.Errorf("expected 200, got %s (body=%q)", res.Code, res.Body)
			}
			if !strings.Contains(res.Body, "hello-from-A") {
				return fmt.Errorf("expected response from echo-a, got body=%q", res.Body)
			}
			return nil
		}, 120*time.Second).ShouldNot(HaveOccurred())

		By("Verifying GET /b is routed to echo-b through the gateway")
		Eventually(func() error {
			res, err := runCurl(cfg, appNs, "curl-client", fmt.Sprintf("http://%s/b", gatewayIP))
			if err != nil {
				return err
			}
			if res.Code != "200" {
				return fmt.Errorf("expected 200, got %s (body=%q)", res.Code, res.Body)
			}
			if !strings.Contains(res.Body, "hello-from-B") {
				return fmt.Errorf("expected response from echo-b, got body=%q", res.Body)
			}
			return nil
		}, 120*time.Second).ShouldNot(HaveOccurred())

		By("Verifying an unmatched path returns 404 from the gateway")
		Eventually(func() error {
			res, _ := runCurl(cfg, appNs, "curl-client", fmt.Sprintf("http://%s/no-such-route", gatewayIP))
			if res.Code != "404" {
				return fmt.Errorf("expected 404 for unmatched path, got %s (body=%q)", res.Code, res.Body)
			}
			return nil
		}, 60*time.Second).ShouldNot(HaveOccurred())

		By("Verifying FelixConfiguration was not touched (no PolicySync patch in headless mode)")
		expectNoFelixConfiguration()
	})

	It("enforces an AuthorizationPolicy on real traffic in the Calico Istio ambient mesh", func() {
		const meshNs = "istio-fv-usage"
		cfg := mgr.GetConfig()

		operatorDone = createInstallation(c, mgr, shutdownContext, headlessInstallationSpec(operator.Calico))
		verifyHeadlessInstallation()

		By("Creating the default Istio CR and waiting for the ambient mesh to be ready")
		Expect(c.Create(shutdownContext, &operator.Istio{
			TypeMeta:   metav1.TypeMeta{Kind: "Istio", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		})).NotTo(HaveOccurred())
		waitForDeploymentAvailable(c, istio.IstioNamespace, istio.IstioIstiodDeploymentName, 300*time.Second)
		// istio-cni and ztunnel must be fully ready on every node before mesh workloads
		// start, since pod enrollment into the mesh happens at pod-creation time.
		waitForDaemonSetReady(c, istio.IstioNamespace, istio.IstioCNIDaemonSetName, 300*time.Second)
		waitForDaemonSetReady(c, istio.IstioNamespace, istio.IstioZTunnelDaemonSetName, 300*time.Second)
		Eventually(func() error {
			ts, err := getTigeraStatus(c, "istio")
			if err != nil {
				return err
			}
			return assertAvailable(ts)
		}, 120*time.Second).Should(BeNil())

		By("Creating an ambient-enrolled namespace with a server and a client workload")
		ensureNamespace(c, meshNs, map[string]string{"istio.io/dataplane-mode": "ambient"})
		DeferCleanup(func() { deleteNamespace(c, meshNs) })
		deployHTTPEcho(c, meshNs, "mesh-echo", "hello-mesh")
		deployCurlClient(c, meshNs, "curl-client")
		waitForDeploymentAvailable(c, meshNs, "mesh-echo", 120*time.Second)
		waitForPodReady(c, meshNs, "curl-client", 120*time.Second)

		echoURL := fmt.Sprintf("http://mesh-echo:%d/", echoPort)

		By("Verifying client-to-server traffic flows by default in the mesh")
		Eventually(func() error {
			res, err := runCurl(cfg, meshNs, "curl-client", echoURL)
			if err != nil {
				return err
			}
			if res.Code != "200" {
				return fmt.Errorf("expected 200, got %s (body=%q)", res.Code, res.Body)
			}
			if !strings.Contains(res.Body, "hello-mesh") {
				return fmt.Errorf("expected response from mesh-echo, got body=%q", res.Body)
			}
			return nil
		}, 120*time.Second).ShouldNot(HaveOccurred())

		By("Applying a deny-all AuthorizationPolicy targeting the server workload")
		denyPolicy := denyAllAuthorizationPolicy(meshNs, "deny-mesh-echo", map[string]string{"app": "mesh-echo"})
		// The AuthorizationPolicy CRD is installed by the Istio control plane, which may
		// race the reconcile that created it, so tolerate a transient no-match error.
		Eventually(func() error {
			err := c.Create(shutdownContext, denyPolicy)
			if err != nil && !kerror.IsAlreadyExists(err) {
				return err
			}
			return nil
		}, 60*time.Second).ShouldNot(HaveOccurred())
		DeferCleanup(func() { _ = c.Delete(context.Background(), denyPolicy) })

		By("Verifying ztunnel actually blocks the traffic")
		Eventually(func() error {
			res, _ := runCurl(cfg, meshNs, "curl-client", echoURL)
			if res.Code == "200" {
				return fmt.Errorf("expected the mesh to deny the request, still got 200 (body=%q)", res.Body)
			}
			return nil
		}, 90*time.Second).ShouldNot(HaveOccurred())

		By("Removing the AuthorizationPolicy and verifying traffic flows again")
		Expect(c.Delete(shutdownContext, denyPolicy)).NotTo(HaveOccurred())
		Eventually(func() error {
			res, err := runCurl(cfg, meshNs, "curl-client", echoURL)
			if err != nil {
				return err
			}
			if res.Code != "200" {
				return fmt.Errorf("expected traffic to be allowed again, got %s (body=%q)", res.Code, res.Body)
			}
			return nil
		}, 90*time.Second).ShouldNot(HaveOccurred())

		By("Verifying FelixConfiguration was not touched (Calico dataplane integration is disabled)")
		expectNoFelixConfiguration()
	})
})
