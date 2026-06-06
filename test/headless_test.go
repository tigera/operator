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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
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

// These tests exercise headless installations (spec.cni.type: None plus
// spec.calicoNetwork.linuxDataplane: None): the operator deploys no Calico dataplane and
// standalone components (Calico Ingress Gateway, Calico Istio service mesh) install on top
// of a third-party CNI.
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
			CNI:     &operator.CNISpec{Type: operator.PluginNone},
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
			if kerror.IsNotFound(err) {
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

		By("Waiting for the istio-cni and ztunnel DaemonSets to become ready")
		for _, name := range []string{istio.IstioCNIDaemonSetName, istio.IstioZTunnelDaemonSetName} {
			Eventually(func() error {
				ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: istio.IstioNamespace}}
				if err := GetResource(c, ds); err != nil {
					return err
				}
				if ds.Status.NumberReady < 1 {
					return fmt.Errorf("%s has no ready pods yet (desired=%d)", name, ds.Status.DesiredNumberScheduled)
				}
				return nil
			}, 300*time.Second).ShouldNot(HaveOccurred(), "DaemonSet %s did not become ready", name)
		}

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
})
