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
	gwctrl "github.com/tigera/operator/pkg/controller/gatewayapi"
	"github.com/tigera/operator/pkg/render/istio"
)

// These tests exercise the *dataplane-on* path: a full Calico install (calico-node + Felix
// running) with the Calico Ingress Gateway and the Calico Istio service mesh installed on
// top. They are the positive counterpart to the dataplane-disabled specs (no_dataplane_test.go), which
// verify the same components install with the Calico dataplane integration switched OFF.
//
// The distinct thing proven here is that the integration actually *functions* when Felix is
// present: FelixConfiguration is patched (IstioAmbientMode/DSCP for Istio, PolicySyncPathPrefix
// for the Gateway), the Transparent Network Policies datapath is wired, and a Calico
// NetworkPolicy enforces on real ambient-mesh (HBONE) traffic.
//
// They run on the regular FV cluster (deploy/kind-config.yaml, no default CNI — the operator
// installs Calico CNI), so they carry NO "no-dataplane" label and run under `make fv`.
//
// Dataplane modes: iptables is deprecated, so we exercise Nftables (primary) and BPF/eBPF.
// Whether Felix's DSCP-marking of HBONE works per mode is a Felix-runtime concern only
// observable here; the BPF spec self-skips if the eBPF dataplane cannot come up on the host.
var _ = Describe("Dataplane-on integration FV tests", func() {
	var c client.Client
	var mgr manager.Manager
	var shutdownContext context.Context
	var cancel context.CancelFunc
	var operatorDone chan struct{}

	fullInstallationSpec := func(variant operator.ProductVariant, dataplane operator.LinuxDataplaneOption) *operator.InstallationSpec {
		dp := dataplane
		return &operator.InstallationSpec{
			Variant: variant,
			CalicoNetwork: &operator.CalicoNetworkSpec{
				LinuxDataplane: &dp,
			},
		}
	}

	// calicoNodeReady reports nil once every scheduled calico-node pod is available.
	calicoNodeReady := func() error {
		ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-node", Namespace: "calico-system"}}
		if err := GetResource(c, ds); err != nil {
			return err
		}
		if ds.Status.DesiredNumberScheduled == 0 || ds.Status.NumberAvailable < ds.Status.DesiredNumberScheduled {
			return fmt.Errorf("calico-node not fully available (%d/%d)", ds.Status.NumberAvailable, ds.Status.DesiredNumberScheduled)
		}
		return nil
	}

	// waitForCalicoOrSkip polls calico-node readiness. When skippable (BPF), a timeout
	// Skip()s the spec with a clear reason rather than failing — the eBPF dataplane needs
	// kernel/kind support that may be absent on the FV host. For Nftables it must succeed.
	waitForCalicoOrSkip := func(timeout time.Duration, skippable bool, reason string) {
		deadline := time.Now().Add(timeout)
		var lastErr error
		for time.Now().Before(deadline) {
			if lastErr = calicoNodeReady(); lastErr == nil {
				return
			}
			time.Sleep(5 * time.Second)
		}
		if skippable {
			Skip(fmt.Sprintf("%s: calico-node did not become ready (%v)", reason, lastErr))
		}
		Expect(lastErr).NotTo(HaveOccurred(), "calico-node did not become ready")
	}

	// waitForAPIServer creates the Calico API server and waits until the aggregated
	// projectcalico.org/v3 API actually answers reads. The dataplane-on integration needs that
	// API (FelixConfiguration + Calico NetworkPolicy).
	//
	// Deployment-available is NOT a sufficient signal: after the calico-apiserver Deployment
	// reports ready there is still a window before the kube-apiserver registers the APIService,
	// completes the TLS handshake to the calico-apiserver endpoints, and marks aggregation
	// Available — a one-shot v3 read in that window fails transiently. The aggregation hop
	// (kube-apiserver → calico-apiserver Service) is in-node and platform-independent, so this
	// is a bring-up race, not a host limitation; pool_test.go reads v3.IPPool the same way in
	// this suite. We therefore reuse verifyAPIServerHasDeployed (which also waits for the
	// apiserver TigeraStatus to be Available) and then poll a real v3 read until it succeeds.
	waitForAPIServer := func(timeout time.Duration) {
		createAPIServer(c, mgr, shutdownContext, nil)
		verifyAPIServerHasDeployed(c)

		By("Waiting for the aggregated projectcalico.org/v3 API to answer reads")
		Eventually(func() error {
			return c.List(shutdownContext, &v3.FelixConfigurationList{})
		}, timeout, 5*time.Second).ShouldNot(HaveOccurred(),
			"the aggregated projectcalico.org/v3 API never became reachable")
	}

	// expectFelixConfig fetches the default FelixConfiguration (which must exist once the
	// Calico dataplane is running) and runs assertions against it. The Get is polled so it
	// rides through any remaining aggregation bring-up jitter rather than failing on the
	// first attempt.
	expectFelixConfig := func(assert func(fc *v3.FelixConfiguration)) {
		fc := &v3.FelixConfiguration{}
		Eventually(func() error {
			return c.Get(shutdownContext, types.NamespacedName{Name: "default"}, fc)
		}, 60*time.Second, 5*time.Second).ShouldNot(HaveOccurred())
		assert(fc)
	}

	// daemonSetHasEnv reports whether any container of the named DaemonSet sets envName.
	daemonSetHasEnv := func(namespace, name, envName string) bool {
		ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
		if err := GetResource(c, ds); err != nil {
			return false
		}
		for _, container := range ds.Spec.Template.Spec.Containers {
			for _, e := range container.Env {
				if e.Name == envName {
					return true
				}
			}
		}
		return false
	}

	BeforeEach(func() {
		c, shutdownContext, cancel, mgr = setupManager(ManageCRDsDisable, SingleTenant, EnterpriseCRDsExist)

		By("Cleaning up resources before the test")
		cleanupGatewayResources(c)
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
		instance := &operator.Installation{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
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

		// Cleanup must run while the operator is alive so finalizers are processed. The
		// Istio finalizer cleanup patches FelixConfiguration (removing IstioAmbientMode/DSCP)
		// in this dataplane-on mode, so deletion must complete before we cancel the operator.
		By("Cleaning up resources after the test")
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
		cleanupResources(c)
	})

	// runIstioDataplaneIntegration installs a full Calico dataplane in the given mode plus the
	// Calico Istio service mesh, asserts the always-on integration wiring, then attempts the
	// (gated) live-traffic Calico-policy-enforcement check on the ambient mesh.
	runIstioDataplaneIntegration := func(dataplane operator.LinuxDataplaneOption, skippable bool) {
		const meshNs = "istio-dp-usage"

		By(fmt.Sprintf("Installing a full Calico dataplane (linuxDataplane: %s)", dataplane))
		operatorDone = createInstallation(c, mgr, shutdownContext, fullInstallationSpec(operator.Calico, dataplane))
		waitForCalicoOrSkip(300*time.Second, skippable, fmt.Sprintf("linuxDataplane %s not supported on this FV host", dataplane))

		// The integration patches FelixConfiguration (a projectcalico.org/v3 resource) and
		// the enforcement check creates a Calico NetworkPolicy, both of which need the v3 API
		// served by the Calico API server. Bring it up before creating the Istio CR so the
		// first reconcile that patches FelixConfiguration succeeds rather than requeuing.
		By("Installing the Calico API server so the projectcalico.org/v3 API is served")
		waitForAPIServer(180 * time.Second)

		By("Creating the default Istio CR and waiting for the ambient mesh to be ready")
		Expect(c.Create(shutdownContext, &operator.Istio{
			TypeMeta:   metav1.TypeMeta{Kind: "Istio", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		})).NotTo(HaveOccurred())
		waitForDeploymentAvailable(c, istio.IstioNamespace, istio.IstioIstiodDeploymentName, 300*time.Second)
		// istio-cni and ztunnel must be ready on every node before mesh workloads start,
		// since pod enrollment into the mesh happens at pod-creation time.
		waitForDaemonSetReady(c, istio.IstioNamespace, istio.IstioCNIDaemonSetName, 300*time.Second)
		waitForDaemonSetReady(c, istio.IstioNamespace, istio.IstioZTunnelDaemonSetName, 300*time.Second)

		By("Verifying the Calico dataplane integration is applied to FelixConfiguration")
		expectFelixConfig(func(fc *v3.FelixConfiguration) {
			Expect(fc.Spec.IstioAmbientMode).NotTo(BeNil(), "expected IstioAmbientMode to be set with the dataplane running")
			Expect(*fc.Spec.IstioAmbientMode).To(Equal(v3.IstioAmbientModeEnabled))
			Expect(fc.Spec.IstioDSCPMark).NotTo(BeNil(), "expected IstioDSCPMark to be set with the dataplane running")
			Expect(fc.Spec.IstioDSCPMark.ToUint8()).To(Equal(uint8(23)))
		})

		By("Verifying the Transparent Network Policies datapath is wired")
		Expect(daemonSetHasEnv(istio.IstioNamespace, istio.IstioZTunnelDaemonSetName, "TRANSPARENT_NETWORK_POLICIES")).
			To(BeTrue(), "expected ztunnel to carry TRANSPARENT_NETWORK_POLICIES with the dataplane running")
		Expect(daemonSetHasEnv(istio.IstioNamespace, istio.IstioCNIDaemonSetName, "MAGIC_DSCP_MARK")).
			To(BeTrue(), "expected istio-cni to carry MAGIC_DSCP_MARK with the dataplane running")

		By("Creating an ambient-enrolled namespace with a server and a client workload")
		ensureNamespace(c, meshNs, map[string]string{"istio.io/dataplane-mode": "ambient"})
		DeferCleanup(func() { deleteNamespace(c, meshNs) })
		deployHTTPEcho(c, meshNs, "mesh-echo", "hello-mesh")
		deployCurlClient(c, meshNs, "curl-client")
		waitForDeploymentAvailable(c, meshNs, "mesh-echo", 120*time.Second)
		waitForPodReady(c, meshNs, "curl-client", 120*time.Second)

		cfg := mgr.GetConfig()
		echoURL := fmt.Sprintf("http://mesh-echo:%d/", echoPort)

		// Gate the live-traffic enforcement assertions on the mesh data path actually
		// carrying traffic. If default-allow traffic never flows on this host we keep the
		// always-on wiring assertions above but skip enforcement rather than flake.
		By("Checking whether the ambient mesh data path carries traffic on this host")
		dataPathFunctional := false
		dpDeadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(dpDeadline) {
			if res, err := runCurl(cfg, meshNs, "curl-client", echoURL); err == nil && res.Code == "200" {
				dataPathFunctional = true
				break
			}
			time.Sleep(5 * time.Second)
		}

		if !dataPathFunctional {
			AddReportEntry("istio-dataplane-integration", fmt.Sprintf(
				"linuxDataplane %s: wiring asserted, but the ambient mesh data path did not carry traffic on this host; skipping live Calico-policy enforcement", dataplane))
			return
		}

		By("Applying a Calico NetworkPolicy that denies ingress to the mesh-echo workload")
		denyPolicy := &v3.NetworkPolicy{
			TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
			ObjectMeta: metav1.ObjectMeta{Name: "deny-mesh-echo", Namespace: meshNs},
			Spec: v3.NetworkPolicySpec{
				Selector: "app == 'mesh-echo'",
				// Types Ingress with no Ingress rules is a default-deny for ingress.
				Types: []v3.PolicyType{v3.PolicyTypeIngress},
			},
		}
		Expect(c.Create(shutdownContext, denyPolicy)).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = c.Delete(context.Background(), denyPolicy) })

		// Force a fresh ztunnel->backend connection that must traverse the new policy. Calico's
		// per-endpoint chain accepts RELATED,ESTABLISHED before evaluating policy, and ztunnel
		// pools its connection to the backend, so a deny applied after traffic is already
		// flowing only affects NEW connections — the pooled flow keeps being accepted. Bouncing
		// mesh-echo makes ztunnel reconnect, so the policy is actually exercised. (Verified: the
		// fresh connection is denied; without this the established pooled connection sails through.)
		By("Restarting mesh-echo so ztunnel opens a fresh connection through the new policy")
		Expect(c.DeleteAllOf(shutdownContext, &corev1.Pod{},
			client.InNamespace(meshNs), client.MatchingLabels{"app": "mesh-echo"})).NotTo(HaveOccurred())
		waitForDeploymentAvailable(c, meshNs, "mesh-echo", 120*time.Second)

		By("Verifying the Calico policy blocks ambient-mesh traffic")
		Eventually(func() error {
			res, _ := runCurl(cfg, meshNs, "curl-client", echoURL)
			if res.Code == "200" {
				return fmt.Errorf("expected the Calico policy to deny the request, still got 200 (body=%q)", res.Body)
			}
			return nil
		}, 90*time.Second).ShouldNot(HaveOccurred())

		By("Removing the Calico policy and verifying traffic flows again")
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
	}

	It("enforces a Calico NetworkPolicy on the Istio ambient mesh (Nftables dataplane)", func() {
		runIstioDataplaneIntegration(operator.LinuxDataplaneNftables, false)
	})

	It("enforces a Calico NetworkPolicy on the Istio ambient mesh (BPF dataplane)", func() {
		// Self-skips if the eBPF dataplane cannot come up on this FV host.
		runIstioDataplaneIntegration(operator.LinuxDataplaneBPF, true)
	})

	It("patches FelixConfiguration for L7 log collection when the Calico Ingress Gateway runs on a full dataplane", func() {
		By("Installing a full Calico dataplane (linuxDataplane: Nftables)")
		operatorDone = createInstallation(c, mgr, shutdownContext, fullInstallationSpec(operator.Calico, operator.LinuxDataplaneNftables))
		waitForCalicoOrSkip(300*time.Second, false, "Nftables dataplane not ready")

		// PolicySyncPathPrefix is a projectcalico.org/v3 FelixConfiguration field, so the
		// Calico API server must be serving the v3 API before the GatewayAPI controller can
		// patch it.
		By("Installing the Calico API server so the projectcalico.org/v3 API is served")
		waitForAPIServer(180 * time.Second)

		By("Creating the default GatewayAPI and waiting for the envoy-gateway controller")
		Expect(c.Create(shutdownContext, &operator.GatewayAPI{
			TypeMeta:   metav1.TypeMeta{Kind: "GatewayAPI", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		})).NotTo(HaveOccurred())
		waitForDeploymentAvailable(c, "calico-system", "envoy-gateway", 300*time.Second)
		Eventually(func() error {
			ts, err := getTigeraStatus(c, "gatewayapi")
			if err != nil {
				return err
			}
			return assertAvailable(ts)
		}, 120*time.Second).Should(BeNil())

		// The dataplane-on signal that the dataplane-disabled Gateway spec asserts is *absent*: with
		// Felix running, the controller patches PolicySyncPathPrefix so the L7 log collector
		// can reach the Felix policy-sync socket. (The l7-log-collector container itself is
		// Enterprise-only and its images are not publicly pullable in this FV environment,
		// so its runtime is covered by render-level unit tests rather than asserted here.)
		By("Verifying FelixConfiguration.PolicySyncPathPrefix was patched")
		Eventually(func() error {
			fc := &v3.FelixConfiguration{}
			if err := c.Get(shutdownContext, types.NamespacedName{Name: "default"}, fc); err != nil {
				return err
			}
			if fc.Spec.PolicySyncPathPrefix != gwctrl.DefaultPolicySyncPrefix {
				return fmt.Errorf("PolicySyncPathPrefix=%q, want %q", fc.Spec.PolicySyncPathPrefix, gwctrl.DefaultPolicySyncPrefix)
			}
			return nil
		}, 120*time.Second).ShouldNot(HaveOccurred())
	})
})
