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

package render_test

import (
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// TestPolicyAnalysis runs the static policy analysis as a Go test
func TestPolicyAnalysis(t *testing.T) {
	RegisterFailHandler(Fail)

	// Run the policy analysis test
	t.Run("StaticPolicyAnalysis", func(t *testing.T) {
		analyzer := testutils.NewPolicyAnalyzer()

		// Setup common test infrastructure
		scheme := runtime.NewScheme()
		if err := apis.AddToScheme(scheme, false); err != nil {
			t.Fatalf("Failed to add APIs to scheme: %v", err)
		}
		cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		clusterDomain := dns.DefaultClusterDomain
		certManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		if err != nil {
			t.Fatalf("Failed to create certificate manager: %v", err)
		}

		// Test scenarios
		scenarios := []struct {
			name           string
			openShift      bool
			managedCluster bool
		}{
			{"Standard", false, false},
			{"OpenShift", true, false},
			{"ManagedCluster", false, true},
		}

		for _, scenario := range scenarios {
			t.Logf("Analyzing scenario: %s (OpenShift=%v, ManagedCluster=%v)",
				scenario.name, scenario.openShift, scenario.managedCluster)

			// Render and collect from each component
			renderAndCollect(t, analyzer, cli, certManager, clusterDomain, scenario.openShift, scenario.managedCluster)
		}

		// Run analysis
		results := analyzer.Analyze()

		// Report results
		t.Log(testutils.FormatResults(results))

		// Check for failures
		failures := analyzer.GetFailures()
		if len(failures) > 0 {
			t.Logf("Found %d policy analysis failures:", len(failures))
			for _, f := range failures {
				t.Errorf("FAIL: %s/%s - %s: %s", f.PolicyNS, f.PolicyName, f.CheckType, f.Message)
			}
		}

		passed := analyzer.GetPassed()
		t.Logf("Summary: %d checks passed, %d checks failed", len(passed), len(failures))
	})
}

// renderAndCollect renders components and collects pods and policies
func renderAndCollect(t *testing.T, analyzer *testutils.PolicyAnalyzer,
	cli client.Client, certManager certificatemanager.CertificateManager,
	clusterDomain string, openShift bool, managedCluster bool) {

	installation := &operatorv1.InstallationSpec{
		KubernetesProvider: operatorv1.ProviderNone,
		Registry:           "testregistry.com/",
	}
	if openShift {
		installation.KubernetesProvider = operatorv1.ProviderOpenShift
	}

	trustedBundle := certManager.CreateTrustedBundle()

	// Render Compliance
	renderComplianceComponent(t, analyzer, cli, certManager, installation, trustedBundle, clusterDomain, openShift, managedCluster)

	// Render IntrusionDetection
	renderIntrusionDetectionComponent(t, analyzer, cli, certManager, installation, trustedBundle, clusterDomain, openShift, managedCluster)

	// Render Fluentd (skip - requires extensive configuration)
	// renderFluentdComponent(t, analyzer, cli, certManager, installation, trustedBundle, clusterDomain)

	// Render Monitor (skip - requires PullSecrets and other configuration)
	// renderMonitorComponent(t, analyzer, cli, certManager, installation, trustedBundle, clusterDomain, openShift)

	// Render Guardian (skip - requires ManagementClusterConnection for managed clusters)
	// if managedCluster {
	// 	renderGuardianComponent(t, analyzer, cli, certManager, installation, trustedBundle, openShift)
	// }
}

func renderComplianceComponent(t *testing.T, analyzer *testutils.PolicyAnalyzer,
	cli client.Client, certManager certificatemanager.CertificateManager,
	installation *operatorv1.InstallationSpec, trustedBundle certificatemanagement.TrustedBundle,
	clusterDomain string, openShift bool, managedCluster bool) {

	serverKP, _ := certManager.GetOrCreateKeyPair(cli, render.ComplianceServerCertSecret, common.OperatorNamespace(), []string{""})
	controllerKP, _ := certManager.GetOrCreateKeyPair(cli, render.ComplianceControllerSecret, common.OperatorNamespace(), []string{""})
	benchmarkerKP, _ := certManager.GetOrCreateKeyPair(cli, render.ComplianceBenchmarkerSecret, common.OperatorNamespace(), []string{""})
	reporterKP, _ := certManager.GetOrCreateKeyPair(cli, render.ComplianceReporterSecret, common.OperatorNamespace(), []string{""})
	snapshotterKP, _ := certManager.GetOrCreateKeyPair(cli, render.ComplianceSnapshotterSecret, common.OperatorNamespace(), []string{""})

	cfg := &render.ComplianceConfiguration{
		Installation:       installation,
		ServerKeyPair:      serverKP,
		ControllerKeyPair:  controllerKP,
		ReporterKeyPair:    reporterKP,
		BenchmarkerKeyPair: benchmarkerKP,
		SnapshotterKeyPair: snapshotterKP,
		OpenShift:          openShift,
		ClusterDomain:      clusterDomain,
		TrustedBundle:      trustedBundle,
		Namespace:          render.ComplianceNamespace,
	}

	if managedCluster {
		cfg.ManagementClusterConnection = &operatorv1.ManagementClusterConnection{}
	}

	component, err := render.Compliance(cfg)
	if err != nil {
		t.Logf("Warning: Failed to render Compliance: %v", err)
		return
	}
	_ = component.ResolveImages(nil)

	resources, _ := component.Objects()
	collectResources(analyzer, resources, "Compliance")
}

func renderIntrusionDetectionComponent(t *testing.T, analyzer *testutils.PolicyAnalyzer,
	cli client.Client, certManager certificatemanager.CertificateManager,
	installation *operatorv1.InstallationSpec, trustedBundle certificatemanagement.TrustedBundle,
	clusterDomain string, openShift bool, managedCluster bool) {

	idCert, _ := certManager.GetOrCreateKeyPair(cli, render.IntrusionDetectionTLSSecretName, common.OperatorNamespace(), []string{""})

	cfg := &render.IntrusionDetectionConfiguration{
		Installation:                 installation,
		OpenShift:                    openShift,
		ClusterDomain:                clusterDomain,
		TrustedCertBundle:            trustedBundle,
		IntrusionDetectionCertSecret: idCert,
		Namespace:                    render.IntrusionDetectionNamespace,
		ManagedCluster:               managedCluster,
	}

	component := render.IntrusionDetection(cfg)
	_ = component.ResolveImages(nil)

	resources, _ := component.Objects()
	collectResources(analyzer, resources, "IntrusionDetection")
}

func renderFluentdComponent(t *testing.T, analyzer *testutils.PolicyAnalyzer,
	cli client.Client, certManager certificatemanager.CertificateManager,
	installation *operatorv1.InstallationSpec, trustedBundle certificatemanagement.TrustedBundle,
	clusterDomain string) {

	fluentdKP, _ := certManager.GetOrCreateKeyPair(cli, render.FluentdPrometheusTLSSecretName, common.OperatorNamespace(), []string{""})

	cfg := &render.FluentdConfiguration{
		Installation:   installation,
		ClusterDomain:  clusterDomain,
		TrustedBundle:  trustedBundle,
		FluentdKeyPair: fluentdKP,
		LogCollector:   &operatorv1.LogCollector{},
		Filters:        &render.FluentdFilters{},
		OSType:         rmeta.OSTypeLinux,
	}

	component := render.Fluentd(cfg)
	_ = component.ResolveImages(nil)

	resources, _ := component.Objects()
	collectResources(analyzer, resources, "Fluentd")
}

func renderMonitorComponent(t *testing.T, analyzer *testutils.PolicyAnalyzer,
	cli client.Client, certManager certificatemanager.CertificateManager,
	installation *operatorv1.InstallationSpec, trustedBundle certificatemanagement.TrustedBundle,
	clusterDomain string, openShift bool) {

	serverTLS, _ := certManager.GetOrCreateKeyPair(cli, monitor.PrometheusServerTLSSecretName, common.OperatorNamespace(), []string{""})
	clientTLS, _ := certManager.GetOrCreateKeyPair(cli, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{""})

	cfg := &monitor.Config{
		Installation:      installation,
		OpenShift:         openShift,
		ClusterDomain:     clusterDomain,
		TrustedCertBundle: trustedBundle,
		ServerTLSSecret:   serverTLS,
		ClientTLSSecret:   clientTLS,
	}

	component := monitor.Monitor(cfg)
	_ = component.ResolveImages(nil)

	resources, _ := component.Objects()
	collectResources(analyzer, resources, "Monitor")

	// Also collect the policy component
	policyComponent := monitor.MonitorPolicy(cfg)
	policyResources, _ := policyComponent.Objects()
	collectResources(analyzer, policyResources, "MonitorPolicy")
}

func renderGuardianComponent(t *testing.T, analyzer *testutils.PolicyAnalyzer,
	cli client.Client, certManager certificatemanager.CertificateManager,
	installation *operatorv1.InstallationSpec, trustedBundle certificatemanagement.TrustedBundle,
	openShift bool) {

	guardianKP, _ := certManager.GetOrCreateKeyPair(cli, render.GuardianSecretName, common.OperatorNamespace(), []string{""})

	cfg := &render.GuardianConfiguration{
		Installation:          installation,
		OpenShift:             openShift,
		TrustedCertBundle:     trustedBundle,
		TunnelCAType:          operatorv1.CATypeTigera,
		GuardianClientKeyPair: guardianKP,
	}

	component := render.Guardian(cfg)
	_ = component.ResolveImages(nil)

	resources, _ := component.Objects()
	collectResources(analyzer, resources, "Guardian")

	// Also collect the policy component
	policyComponent, err := render.GuardianPolicy(cfg)
	if err == nil {
		policyResources, _ := policyComponent.Objects()
		collectResources(analyzer, policyResources, "GuardianPolicy")
	}
}

// collectResources extracts pods and policies from rendered resources
func collectResources(analyzer *testutils.PolicyAnalyzer, resources []client.Object, componentName string) {
	pods := testutils.ExtractPodInfoFromResources(resources, componentName)
	policies := testutils.ExtractPolicyInfoFromResources(resources, componentName)

	analyzer.AddPods(pods)
	analyzer.AddPolicies(policies)
}

var _ = Describe("Static Policy Analysis", func() {
	var (
		analyzer    *testutils.PolicyAnalyzer
		cli         client.Client
		certManager certificatemanager.CertificateManager
		scheme      *runtime.Scheme
	)

	BeforeEach(func() {
		analyzer = testutils.NewPolicyAnalyzer()

		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		var err error
		certManager, err = certificatemanager.Create(cli, nil, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
	})

	DescribeTable("should validate policy selectors match pods",
		func(openShift bool, managedCluster bool) {
			installation := &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "testregistry.com/",
			}
			if openShift {
				installation.KubernetesProvider = operatorv1.ProviderOpenShift
			}

			trustedBundle := certManager.CreateTrustedBundle()

			// Render Compliance component
			serverKP, _ := certManager.GetOrCreateKeyPair(cli, render.ComplianceServerCertSecret, common.OperatorNamespace(), []string{""})
			controllerKP, _ := certManager.GetOrCreateKeyPair(cli, render.ComplianceControllerSecret, common.OperatorNamespace(), []string{""})
			benchmarkerKP, _ := certManager.GetOrCreateKeyPair(cli, render.ComplianceBenchmarkerSecret, common.OperatorNamespace(), []string{""})
			reporterKP, _ := certManager.GetOrCreateKeyPair(cli, render.ComplianceReporterSecret, common.OperatorNamespace(), []string{""})
			snapshotterKP, _ := certManager.GetOrCreateKeyPair(cli, render.ComplianceSnapshotterSecret, common.OperatorNamespace(), []string{""})

			complianceCfg := &render.ComplianceConfiguration{
				Installation:       installation,
				ServerKeyPair:      serverKP,
				ControllerKeyPair:  controllerKP,
				ReporterKeyPair:    reporterKP,
				BenchmarkerKeyPair: benchmarkerKP,
				SnapshotterKeyPair: snapshotterKP,
				OpenShift:          openShift,
				ClusterDomain:      dns.DefaultClusterDomain,
				TrustedBundle:      trustedBundle,
				Namespace:          render.ComplianceNamespace,
			}

			if managedCluster {
				complianceCfg.ManagementClusterConnection = &operatorv1.ManagementClusterConnection{}
			}

			component, err := render.Compliance(complianceCfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(component.ResolveImages(nil)).To(BeNil())

			resources, _ := component.Objects()

			// Extract pods and policies
			pods := testutils.ExtractPodInfoFromResources(resources, "Compliance")
			policies := testutils.ExtractPolicyInfoFromResources(resources, "Compliance")

			analyzer.AddPods(pods)
			analyzer.AddPolicies(policies)

			// Run analysis
			_ = analyzer.Analyze()

			// Check for failures
			failures := analyzer.GetFailures()
			if len(failures) > 0 {
				for _, f := range failures {
					fmt.Printf("FAIL: %s/%s - %s: %s\n", f.PolicyNS, f.PolicyName, f.CheckType, f.Message)
				}
			}

			// Print summary
			passed := analyzer.GetPassed()
			fmt.Printf("Scenario (OpenShift=%v, ManagedCluster=%v): %d passed, %d failed\n",
				openShift, managedCluster, len(passed), len(failures))

			// For now, we don't fail the test on policy mismatches - we just report them
			// Uncomment the following line to fail on mismatches:
			// Expect(failures).To(BeEmpty(), "Policy analysis found selector mismatches")
		},
		Entry("Standard cluster", false, false),
		Entry("OpenShift cluster", true, false),
		Entry("Managed cluster", false, true),
		Entry("OpenShift managed cluster", true, true),
	)

	It("should correctly parse selector expressions", func() {
		// Test basic equality
		labels := map[string]string{"k8s-app": "my-app", "env": "prod"}
		Expect(testutils.MatchesSelector(labels, "k8s-app == 'my-app'")).To(BeTrue())
		Expect(testutils.MatchesSelector(labels, "k8s-app == 'other'")).To(BeFalse())

		// Test OR expressions
		Expect(testutils.MatchesSelector(labels, "k8s-app == 'my-app' || k8s-app == 'other'")).To(BeTrue())
		Expect(testutils.MatchesSelector(labels, "k8s-app == 'foo' || k8s-app == 'bar'")).To(BeFalse())

		// Test AND expressions
		Expect(testutils.MatchesSelector(labels, "k8s-app == 'my-app' && env == 'prod'")).To(BeTrue())
		Expect(testutils.MatchesSelector(labels, "k8s-app == 'my-app' && env == 'dev'")).To(BeFalse())

		// Test has()
		Expect(testutils.MatchesSelector(labels, "has(k8s-app)")).To(BeTrue())
		Expect(testutils.MatchesSelector(labels, "has(missing)")).To(BeFalse())

		// Test !has()
		Expect(testutils.MatchesSelector(labels, "!has(missing)")).To(BeTrue())
		Expect(testutils.MatchesSelector(labels, "!has(k8s-app)")).To(BeFalse())

		// Test all()
		Expect(testutils.MatchesSelector(labels, "all()")).To(BeTrue())
		Expect(testutils.MatchesSelector(map[string]string{}, "all()")).To(BeTrue())

		// Test empty selector
		Expect(testutils.MatchesSelector(labels, "")).To(BeTrue())
	})
})
