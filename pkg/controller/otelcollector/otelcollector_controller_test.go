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

package otelcollector

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/otelcollector"
	"github.com/tigera/operator/test"
)

var _ = Describe("OpenTelemetry controller tests", func() {
	var (
		cli             client.Client
		scheme          *runtime.Scheme
		ctx             context.Context
		mockStatus      *status.MockStatus
		r               *Reconciler
		install         *operatorv1.Installation
		licenseAPIReady *utils.ReadyFlag
		tierWatchReady  *utils.ReadyFlag
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		replicas := int32(2)
		install = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Generation: 2},
			Status: operatorv1.InstallationStatus{
				Variant:  operatorv1.CalicoEnterprise,
				Computed: &operatorv1.InstallationSpec{},
			},
			Spec: operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				Variant:              operatorv1.CalicoEnterprise,
				Registry:             "some.registry.org/",
			},
		}
		Expect(cli.Create(ctx, install)).ToNot(HaveOccurred())

		Expect(cli.Create(ctx, &v3.LicenseKey{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Status: v3.LicenseKeyStatus{
				Features: []string{common.OpenTelemetryCollectorFeature},
			},
		})).ToNot(HaveOccurred())

		// Create a CA secret so the certificate manager can issue keypairs.
		cm, err := certificatemanager.Create(cli, &install.Spec, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, cm.KeyPair().Secret(common.OperatorNamespace()))).ShouldNot(HaveOccurred())

		// Create the calico-system tier so the controller's tier check passes.
		Expect(cli.Create(ctx, &v3.Tier{
			ObjectMeta: metav1.ObjectMeta{Name: networkpolicy.CalicoTierName},
		})).ToNot(HaveOccurred())

		Expect(cli.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Status:     operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady},
		})).ToNot(HaveOccurred())

		licenseAPIReady = &utils.ReadyFlag{}
		licenseAPIReady.MarkAsReady()
		tierWatchReady = &utils.ReadyFlag{}
		tierWatchReady.MarkAsReady()

		mockStatus = &status.MockStatus{}
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
		// Teardown path (feature disabled / license expired) stops monitoring the
		// workload it just removed.
		mockStatus.On("RemoveStatefulSets", mock.Anything).Return().Maybe()
		mockStatus.On("RemoveDeployments", mock.Anything).Return().Maybe()
		mockStatus.On("RemoveDaemonsets", mock.Anything).Return().Maybe()
		mockStatus.On("AddCertificateSigningRequests", mock.Anything).Return()
		mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("OnCRNotFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()
		mockStatus.On("SetDegraded", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("ClearWarning", mock.AnythingOfType("string")).Return().Maybe()

		r = &Reconciler{
			cli:             cli,
			scheme:          scheme,
			status:          mockStatus,
			licenseAPIReady: licenseAPIReady,
			tierWatchReady:  tierWatchReady,
			opts: options.ControllerOptions{
				DetectedProvider: operatorv1.ProviderNone,
				Variant:          operatorv1.CalicoEnterprise,
				ClusterDomain:    dns.DefaultClusterDomain,
			},
		}
	})

	Context("CR not found", func() {
		It("should call OnCRNotFound and return without error", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "OnCRNotFound")
		})
	})

	Context("LogCollector without OpenTelemetry", func() {
		BeforeEach(func() {
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec:       operatorv1.LogCollectorSpec{},
			})).ToNot(HaveOccurred())
		})

		It("should call OnCRNotFound when OpenTelemetry is nil", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "OnCRNotFound")
		})
	})

	Context("happy path", func() {
		BeforeEach(func() {
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Logs:      &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
						Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
					},
				},
			})).ToNot(HaveOccurred())
		})

		It("should reconcile and create resources", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			mockStatus.AssertCalled(GinkgoT(), "OnCRFound")
			mockStatus.AssertCalled(GinkgoT(), "ReadyToMonitor")
			mockStatus.AssertCalled(GinkgoT(), "ClearDegraded")

			ss := appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector", Namespace: "calico-system"}}
			Expect(test.GetResource(cli, &ss)).To(BeNil())
			Expect(ss.Spec.Template.Spec.Containers).To(HaveLen(1))
		})
	})

	Context("feature switched off after being enabled", func() {
		It("should remove the collector's resources rather than orphaning them", func() {
			lc := &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Logs:      &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
						Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
					},
				},
			}
			Expect(cli.Create(ctx, lc)).ToNot(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			ss := appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector", Namespace: "calico-system"}}
			Expect(test.GetResource(cli, &ss)).To(BeNil(), "collector should exist while enabled")

			// Turn it off. Nothing owns these resources, so without an explicit
			// teardown they would linger indefinitely.
			Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-secure"}, lc)).ToNot(HaveOccurred())
			lc.Spec.OpenTelemetry = nil
			Expect(cli.Update(ctx, lc)).ToNot(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(test.GetResource(cli, &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector", Namespace: "calico-system"}})).ToNot(BeNil(), "StatefulSet should be gone")
			Expect(test.GetResource(cli, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector", Namespace: "calico-system"}})).ToNot(BeNil(), "Service should be gone")
			Expect(test.GetResource(cli, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector", Namespace: "calico-system"}})).ToNot(BeNil(), "ConfigMap should be gone")
			Expect(test.GetResource(cli, &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector"}})).ToNot(BeNil(), "ClusterRole should be gone")
		})
	})

	DescribeTable("license states that must stop forwarding",
		// The degraded message claims forwarding has stopped; these paths make that
		// true rather than leaving the collector running and exporting.
		func(mutate func()) {
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Logs:      &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
						Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
					},
				},
			})).ToNot(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(test.GetResource(cli, &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector", Namespace: "calico-system"}})).To(BeNil())

			mutate()
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(test.GetResource(cli, &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "otel-collector", Namespace: "calico-system"}})).ToNot(BeNil(), "collector should be removed")
		},
		Entry("license loses the OpenTelemetry feature", func() {
			lk := &v3.LicenseKey{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: "default"}, lk)).ToNot(HaveOccurred())
			lk.Status.Features = []string{"some-other-feature"}
			Expect(cli.Update(ctx, lk)).ToNot(HaveOccurred())
		}),
	)

	Context("spec the collector cannot start from", func() {
		// otelcol validates both of these at boot (service/pipelines/config.go),
		// so without a pre-render check the pod crash-loops with no diagnostic.
		DescribeTable("should degrade instead of rendering an invalid config",
			func(spec *operatorv1.OpenTelemetrySpec) {
				Expect(cli.Create(ctx, &operatorv1.LogCollector{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
					Spec:       operatorv1.LogCollectorSpec{OpenTelemetry: spec},
				})).ToNot(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operatorv1.ResourceValidationError, "Invalid OpenTelemetry configuration", mock.Anything, mock.Anything)
			},
			Entry("no exporters, so every pipeline would be exporter-less", &operatorv1.OpenTelemetrySpec{
				Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
			}),
			Entry("no data sources, so there would be no pipelines at all", &operatorv1.OpenTelemetrySpec{
				Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
			}),
			Entry("duplicate exporter names, which would emit the same config key twice", &operatorv1.OpenTelemetrySpec{
				Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
				Exporters: []operatorv1.OpenTelemetryExporter{
					{Name: "backend", Endpoint: "otlp.example.com:4317"},
					{Name: "backend", Endpoint: "other.example.com:4317"},
				},
			}),
		)
	})

	Context("exporter TLS material present but unusable", func() {
		// Rendering a path the mount never materialises makes the collector fail
		// to load it at startup, which is an opaque crash-loop.
		It("should degrade when the exporter CA ConfigMap has no certificate", func() {
			Expect(cli.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      otelcollector.OpenTelemetryCollectorCAConfigMapName,
					Namespace: common.OperatorNamespace(),
				},
			})).ToNot(HaveOccurred())
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Logs:      &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
						Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
					},
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operatorv1.ResourceValidationError, mock.AnythingOfType("string"), mock.Anything, mock.Anything)
		})

		It("should degrade when the client keypair Secret is missing its key", func() {
			Expect(cli.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      otelcollector.OpenTelemetryCollectorClientTLSSecretName,
					Namespace: common.OperatorNamespace(),
				},
				Data: map[string][]byte{corev1.TLSCertKey: []byte("cert")},
			})).ToNot(HaveOccurred())
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
						Exporters: []operatorv1.OpenTelemetryExporter{
							{Name: "backend", Endpoint: "otlp.example.com:4317", MutualTLS: ptr.To(true)},
						},
					},
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operatorv1.ResourceValidationError, mock.AnythingOfType("string"), mock.Anything, mock.Anything)
		})
	})

	Context("mutual TLS without the client keypair", func() {
		BeforeEach(func() {
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Logs: &operatorv1.OpenTelemetryLogs{Types: []operatorv1.OpenTelemetryLogType{operatorv1.OpenTelemetryFlowLog}},
						Exporters: []operatorv1.OpenTelemetryExporter{
							{Name: "backend", Endpoint: "otlp.example.com:4317", MutualTLS: ptr.To(true)},
						},
					},
				},
			})).ToNot(HaveOccurred())
		})

		It("should degrade rather than render a config the collector cannot honour", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operatorv1.ResourceReadError, mock.AnythingOfType("string"), mock.Anything, mock.Anything)
		})
	})

	Context("license missing", func() {
		BeforeEach(func() {
			Expect(cli.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).ToNot(HaveOccurred())
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
					},
				},
			})).ToNot(HaveOccurred())
		})

		It("should set degraded status", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operatorv1.ResourceNotFound, mock.AnythingOfType("string"), mock.Anything, mock.Anything)
		})
	})

	Context("license feature inactive", func() {
		BeforeEach(func() {
			Expect(cli.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).ToNot(HaveOccurred())
			Expect(cli.Create(ctx, &v3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Status: v3.LicenseKeyStatus{
					Features: []string{"some-other-feature"},
				},
			})).ToNot(HaveOccurred())

			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
					},
				},
			})).ToNot(HaveOccurred())
		})

		It("should set degraded status for inactive feature", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operatorv1.ResourceValidationError, mock.AnythingOfType("string"), mock.Anything, mock.Anything)
		})
	})

	Context("installation missing", func() {
		BeforeEach(func() {
			Expect(cli.Delete(ctx, &operatorv1.Installation{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).ToNot(HaveOccurred())
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OpenTelemetry: &operatorv1.OpenTelemetrySpec{
						Exporters: []operatorv1.OpenTelemetryExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
					},
				},
			})).ToNot(HaveOccurred())
		})

		It("should return error when installation is missing", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
		})
	})
})
