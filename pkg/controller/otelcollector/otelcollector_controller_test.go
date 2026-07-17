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
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/test"
)

var _ = Describe("OTelCollector controller tests", func() {
	var (
		cli        client.Client
		scheme     *runtime.Scheme
		ctx        context.Context
		mockStatus *status.MockStatus
		r          *Reconciler
		install    *operatorv1.Installation
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
				Features: []string{common.OTelCollectorFeature},
			},
		})).ToNot(HaveOccurred())

		// Create a CA secret so the certificate manager can issue keypairs.
		cm, err := certificatemanager.Create(cli, &install.Spec, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, cm.KeyPair().Secret(common.OperatorNamespace()))).ShouldNot(HaveOccurred())

		mockStatus = &status.MockStatus{}
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
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
			cli:    cli,
			scheme: scheme,
			status: mockStatus,
			opts: options.ControllerOptions{
				DetectedProvider:    operatorv1.ProviderNone,
				EnterpriseCRDExists: true,
				ClusterDomain:       dns.DefaultClusterDomain,
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

	Context("LogCollector without OTelCollector", func() {
		BeforeEach(func() {
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec:       operatorv1.LogCollectorSpec{},
			})).ToNot(HaveOccurred())
		})

		It("should call OnCRNotFound when OTelCollector is nil", func() {
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
					OTelCollector: &operatorv1.OTelCollectorSpec{
						Logs:      &operatorv1.OTelLogs{Types: []operatorv1.OTelLogType{operatorv1.OTelFlowLog}},
						Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
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

	Context("license missing", func() {
		BeforeEach(func() {
			Expect(cli.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).ToNot(HaveOccurred())
			Expect(cli.Create(ctx, &operatorv1.LogCollector{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.LogCollectorSpec{
					OTelCollector: &operatorv1.OTelCollectorSpec{
						Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
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
					OTelCollector: &operatorv1.OTelCollectorSpec{
						Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
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
					OTelCollector: &operatorv1.OTelCollectorSpec{
						Exporters: []operatorv1.OTelExporter{{Name: "backend", Endpoint: "otlp.example.com:4317"}},
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
