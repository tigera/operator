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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"github.com/stretchr/testify/mock"

	admregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
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
		mockStatus.On("SetDegraded", "Waiting for LicenseKeyAPI to be ready", "").Return().Maybe()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()

		r = &ReconcileGatewayAPI{
			client: c,
			scheme: scheme,
			status: mockStatus,
		}
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
