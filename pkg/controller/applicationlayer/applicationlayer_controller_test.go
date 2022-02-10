// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package applicationlayer

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render/applicationlayer"
	"github.com/tigera/operator/test"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("Application layer controller tests", func() {
	var c client.Client
	var ctx context.Context
	var r ReconcileApplicationLayer
	var scheme *runtime.Scheme
	var mockStatus *status.MockStatus

	Context("image reconciliation", func() {
		BeforeEach(func() {
			// The schema contains all objects that should be known to the fake client when the test runs.
			scheme = runtime.NewScheme()
			Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
			Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
			// Create a client that will have a crud interface of k8s objects.
			c = fake.NewClientBuilder().WithScheme(scheme).Build()
			ctx = context.Background()

			mockStatus = &status.MockStatus{}
			mockStatus.On("AddDaemonsets", mock.Anything).Return()
			mockStatus.On("AddDeployments", mock.Anything).Return()
			mockStatus.On("IsAvailable").Return(true)
			mockStatus.On("AddStatefulSets", mock.Anything).Return()
			mockStatus.On("AddCronJobs", mock.Anything)
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("OnCRNotFound").Return()
			mockStatus.On("ClearDegraded")
			mockStatus.On("SetDegraded", "Waiting for LicenseKeyAPI to be ready", "").Return().Maybe()
			mockStatus.On("ReadyToMonitor")

			r = ReconcileApplicationLayer{
				client:          c,
				scheme:          scheme,
				provider:        operatorv1.ProviderNone,
				status:          mockStatus,
				licenseAPIReady: &utils.ReadyFlag{},
			}

			Expect(c.Create(ctx, &operatorv1.Installation{
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
			})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &crdv1.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: crdv1.FelixConfigurationSpec{
					TPROXYMode: nil,
				},
			})).NotTo(HaveOccurred())

			// Mark that the watch for license key was successful.
			r.licenseAPIReady.MarkAsReady()
		})

		It("should render accurate resources for for log collection", func() {

			By("applying the ApplicationLayer CR to the fake cluster")
			enabled := operatorv1.L7LogCollectionEnabled
			Expect(c.Create(ctx, &operatorv1.ApplicationLayer{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.ApplicationLayerSpec{
					LogCollection: &operatorv1.LogCollectionSpec{
						CollectLogs: &enabled,
					},
				},
			})).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			ds := appsv1.DaemonSet{
				TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      applicationlayer.L7LogCollectorDeamonsetName,
					Namespace: common.CalicoNamespace,
				},
			}
			By("ensuring that log collection resources created properly")
			Expect(test.GetResource(c, &ds)).To(BeNil())
			Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(2))

			proxy := ds.Spec.Template.Spec.Containers[0]
			Expect(proxy).ToNot(BeNil())
			Expect(proxy.Image).To(Equal(fmt.Sprintf("some.registry.org/%s:%s",
				components.ComponentEnvoyProxy.Image, components.ComponentEnvoyProxy.Version)))

			l7collector := ds.Spec.Template.Spec.Containers[1]
			Expect(l7collector).ToNot(BeNil())
			Expect(l7collector.Image).To(Equal(fmt.Sprintf("some.registry.org/%s:%s",
				components.ComponentL7Collector.Image, components.ComponentL7Collector.Version)))

			By("ensuring that felix configuration updated to enabled")
			fc := crdv1.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
			}
			Expect(test.GetResource(c, &fc)).To(BeNil())
			Expect(*fc.Spec.TPROXYMode).To(Equal(crdv1.TPROXYModeOptionEnabled))

			By("deleting that ApplicationLayer CR")
			Expect(c.Delete(ctx, &operatorv1.ApplicationLayer{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			})).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			By("ensuring that felix configuration updated to disabled")
			Expect(test.GetResource(c, &fc)).To(BeNil())
			Expect(*fc.Spec.TPROXYMode).To(Equal(crdv1.TPROXYModeOptionDisabled))
		})

	})
})
