// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

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

package initializer

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"
)

func NewTestInitializer(
	cli client.Client,
	scheme *runtime.Scheme,
	status status.StatusManager,
	provider operatorv1.Provider,
	clusterDomain string,
) (*LogStorageInitializer, error) {
	opts := options.AddOptions{
		DetectedProvider: provider,
		ClusterDomain:    clusterDomain,
		ShutdownContext:  context.TODO(),
	}

	r := &LogStorageInitializer{
		client:      cli,
		scheme:      scheme,
		status:      status,
		provider:    opts.DetectedProvider,
		multiTenant: opts.MultiTenant,
	}
	r.status.Run(opts.ShutdownContext)
	return r, nil
}

var _ = Describe("LogStorage Initializing controller", func() {
	var (
		cli        client.Client
		mockStatus *status.MockStatus
		readyFlag  *utils.ReadyFlag
		scheme     *runtime.Scheme
		ctx        context.Context
		install    *operatorv1.Installation
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(admissionv1beta1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()

		readyFlag = &utils.ReadyFlag{}
		readyFlag.MarkAsReady()
	})

	Context("LogStorage is nil", func() {
		BeforeEach(func() {
			// Create a basic Installation.
			var replicas int32 = 2
			install = &operatorv1.Installation{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Status: operatorv1.InstallationStatus{
					Variant:  operatorv1.TigeraSecureEnterprise,
					Computed: &operatorv1.InstallationSpec{},
				},
				Spec: operatorv1.InstallationSpec{
					ControlPlaneReplicas: &replicas,
					Variant:              operatorv1.TigeraSecureEnterprise,
				},
			}
			Expect(cli.Create(ctx, install)).ShouldNot(HaveOccurred())

			mockStatus = &status.MockStatus{}
			mockStatus.On("Run")
			mockStatus.On("OnCRFound")
			mockStatus.On("SetMetaData", mock.Anything)
			mockStatus.On("ReadyToMonitor")
			mockStatus.On("ClearDegraded")
			mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			mockStatus.On("OnCRNotFound")
		})

		It("fills defaults on an empty LogStorage", func() {
			// Create a LogStorage with no fields set.
			ls := &operatorv1.LogStorage{}
			ls.Name = "tigera-secure"
			Expect(cli.Create(ctx, ls)).ShouldNot(HaveOccurred())

			// Run the reconciler. It should fill in defaults.
			r, err := NewTestInitializer(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
			Expect(err).ShouldNot(HaveOccurred())
			r.Reconcile(ctx, reconcile.Request{})

			// Expect the LogStorage to be updated with defaults.
			ls = &operatorv1.LogStorage{}
			expected := &operatorv1.LogStorage{}
			FillDefaults(expected)
			Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-secure"}, ls)).ShouldNot(HaveOccurred())
			Expect(ls.Spec).Should(Equal(expected.Spec))
			Expect(ls.Status.State).Should(Equal(operatorv1.TigeraStatusReady))
		})

		It("sets a degraded status when an invalid LogStorage is given", func() {
			// Create a LogStorage instance with invalid fields. Specifically, one with
			// component resources that are not valid.
			ls := &operatorv1.LogStorage{}
			ls.Name = "tigera-secure"
			FillDefaults(ls)
			ls.Spec.ComponentResources[0].ComponentName = "invalid"
			Expect(cli.Create(ctx, ls)).ShouldNot(HaveOccurred())

			// Run the reconciler. Expect an error and a degraded status.
			r, err := NewTestInitializer(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
			Expect(err).ShouldNot(HaveOccurred())
			r.Reconcile(ctx, reconcile.Request{})
			Expect(mockStatus.AssertNumberOfCalls(GinkgoT(), "SetDegraded", 1)).Should(BeTrue())

			// Get the LogStorage and expect the degraded status to be set.
			ls = &operatorv1.LogStorage{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-secure"}, ls)).ShouldNot(HaveOccurred())
			Expect(ls.Status.State).Should(Equal(operatorv1.TigeraStatusDegraded))

			// Fixing the invalid field should clear the degraded status.
			ls.Spec.ComponentResources[0].ComponentName = "ECKOperator"
			Expect(cli.Update(ctx, ls)).ShouldNot(HaveOccurred())
			r.Reconcile(ctx, reconcile.Request{})

			// Get the LogStorage and expect the degraded status to be cleared.
			ls = &operatorv1.LogStorage{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-secure"}, ls)).ShouldNot(HaveOccurred())
			Expect(ls.Status.State).Should(Equal(operatorv1.TigeraStatusReady))
		})

		It("handles LogStorage deletion", func() {
			// Create a LogStorage instance.
			ls := &operatorv1.LogStorage{}
			ls.Name = "tigera-secure"
			Expect(cli.Create(ctx, ls)).ShouldNot(HaveOccurred())

			// Run the reconciler and expect an OK status.
			r, err := NewTestInitializer(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
			Expect(err).ShouldNot(HaveOccurred())
			r.Reconcile(ctx, reconcile.Request{})
			Expect(mockStatus.AssertNumberOfCalls(GinkgoT(), "SetDegraded", 0)).Should(BeTrue())

			// Delete the LogStorage instance.
			Expect(cli.Delete(ctx, ls)).ShouldNot(HaveOccurred())

			// Run the reconciler and expect an OK status.
			r.Reconcile(ctx, reconcile.Request{})
			Expect(mockStatus.AssertNumberOfCalls(GinkgoT(), "SetDegraded", 0)).Should(BeTrue())

			// Expect OnCRNotFound to be called.
			Expect(mockStatus.AssertNumberOfCalls(GinkgoT(), "OnCRNotFound", 1)).Should(BeTrue())
		})

		It("should return an error if LogStorage exists on a managed cluster", func() {
			// Create a LogStorage instance.
			ls := &operatorv1.LogStorage{}
			ls.Name = "tigera-secure"
			Expect(cli.Create(ctx, ls)).ShouldNot(HaveOccurred())

			// Run the reconciler and expect everyting to be ok
			r, err := NewTestInitializer(cli, scheme, mockStatus, operatorv1.ProviderOpenShift, dns.DefaultClusterDomain)
			Expect(err).ShouldNot(HaveOccurred())
			r.Reconcile(ctx, reconcile.Request{})
			Expect(mockStatus.AssertNumberOfCalls(GinkgoT(), "SetDegraded", 0)).Should(BeTrue())

			// Create a ManagementClusterConnection instance.
			mcc := &operatorv1.ManagementClusterConnection{}
			mcc.Name = "tigera-secure"
			Expect(cli.Create(ctx, mcc)).ShouldNot(HaveOccurred())

			// Run the reconciler again.
			r.Reconcile(ctx, reconcile.Request{})

			// Expect SetDegraded to be called with an error.
			Expect(mockStatus.AssertNumberOfCalls(GinkgoT(), "SetDegraded", 1)).Should(BeTrue())

			// Query the LogStorage instance and expect the status to be degraded.
			ls = &operatorv1.LogStorage{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-secure"}, ls)).ShouldNot(HaveOccurred())
			Expect(ls.Status.State).Should(Equal(operatorv1.TigeraStatusDegraded))
		})
	})
})
