// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package tiers

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("tier controller tests", func() {
	var r ReconcileTiers
	var c client.Client
	var ctx context.Context
	var scheme *runtime.Scheme
	var mockStatus *status.MockStatus
	var readyFlag *utils.ReadyFlag

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		// Create a client that will have a crud interface of k8s objects.
		c = fake.NewClientBuilder().WithScheme(scheme).Build()
		ctx = context.Background()

		mockStatus = &status.MockStatus{}
		mockStatus.On("ReadyToMonitor").Return()

		// Mark that the watches were successful.
		readyFlag = &utils.ReadyFlag{}
		readyFlag.MarkAsReady()

		// Create an object we can use throughout the test to perform the reconcile loops.
		r = ReconcileTiers{
			client:             c,
			scheme:             scheme,
			provider:           operatorv1.ProviderNone,
			status:             mockStatus,
			tierWatchReady:     readyFlag,
			policyWatchesReady: readyFlag,
		}

		// Create objects that are prerequisites of the reconcile loop.
		Expect(c.Create(
			ctx,
			&operatorv1.Installation{
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

		Expect(c.Create(
			ctx,
			&v3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Status: v3.LicenseKeyStatus{
					Features: []string{
						common.TiersFeature,
						common.EgressAccessControlFeature,
					},
				},
			},
		)).NotTo(HaveOccurred())

		Expect(c.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Status:     operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady},
		})).NotTo(HaveOccurred())
	})

	// Validate that the tier is created. Policy coverage is handled in the render tests.
	It("reconciles the allow-tigera tier", func() {
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())

		tier := v3.Tier{}
		Expect(c.Get(ctx, client.ObjectKey{Name: "allow-tigera"}, &tier)).To(BeNil())
	})

	It("waits for API server to be available before reconciling", func() {
		err := c.Delete(ctx, &operatorv1.APIServer{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})
		Expect(err).ShouldNot(HaveOccurred())
		mockStatus = &status.MockStatus{}
		mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for Tigera API server to be ready", mock.Anything, mock.Anything).Return()
		r = ReconcileTiers{
			client:             c,
			scheme:             scheme,
			provider:           operatorv1.ProviderNone,
			status:             mockStatus,
			tierWatchReady:     readyFlag,
			policyWatchesReady: readyFlag,
		}

		_, err = r.Reconcile(ctx, reconcile.Request{})

		Expect(err).ShouldNot(HaveOccurred())
		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should require license", func() {
		Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).ToNot(HaveOccurred())
		mockStatus = &status.MockStatus{}
		r = ReconcileTiers{
			client:             c,
			scheme:             scheme,
			provider:           operatorv1.ProviderNone,
			status:             mockStatus,
			tierWatchReady:     readyFlag,
			policyWatchesReady: readyFlag,
		}
		mockStatus.On("SetDegraded", operatorv1.ResourceNotFound, "License not found", "licensekeies.projectcalico.org \"default\" not found", mock.Anything).Return()
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		mockStatus.AssertExpectations(GinkgoT())
	})

	It("should require license with tiers feature", func() {
		license := &v3.LicenseKey{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Status: v3.LicenseKeyStatus{
				Features: []string{
					common.EgressAccessControlFeature,
				},
			},
		}
		Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: license.ObjectMeta}))
		Expect(c.Create(ctx, license)).ToNot(HaveOccurred())
		mockStatus = &status.MockStatus{}
		r = ReconcileTiers{
			client:             c,
			scheme:             scheme,
			provider:           operatorv1.ProviderNone,
			status:             mockStatus,
			tierWatchReady:     readyFlag,
			policyWatchesReady: readyFlag,
		}
		mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "Feature is not active - License does not support feature: tiers", mock.Anything, mock.Anything).Return()
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		mockStatus.AssertExpectations(GinkgoT())
	})
})
