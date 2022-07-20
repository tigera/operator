// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.

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

package clusterconnection_test

import (
	"context"
	"fmt"

	"github.com/tigera/operator/pkg/controller/utils"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/test"

	"github.com/tigera/operator/pkg/controller/clusterconnection"
	"github.com/tigera/operator/pkg/render"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/stretchr/testify/mock"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("ManagementClusterConnection controller tests", func() {
	var c client.Client
	var ctx context.Context
	var cfg *operatorv1.ManagementClusterConnection
	var r reconcile.Reconciler
	var scheme *runtime.Scheme
	var dpl *appsv1.Deployment
	var mockStatus *status.MockStatus

	notReady := &utils.ReadyFlag{}
	ready := &utils.ReadyFlag{}
	ready.MarkAsReady()

	BeforeEach(func() {
		// Create a Kubernetes client.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		err := operatorv1.SchemeBuilder.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
		c = fake.NewClientBuilder().WithScheme(scheme).Build()
		ctx = context.Background()
		mockStatus = &status.MockStatus{}
		mockStatus.On("Run").Return()

		mockStatus.On("AddDaemonsets", mock.Anything)
		mockStatus.On("AddDeployments", mock.Anything)
		mockStatus.On("AddStatefulSets", mock.Anything)
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("ClearDegraded", mock.Anything)
		mockStatus.On("SetDegraded", mock.Anything, mock.Anything)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ReadyToMonitor")

		r = clusterconnection.NewReconcilerWithShims(c, scheme, mockStatus, operatorv1.ProviderNone, ready)
		dpl = &appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.GuardianDeploymentName,
				Namespace: render.GuardianNamespace,
			},
		}
		certificateManager, err := certificatemanager.Create(c, nil, dns.DefaultClusterDomain)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))) // Persist the root-ca in the operator namespace.
		secret, err := certificateManager.GetOrCreateKeyPair(c, render.GuardianSecretName, common.OperatorNamespace(), []string{"a"})
		Expect(err).NotTo(HaveOccurred())

		pcSecret, err := certificateManager.GetOrCreateKeyPair(c, render.PacketCaptureCertSecret, common.OperatorNamespace(), []string{"a"})
		Expect(err).NotTo(HaveOccurred())

		promSecret, err := certificateManager.GetOrCreateKeyPair(c, render.PrometheusTLSSecretName, common.OperatorNamespace(), []string{"a"})
		Expect(err).NotTo(HaveOccurred())
		err = c.Create(ctx, secret.Secret(common.OperatorNamespace()))
		Expect(err).NotTo(HaveOccurred())
		err = c.Create(ctx, pcSecret.Secret(common.OperatorNamespace()))
		Expect(err).NotTo(HaveOccurred())
		err = c.Create(ctx, promSecret.Secret(common.OperatorNamespace()))
		Expect(err).NotTo(HaveOccurred())

		By("applying the required prerequisites")
		// Create a ManagementClusterConnection in the k8s client.
		cfg = &operatorv1.ManagementClusterConnection{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.ManagementClusterConnectionSpec{
				ManagementClusterAddr: "127.0.0.1:12345",
			},
		}
		err = c.Create(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())
		err = c.Create(
			ctx,
			&operatorv1.Installation{
				Spec: operatorv1.InstallationSpec{
					Variant:  operatorv1.TigeraSecureEnterprise,
					Registry: "some.registry.org/",
				},
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Status: operatorv1.InstallationStatus{
					Variant: operatorv1.TigeraSecureEnterprise,
					Computed: &operatorv1.InstallationSpec{
						Registry:           "my-reg",
						KubernetesProvider: operatorv1.ProviderNone,
					},
				},
			})
		Expect(err).NotTo(HaveOccurred())
	})

	Context("default config", func() {
		It("should create a default ManagementClusterConnection", func() {
			By("reconciling with the required prerequisites")
			err := c.Get(ctx, client.ObjectKey{Name: render.GuardianDeploymentName, Namespace: render.GuardianNamespace}, dpl)
			Expect(err).To(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ToNot(HaveOccurred())
			err = c.Get(ctx, client.ObjectKey{Name: render.GuardianDeploymentName, Namespace: render.GuardianNamespace}, dpl)
			// Verifying that there is a deployment is enough for the purpose of this test. More detailed testing will be done
			// in the render package.
			Expect(err).NotTo(HaveOccurred())
			Expect(dpl.Labels["k8s-app"]).To(Equal(render.GuardianName))
		})
	})

	Context("image reconciliation", func() {
		It("should use builtin images", func() {
			r = clusterconnection.NewReconcilerWithShims(c, scheme, mockStatus, operatorv1.ProviderNone, ready)
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.GuardianDeploymentName,
					Namespace: render.GuardianNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			dexC := test.GetContainer(d.Spec.Template.Spec.Containers, render.GuardianDeploymentName)
			Expect(dexC).ToNot(BeNil())
			Expect(dexC.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s:%s",
					components.ComponentGuardian.Image,
					components.ComponentGuardian.Version)))
		})
		It("should use images from imageset", func() {
			Expect(c.Create(ctx, &operatorv1.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/guardian", Digest: "sha256:guardianhash"},
					},
				},
			})).ToNot(HaveOccurred())

			r = clusterconnection.NewReconcilerWithShims(c, scheme, mockStatus, operatorv1.ProviderNone, ready)
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.GuardianDeploymentName,
					Namespace: render.GuardianNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			apiserver := test.GetContainer(d.Spec.Template.Spec.Containers, render.GuardianDeploymentName)
			Expect(apiserver).ToNot(BeNil())
			Expect(apiserver.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentGuardian.Image,
					"sha256:guardianhash")))
		})
	})

	Context("allow-tigera reconciliation", func() {
		var licenseKey *v3.LicenseKey
		BeforeEach(func() {
			licenseKey = &v3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Status: v3.LicenseKeyStatus{
					Features: []string{
						common.TiersFeature,
						common.EgressAccessControlFeature,
					},
				},
			}
			Expect(c.Create(ctx, licenseKey)).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())
			r = clusterconnection.NewReconcilerWithShims(c, scheme, mockStatus, operatorv1.ProviderNone, ready)
		})

		Context("IP-based management cluster address", func() {
			It("should render allow-tigera policy when tier and watch are ready", func() {
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				policies := v3.NetworkPolicyList{}
				Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())

				Expect(policies.Items).To(HaveLen(2))
				Expect(policies.Items[0].Name).To(Equal("allow-tigera.default-deny"))
				Expect(policies.Items[1].Name).To(Equal("allow-tigera.guardian-access"))
			})

			It("should omit allow-tigera policy and not degrade when tier is not ready", func() {
				Expect(c.Delete(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				policies := v3.NetworkPolicyList{}
				Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
				Expect(policies.Items).To(HaveLen(0))
			})

			It("should degrade and wait when tier is ready, but tier watch is not ready", func() {
				mockStatus = &status.MockStatus{}
				mockStatus.On("Run").Return()
				mockStatus.On("OnCRFound").Return()

				r = clusterconnection.NewReconcilerWithShims(c, scheme, mockStatus, operatorv1.ProviderNone, notReady)
				utils.ExpectWaitForTierWatch(ctx, r, mockStatus)

				policies := v3.NetworkPolicyList{}
				Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
				Expect(policies.Items).To(HaveLen(0))
			})
		})

		Context("Domain-based management cluster address", func() {
			BeforeEach(func() {
				cfg.Spec.ManagementClusterAddr = "mydomain.io:443"
				Expect(c.Update(ctx, cfg)).NotTo(HaveOccurred())
			})

			It("should render allow-tigera policy when license and tier are ready", func() {
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				policies := v3.NetworkPolicyList{}
				Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())

				Expect(policies.Items).To(HaveLen(2))
				Expect(policies.Items[0].Name).To(Equal("allow-tigera.default-deny"))
				Expect(policies.Items[1].Name).To(Equal("allow-tigera.guardian-access"))
			})

			It("should degrade and wait when tier is ready, but license is not sufficient", func() {
				licenseKey.Status.Features = []string{common.TiersFeature}
				Expect(c.Update(ctx, licenseKey)).NotTo(HaveOccurred())

				mockStatus = &status.MockStatus{}
				mockStatus.On("Run").Return()
				mockStatus.On("OnCRFound").Return()
				mockStatus.On("SetDegraded", "Feature is not active", "License does not support feature: egress-access-control").Return()

				r = clusterconnection.NewReconcilerWithShims(c, scheme, mockStatus, operatorv1.ProviderNone, ready)
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				mockStatus.AssertExpectations(GinkgoT())
			})

			It("should degrade and wait when tier and license are ready, but tier watch is not ready", func() {
				mockStatus = &status.MockStatus{}
				mockStatus.On("Run").Return()
				mockStatus.On("OnCRFound").Return()

				r = clusterconnection.NewReconcilerWithShims(c, scheme, mockStatus, operatorv1.ProviderNone, notReady)
				utils.ExpectWaitForTierWatch(ctx, r, mockStatus)

				policies := v3.NetworkPolicyList{}
				Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
				Expect(policies.Items).To(HaveLen(0))
			})

			It("should omit allow-tigera policy when tier is ready but license is not ready", func() {
				Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).NotTo(HaveOccurred())
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				policies := v3.NetworkPolicyList{}
				Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
				Expect(policies.Items).To(HaveLen(0))
			})

			It("should omit allow-tigera policy when license is ready but tier is not ready", func() {
				Expect(c.Delete(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())

				policies := v3.NetworkPolicyList{}
				Expect(c.List(ctx, &policies)).ToNot(HaveOccurred())
				Expect(policies.Items).To(HaveLen(0))
			})
		})
	})
})
