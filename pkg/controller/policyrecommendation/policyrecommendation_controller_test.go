// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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

package policyrecommendation

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/types"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"github.com/tigera/operator/pkg/common"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/test"
)

var _ = Describe("PolicyRecommendation controller tests", func() {
	var c client.Client
	var ctx context.Context
	var r ReconcilePolicyRecommendation
	var scheme *runtime.Scheme
	var mockStatus *status.MockStatus

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		// Create a client that will have a crud interface of k8s objects.
		c = fake.NewClientBuilder().WithScheme(scheme).Build()
		ctx = context.Background()

		// Create an object we can use throughout the test to do the compliance reconcile loops.
		mockStatus = &status.MockStatus{}
		mockStatus.On("AddDaemonsets", mock.Anything).Return()
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("RemoveDeployments", mock.Anything).Return()
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("SetDegraded", "Waiting for LicenseKeyAPI to be ready", "").Return().Maybe()
		mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("SetDegraded", operatorv1.ResourceReadError, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("SetDegraded", operatorv1.ResourceUpdateError, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("SetDegraded", operatorv1.ResourceNotFound, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("RemoveCertificateSigningRequests", mock.Anything)
		mockStatus.On("SetMetaData", mock.Anything).Return()

		// Create an object we can use throughout the test to do the compliance reconcile loops.
		// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
		r = ReconcilePolicyRecommendation{
			client:                   c,
			scheme:                   scheme,
			provider:                 operatorv1.ProviderNone,
			status:                   mockStatus,
			licenseAPIReady:          &utils.ReadyFlag{},
			tierWatchReady:           &utils.ReadyFlag{},
			policyRecScopeWatchReady: &utils.ReadyFlag{},
		}

		// We start off with a 'standard' installation, with nothing special
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

		// The compliance reconcile loop depends on a ton of objects that should be available in your client as
		// prerequisites. Without them, compliance will not even start creating objects. Let's create them now.
		Expect(c.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Status:     operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady},
		})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &v3.LicenseKey{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Status:     v3.LicenseKeyStatus{Features: []string{common.PolicyRecommendationFeature}},
		})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &operatorv1.LogCollector{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		})).NotTo(HaveOccurred())

		certificateManager, err := certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))) // Persist the root-ca in the operator namespace.
		kiibanaTLS, err := certificateManager.GetOrCreateKeyPair(c, relasticsearch.PublicCertSecret, common.OperatorNamespace(), []string{relasticsearch.PublicCertSecret})
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, kiibanaTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
		linseedTLS, err := certificateManager.GetOrCreateKeyPair(c, render.TigeraLinseedSecret, common.OperatorNamespace(), []string{render.TigeraLinseedSecret})
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, linseedTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		Expect(c.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ECKLicenseConfigMapName,
				Namespace: render.ECKOperatorNamespace,
			},
			Data: map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeEnterpriseTrial)},
		})).NotTo(HaveOccurred())

		Expect(c.Create(ctx, &v3.DeepPacketInspection{ObjectMeta: metav1.ObjectMeta{Name: "test-dpi", Namespace: "test-dpi-ns"}})).ShouldNot(HaveOccurred())

		// Apply the policyrecommendation CR to the fake cluster.
		Expect(c.Create(ctx, &operatorv1.PolicyRecommendation{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})).NotTo(HaveOccurred())

		// mark that the watches were successful
		r.licenseAPIReady.MarkAsReady()
		r.tierWatchReady.MarkAsReady()
		r.policyRecScopeWatchReady.MarkAsReady()
	})

	Context("image reconciliation", func() {
		It("should use builtin images", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.PolicyRecommendationName,
					Namespace: render.PolicyRecommendationNamespace,
				},
			}
			res := test.GetResource(c, &d)
			Expect(res).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			controller := test.GetContainer(d.Spec.Template.Spec.Containers, "policy-recommendation-controller")
			Expect(controller).ToNot(BeNil())
			Expect(controller.Image).To(Equal(fmt.Sprintf("some.registry.org/%s:%s",
				components.ComponentPolicyRecommendation.Image,
				components.ComponentPolicyRecommendation.Version)))
		})

		It("should use images from imageset", func() {
			Expect(c.Create(ctx, &operatorv1.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/policy-recommendation", Digest: "sha256:policyrecommendationcontrollerhash"},
					},
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.PolicyRecommendationName,
					Namespace: render.PolicyRecommendationNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			controller := test.GetContainer(d.Spec.Template.Spec.Containers, "policy-recommendation-controller")
			Expect(controller).ToNot(BeNil())
			Expect(controller.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s@%s",
					components.ComponentPolicyRecommendation.Image,
					"sha256:policyrecommendationcontrollerhash")))
		})
	})

	Context("allow-tigera reconciliation", func() {
		var readyFlag *utils.ReadyFlag

		BeforeEach(func() {
			mockStatus = &status.MockStatus{}
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("SetMetaData", mock.Anything).Return()

			readyFlag = &utils.ReadyFlag{}
			readyFlag.MarkAsReady()
			r = ReconcilePolicyRecommendation{
				client:                   c,
				scheme:                   scheme,
				provider:                 operatorv1.ProviderNone,
				status:                   mockStatus,
				licenseAPIReady:          readyFlag,
				tierWatchReady:           readyFlag,
				policyRecScopeWatchReady: readyFlag,
			}
		})

		It("should wait if allow-tigera tier is unavailable", func() {
			utils.DeleteAllowTigeraTierAndExpectWait(ctx, c, &r, mockStatus)
		})

		It("should wait if tier watch is not ready", func() {
			r.tierWatchReady = &utils.ReadyFlag{}
			utils.ExpectWaitForTierWatch(ctx, &r, mockStatus)
		})
	})

	Context("secret availability", func() {
		BeforeEach(func() {
			mockStatus.On("SetDegraded", mock.Anything, mock.Anything).Return()
		})

		It("should not wait on tigera-ee-installer-elasticsearch-access secret when cluster is managed", func() {
			Expect(c.Create(ctx, &operatorv1.ManagementClusterConnection{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.ManagementClusterConnectionSpec{
					ManagementClusterAddr: "127.0.0.1:12345",
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(mockStatus.AssertNumberOfCalls(nil, "SetDegraded", 0)).To(BeTrue())
		})

		It("should wait on tigera-ee-installer-elasticsearch-access secret when in a management cluster", func() {
			Expect(c.Create(ctx, &operatorv1.ManagementCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.ManagementClusterSpec{
					Address: "127.0.0.1:12345",
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(mockStatus.AssertNumberOfCalls(nil, "SetDegraded", 0)).To(BeTrue())
		})
	})

	Context("Feature policy recommendation not active", func() {
		BeforeEach(func() {
			By("Deleting the previous license")
			Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ThreatDefenseFeature}}})).NotTo(HaveOccurred())
			By("Creating a new license that does not contain policy recommendation as a feature")
			Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			By("Deleting the previous license")
			Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
		})
	})

	Context("Reconcile tests", func() {
		BeforeEach(func() {
			mockStatus.On("SetDegraded", mock.Anything, mock.Anything).Return()
		})

		It("should Reconcile with default values for policy recommendation resource", func() {
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(0 * time.Second))

			prs := operatorv1.PolicyRecommendation{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}
			Expect(test.GetResource(c, &prs)).To(BeNil())
		})

		Context("Multi-tenant/namespaced reconciliation", func() {
			tenantANamespace := "tenant-a"
			tenantBNamespace := "tenant-b"

			BeforeEach(func() {
				r.multiTenant = true
			})

			It("should reconcile both with and without namespace provided while namespaced policyrecommendations exist", func() {
				// Create the Tenant resources for tenant-a and tenant-b.
				tenantA := &operatorv1.Tenant{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default",
						Namespace: tenantANamespace,
					},
					Spec: operatorv1.TenantSpec{ID: "tenant-a"},
				}
				Expect(c.Create(ctx, tenantA)).NotTo(HaveOccurred())
				tenantB := &operatorv1.Tenant{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default",
						Namespace: tenantBNamespace,
					},
					Spec: operatorv1.TenantSpec{ID: "tenant-b"},
				}
				Expect(c.Create(ctx, tenantB)).NotTo(HaveOccurred())

				certificateManagerTenantA, err := certificatemanager.Create(c, nil, "", tenantANamespace, certificatemanager.AllowCACreation(), certificatemanager.WithTenant(tenantA))
				Expect(err).NotTo(HaveOccurred())
				Expect(c.Create(ctx, certificateManagerTenantA.KeyPair().Secret(tenantANamespace)))
				Expect(c.Create(ctx, certificateManagerTenantA.CreateTrustedBundle().ConfigMap(tenantANamespace))).NotTo(HaveOccurred())

				linseedTLSTenantA, err := certificateManagerTenantA.GetOrCreateKeyPair(c, render.TigeraLinseedSecret, tenantANamespace, []string{render.TigeraLinseedSecret})
				Expect(err).NotTo(HaveOccurred())
				Expect(c.Create(ctx, linseedTLSTenantA.Secret(tenantANamespace))).NotTo(HaveOccurred())

				certificateManagerTenantB, err := certificatemanager.Create(c, nil, "", tenantBNamespace, certificatemanager.AllowCACreation(), certificatemanager.WithTenant(tenantB))
				Expect(err).NotTo(HaveOccurred())
				Expect(c.Create(ctx, certificateManagerTenantB.KeyPair().Secret(tenantBNamespace)))
				Expect(c.Create(ctx, certificateManagerTenantB.CreateTrustedBundle().ConfigMap(tenantBNamespace))).NotTo(HaveOccurred())

				linseedTLSTenantB, err := certificateManagerTenantB.GetOrCreateKeyPair(c, render.TigeraLinseedSecret, tenantBNamespace, []string{render.TigeraLinseedSecret})
				Expect(err).NotTo(HaveOccurred())
				Expect(c.Create(ctx, linseedTLSTenantB.Secret(tenantBNamespace))).NotTo(HaveOccurred())

				Expect(c.Create(ctx, &operatorv1.PolicyRecommendation{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tigera-secure",
						Namespace: tenantANamespace,
					},
				})).NotTo(HaveOccurred())

				Expect(c.Create(ctx, &operatorv1.PolicyRecommendation{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tigera-secure",
						Namespace: tenantBNamespace,
					},
				})).NotTo(HaveOccurred())

				result, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).NotTo(HaveOccurred())
				Expect(result.RequeueAfter).To(Equal(0 * time.Second))

				// We check for correct rendering of all resources in policyrecommendation_test.go, so use the SA
				// merely as a proxy here that the creation of our PolicyRecommendation went smoothly
				tenantAServiceAccount := corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
					Name:      render.PolicyRecommendationName,
					Namespace: tenantANamespace,
				}}

				tenantBServiceAccount := corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
					Name:      render.PolicyRecommendationName,
					Namespace: tenantBNamespace,
				}}

				// We called Reconcile without specifying a namespace, so neither of these namespaced objects should
				// exist yet
				err = test.GetResource(c, &tenantAServiceAccount)
				Expect(err).Should(HaveOccurred())

				err = test.GetResource(c, &tenantBServiceAccount)
				Expect(err).Should(HaveOccurred())

				// Now reconcile only tenant A's namespace and check that its PolicyRecommendation exists, but tenant B's
				// PolicyRecommendation still hasn't been reconciled so it should still not exist
				_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: tenantANamespace}})
				Expect(err).ShouldNot(HaveOccurred())

				err = test.GetResource(c, &tenantAServiceAccount)
				Expect(err).ShouldNot(HaveOccurred())

				err = test.GetResource(c, &tenantBServiceAccount)
				Expect(err).Should(HaveOccurred())

				// Now reconcile tenant B's namespace and check that its PolicyRecommendation exists now alongside tenant A's
				_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: tenantBNamespace}})
				Expect(err).ShouldNot(HaveOccurred())

				err = test.GetResource(c, &tenantAServiceAccount)
				Expect(err).ShouldNot(HaveOccurred())

				err = test.GetResource(c, &tenantBServiceAccount)
				Expect(err).ShouldNot(HaveOccurred())
			})
		})
	})
})
