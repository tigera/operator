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

package clusterconnection_test

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"

	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/clusterconnection"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"

	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/test"
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
		mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()

		r = clusterconnection.NewReconcilerWithShims(c, scheme, mockStatus, operatorv1.ProviderNone, ready)
		dpl = &appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.GuardianDeploymentName,
				Namespace: render.GuardianNamespace,
			},
		}
		certificateManager, err := certificatemanager.Create(c, nil, dns.DefaultClusterDomain, common.OperatorNamespace())
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))) // Persist the root-ca in the operator namespace.
		secret, err := certificateManager.GetOrCreateKeyPair(c, render.GuardianSecretName, common.OperatorNamespace(), []string{"a"})
		Expect(err).NotTo(HaveOccurred())

		pcSecret, err := certificateManager.GetOrCreateKeyPair(c, render.PacketCaptureServerCert(false, "").Name(), common.OperatorNamespace(), []string{"a"})
		Expect(err).NotTo(HaveOccurred())

		promSecret, err := certificateManager.GetOrCreateKeyPair(c, monitor.PrometheusTLSSecretName, common.OperatorNamespace(), []string{"a"})
		Expect(err).NotTo(HaveOccurred())

		queryServerSecret, err := certificateManager.GetOrCreateKeyPair(c, render.ProjectCalicoAPIServerTLSSecretName(operatorv1.TigeraSecureEnterprise), common.OperatorNamespace(), []string{"a"})
		Expect(err).NotTo(HaveOccurred())

		err = c.Create(ctx, secret.Secret(common.OperatorNamespace()))
		Expect(err).NotTo(HaveOccurred())
		err = c.Create(ctx, pcSecret.Secret(common.OperatorNamespace()))
		Expect(err).NotTo(HaveOccurred())
		err = c.Create(ctx, promSecret.Secret(common.OperatorNamespace()))
		Expect(err).NotTo(HaveOccurred())
		err = c.Create(ctx, queryServerSecret.Secret(common.OperatorNamespace()))
		Expect(err).NotTo(HaveOccurred())

		By("applying the required prerequisites")
		// Create a ManagementClusterConnection in the k8s client.
		cfg = &operatorv1.ManagementClusterConnection{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure", Generation: 3},
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
				mockStatus.On("SetMetaData", mock.Anything).Return()

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
				mockStatus.On("SetDegraded", operatorv1.ResourceReadError, "Feature is not active - License does not support feature: egress-access-control", mock.Anything, mock.Anything).Return()
				mockStatus.On("SetMetaData", mock.Anything).Return()

				r = clusterconnection.NewReconcilerWithShims(c, scheme, mockStatus, operatorv1.ProviderNone, ready)
				_, err := r.Reconcile(ctx, reconcile.Request{})
				Expect(err).ShouldNot(HaveOccurred())
				mockStatus.AssertExpectations(GinkgoT())
			})

			It("should degrade and wait when tier and license are ready, but tier watch is not ready", func() {
				mockStatus = &status.MockStatus{}
				mockStatus.On("Run").Return()
				mockStatus.On("OnCRFound").Return()
				mockStatus.On("SetMetaData", mock.Anything).Return()

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
	Context("Reconcile for Condition status", func() {
		generation := int64(2)
		It("should reconcile with empty tigerastatus conditions ", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "management-cluster-connection"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status:     operatorv1.TigeraStatusStatus{},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "management-cluster-connection",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := utils.GetManagementClusterConnection(ctx, c)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(instance.Status.Conditions).To(HaveLen(0))
			Expect(c.Delete(ctx, ts)).NotTo(HaveOccurred())
		})
		It("should reconcile with creating new status condition with one item", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "management-cluster-connection"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status: operatorv1.TigeraStatusStatus{
					Conditions: []operatorv1.TigeraStatusCondition{
						{
							Type:               operatorv1.ComponentAvailable,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.AllObjectsAvailable),
							Message:            "All Objects are available",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "management-cluster-connection",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := utils.GetManagementClusterConnection(ctx, c)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(1))

			Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
			Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))
			Expect(c.Delete(ctx, ts)).NotTo(HaveOccurred())
		})
		It("should reconcile with creating new status condition  with multiple conditions as true", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "management-cluster-connection"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status: operatorv1.TigeraStatusStatus{
					Conditions: []operatorv1.TigeraStatusCondition{
						{
							Type:               operatorv1.ComponentAvailable,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.AllObjectsAvailable),
							Message:            "All Objects are available",
							ObservedGeneration: generation,
						},
						{
							Type:               operatorv1.ComponentProgressing,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.ResourceNotReady),
							Message:            "Progressing Installation.operatorv1.tigera.io",
							ObservedGeneration: generation,
						},
						{
							Type:               operatorv1.ComponentDegraded,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.ResourceUpdateError),
							Message:            "Error resolving ImageSet for components",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "management-cluster-connection",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := utils.GetManagementClusterConnection(ctx, c)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(3))
			Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
			Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[1].Type).To(Equal("Progressing"))
			Expect(string(instance.Status.Conditions[1].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[1].Reason).To(Equal(string(operatorv1.ResourceNotReady)))
			Expect(instance.Status.Conditions[1].Message).To(Equal("Progressing Installation.operatorv1.tigera.io"))
			Expect(instance.Status.Conditions[1].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[2].Type).To(Equal("Degraded"))
			Expect(string(instance.Status.Conditions[2].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[2].Reason).To(Equal(string(operatorv1.ResourceUpdateError)))
			Expect(instance.Status.Conditions[2].Message).To(Equal("Error resolving ImageSet for components"))
			Expect(instance.Status.Conditions[2].ObservedGeneration).To(Equal(generation))
			Expect(c.Delete(ctx, ts)).NotTo(HaveOccurred())
		})
		It("should reconcile with creating new status condition and toggle Available to true & others to false", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "management-cluster-connection"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status: operatorv1.TigeraStatusStatus{
					Conditions: []operatorv1.TigeraStatusCondition{
						{
							Type:               operatorv1.ComponentAvailable,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.AllObjectsAvailable),
							Message:            "All Objects are available",
							ObservedGeneration: generation,
						},
						{
							Type:               operatorv1.ComponentProgressing,
							Status:             operatorv1.ConditionFalse,
							Reason:             string(operatorv1.NotApplicable),
							Message:            "Not Applicable",
							ObservedGeneration: generation,
						},
						{
							Type:               operatorv1.ComponentDegraded,
							Status:             operatorv1.ConditionFalse,
							Reason:             string(operatorv1.NotApplicable),
							Message:            "Not Applicable",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "management-cluster-connection",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := utils.GetManagementClusterConnection(ctx, c)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(3))
			Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
			Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[1].Type).To(Equal("Progressing"))
			Expect(string(instance.Status.Conditions[1].Status)).To(Equal(string(operatorv1.ConditionFalse)))
			Expect(instance.Status.Conditions[1].Reason).To(Equal(string(operatorv1.NotApplicable)))
			Expect(instance.Status.Conditions[1].Message).To(Equal("Not Applicable"))
			Expect(instance.Status.Conditions[1].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[2].Type).To(Equal("Degraded"))
			Expect(string(instance.Status.Conditions[2].Status)).To(Equal(string(operatorv1.ConditionFalse)))
			Expect(instance.Status.Conditions[2].Reason).To(Equal(string(operatorv1.NotApplicable)))
			Expect(instance.Status.Conditions[2].Message).To(Equal("Not Applicable"))
			Expect(instance.Status.Conditions[2].ObservedGeneration).To(Equal(generation))
			Expect(c.Delete(ctx, ts)).NotTo(HaveOccurred())
		})
	})
})
