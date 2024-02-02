// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.

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
	"k8s.io/apimachinery/pkg/types"
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
	var installation *operatorv1.Installation
	var fc *crdv1.FelixConfiguration

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

			r = ReconcileApplicationLayer{
				client:          c,
				scheme:          scheme,
				provider:        operatorv1.ProviderNone,
				status:          mockStatus,
				licenseAPIReady: &utils.ReadyFlag{},
			}

			fc = &crdv1.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: crdv1.FelixConfigurationSpec{
					TPROXYMode: nil,
				},
			}

			Expect(c.Create(ctx, fc)).NotTo(HaveOccurred())

			// Mark that the watch for license key was successful.
			r.licenseAPIReady.MarkAsReady()
		})

		AfterEach(func() {
			Expect(c.Delete(ctx, fc)).NotTo(HaveOccurred())
		})

		It("should set PolicySyncPathPrefix if ALP is enabled", func() {
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
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

			By("applying the ApplicationLayer CR to the fake cluster")
			enabled := operatorv1.ApplicationLayerPolicyEnabled
			alSpec := &operatorv1.ApplicationLayer{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.ApplicationLayerSpec{
					ApplicationLayerPolicy: &enabled,
				},
			}
			Expect(c.Create(ctx, alSpec)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			By("ensuring that felix configuration PolicySyncPathPrefix is set")
			f1 := crdv1.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
			}
			Expect(test.GetResource(c, &f1)).To(BeNil())
			Expect(f1.Spec.PolicySyncPathPrefix).To(Equal("/var/run/nodeagent"))

			Expect(c.Delete(ctx, alSpec)).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			By("ensuring that felix configuration PolicySyncPathPrefix is left as is, even after ALP deletion")
			f2 := crdv1.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
			}
			Expect(test.GetResource(c, &f2)).To(BeNil())
			Expect(f2.Spec.PolicySyncPathPrefix).To(Equal("/var/run/nodeagent"))
		})

		It("should leave PolicySyncPathPrefix as is if already exists", func() {
			Expect(c.Delete(ctx, fc)).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &crdv1.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: crdv1.FelixConfigurationSpec{
					TPROXYMode:           nil,
					PolicySyncPathPrefix: "/var/run/myfelix",
				},
			})).NotTo(HaveOccurred())

			mockStatus.On("OnCRNotFound").Return()

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			By("applying the ApplicationLayer CR to the fake cluster")
			enabled := operatorv1.ApplicationLayerPolicyEnabled
			alSpec := &operatorv1.ApplicationLayer{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec: operatorv1.ApplicationLayerSpec{
					ApplicationLayerPolicy: &enabled,
				},
			}
			Expect(c.Create(ctx, alSpec)).NotTo(HaveOccurred())

			By("ensuring that felix configuration PolicySyncPathPrefix, if preset, is retained")
			f1 := crdv1.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
			}
			Expect(test.GetResource(c, &f1)).To(BeNil())
			Expect(f1.Spec.PolicySyncPathPrefix).To(Equal("/var/run/myfelix"))

			Expect(c.Delete(ctx, alSpec)).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			By("ensuring that felix configuration PolicySyncPathPrefix is left as is, even after ALP deletion")
			f2 := crdv1.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
			}
			Expect(test.GetResource(c, &f2)).To(BeNil())
			Expect(f2.Spec.PolicySyncPathPrefix).To(Equal("/var/run/myfelix"))
		})

		It("should leave TPROXYMode as nil if log collection is disabled", func() {
			// This test verifies a workaround for upgrade from versions that don't support TPROXY to versions
			// that do.  Setting an unknown felix config field causes older versions of felix to cyclicly restart,
			// which causes a disruptive upgrade.
			By("reconciling before without an app layer resource")
			mockStatus.On("OnCRNotFound").Return()
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			By("ensuring that felix configuration TPROXYMode is nil")
			fc := crdv1.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
			}
			Expect(test.GetResource(c, &fc)).To(BeNil())
			Expect(fc.Spec.TPROXYMode).To(BeNil())
		})

		It("should render accurate resources for for log collection", func() {
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
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

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
					Name:      applicationlayer.ApplicationLayerDaemonsetName,
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
			fc = crdv1.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
			}
			Expect(test.GetResource(c, &fc)).To(BeNil())
			Expect(*fc.Spec.TPROXYMode).To(Equal(crdv1.TPROXYModeOptionDisabled))
		})
		Context("Reconcile for Condition status", func() {
			generation := int64(2)
			BeforeEach(func() {
				enabled := operatorv1.L7LogCollectionEnabled
				Expect(c.Create(ctx, &operatorv1.ApplicationLayer{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure", Generation: 3},
					Spec: operatorv1.ApplicationLayerSpec{
						LogCollection: &operatorv1.LogCollectionSpec{
							CollectLogs: &enabled,
						},
					},
				})).NotTo(HaveOccurred())
			})
			It("should reconcile with creating new status condition with one item", func() {
				mockStatus.On("AddDaemonsets", mock.Anything).Return()
				mockStatus.On("AddDeployments", mock.Anything).Return()
				mockStatus.On("IsAvailable").Return(true)
				mockStatus.On("AddStatefulSets", mock.Anything).Return()
				mockStatus.On("AddCronJobs", mock.Anything)
				mockStatus.On("OnCRNotFound").Return()
				mockStatus.On("ClearDegraded")
				mockStatus.On("ReadyToMonitor")
				mockStatus.On("SetMetaData", mock.Anything).Return()
				Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

				ts := &operatorv1.TigeraStatus{
					ObjectMeta: metav1.ObjectMeta{Name: "applicationlayer"},
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
					Name:      "applicationlayer",
					Namespace: "",
				}})
				Expect(err).ShouldNot(HaveOccurred())
				instance, err := getApplicationLayer(ctx, r.client)
				Expect(err).ShouldNot(HaveOccurred())

				Expect(instance.Status.Conditions).To(HaveLen(1))
				Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
				Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
				Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
				Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
				Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))
			})
			It("should reconcile with empty tigerastatus conditions ", func() {
				mockStatus.On("AddDaemonsets", mock.Anything).Return()
				mockStatus.On("AddDeployments", mock.Anything).Return()
				mockStatus.On("IsAvailable").Return(true)
				mockStatus.On("AddStatefulSets", mock.Anything).Return()
				mockStatus.On("AddCronJobs", mock.Anything)
				mockStatus.On("OnCRNotFound").Return()
				mockStatus.On("ClearDegraded")
				mockStatus.On("ReadyToMonitor")
				mockStatus.On("SetMetaData", mock.Anything).Return()
				Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

				ts := &operatorv1.TigeraStatus{
					ObjectMeta: metav1.ObjectMeta{Name: "applicationlayer"},
					Spec:       operatorv1.TigeraStatusSpec{},
					Status:     operatorv1.TigeraStatusStatus{},
				}
				Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())

				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
					Name:      "applicationlayer",
					Namespace: "",
				}})
				Expect(err).ShouldNot(HaveOccurred())
				instance, err := getApplicationLayer(ctx, r.client)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(instance.Status.Conditions).To(HaveLen(0))
			})
			It("should reconcile with creating new status condition  with multiple conditions as true", func() {
				mockStatus.On("AddDaemonsets", mock.Anything).Return()
				mockStatus.On("AddDeployments", mock.Anything).Return()
				mockStatus.On("IsAvailable").Return(true)
				mockStatus.On("AddStatefulSets", mock.Anything).Return()
				mockStatus.On("AddCronJobs", mock.Anything)
				mockStatus.On("OnCRNotFound").Return()
				mockStatus.On("ClearDegraded")
				mockStatus.On("ReadyToMonitor")
				mockStatus.On("SetMetaData", mock.Anything).Return()
				Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

				ts := &operatorv1.TigeraStatus{
					ObjectMeta: metav1.ObjectMeta{Name: "applicationlayer"},
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
					Name:      "applicationlayer",
					Namespace: "",
				}})
				Expect(err).ShouldNot(HaveOccurred())
				instance, err := getApplicationLayer(ctx, r.client)
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
			})
			It("should reconcile with creating new status condition and toggle Available to true & others to false", func() {
				mockStatus.On("AddDaemonsets", mock.Anything).Return()
				mockStatus.On("AddDeployments", mock.Anything).Return()
				mockStatus.On("IsAvailable").Return(true)
				mockStatus.On("AddStatefulSets", mock.Anything).Return()
				mockStatus.On("AddCronJobs", mock.Anything)
				mockStatus.On("OnCRNotFound").Return()
				mockStatus.On("ClearDegraded")
				mockStatus.On("ReadyToMonitor")
				mockStatus.On("SetMetaData", mock.Anything).Return()
				Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())

				ts := &operatorv1.TigeraStatus{
					ObjectMeta: metav1.ObjectMeta{Name: "applicationlayer"},
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
					Name:      "applicationlayer",
					Namespace: "",
				}})
				Expect(err).ShouldNot(HaveOccurred())
				instance, err := getApplicationLayer(ctx, r.client)
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
			})
		})
		It("should not work in combination with FIPS", func() {
			fipsEnabled := operatorv1.FIPSModeEnabled
			installation.Spec.FIPSMode = &fipsEnabled
			Expect(c.Create(ctx, installation)).NotTo(HaveOccurred())
			mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "ApplicationLayer features cannot be used in combination with FIPSMode=Enabled", mock.Anything, mock.Anything).Return()
			mockStatus.On("SetMetaData", mock.Anything).Return()
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
			mockStatus.AssertExpectations(GinkgoT())
		})
	})
})
