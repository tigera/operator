// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package istio

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	admregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/status"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/test"
)

var _ = Describe("Istio controller tests", func() {
	var (
		cli                 client.Client
		scheme              *runtime.Scheme
		ctx                 context.Context
		mockStatus          *status.MockStatus
		installation        *operatorv1.Installation
		istio               *operatorv1.Istio
		objTrackerWithCalls test.ObjectTrackerWithCalls
		replicas            int32
	)

	BeforeEach(func() {
		// Set up the scheme
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(admregv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(autoscalingv2.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		objTrackerWithCalls = test.NewObjectTrackerWithCalls(scheme)
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjectTracker(&objTrackerWithCalls).Build()

		// Set up a mock status
		mockStatus = &status.MockStatus{}
		mockStatus.On("AddDaemonsets", mock.Anything).Maybe().Return()
		mockStatus.On("AddDeployments", mock.Anything).Maybe().Return()
		mockStatus.On("AddStatefulSets", mock.Anything).Maybe().Return()
		mockStatus.On("AddCronJobs", mock.Anything).Maybe()
		mockStatus.On("IsAvailable").Maybe().Return(true)
		mockStatus.On("OnCRFound").Maybe().Return()
		mockStatus.On("ClearDegraded").Maybe()
		mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Maybe().Return()
		mockStatus.On("ReadyToMonitor").Maybe()
		mockStatus.On("OnCRNotFound").Maybe().Return()
		mockStatus.On("SetMetaData", mock.Anything).Maybe().Return()

		// Apply prerequisites for the basic reconcile to succeed.
		certificateManager, err := certificatemanager.Create(cli, nil, "cluster.local", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(context.Background(), certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		installation = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				Variant:              operatorv1.Calico,
			},
			Status: operatorv1.InstallationStatus{
				Variant: operatorv1.Calico,
				Conditions: []metav1.Condition{
					{Type: string(operatorv1.ComponentAvailable), Status: metav1.ConditionTrue},
				},
			},
		}

		istio = &operatorv1.Istio{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
		}

		replicas = 2
	})

	createResources := func() {
		// Clear any existing resourceVersion to avoid creation conflicts
		Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, istio)).NotTo(HaveOccurred())
	}

	Context("Reconcile tests", func() {
		It("should handle basic Istio reconciliation", func() {
			createResources()

			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			// The controller should successfully handle the reconciliation
			Expect(err).ShouldNot(HaveOccurred())

			// Verify the status methods were called appropriately
			mockStatus.AssertCalled(GinkgoT(), "OnCRFound")
			mockStatus.AssertCalled(GinkgoT(), "SetMetaData", mock.Anything)
		})

		It("should handle missing Installation resource", func() {
			Expect(cli.Create(ctx, istio)).NotTo(HaveOccurred())

			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			Expect(err).ShouldNot(HaveOccurred())
			// Verify OnCRFound was called since we have an Istio resource
			mockStatus.AssertCalled(GinkgoT(), "OnCRFound")
		})

		It("should handle missing Istio resource", func() {
			Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())

			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			Expect(err).ShouldNot(HaveOccurred())
			// Verify OnCRNotFound was called since we don't have an Istio resource
			mockStatus.AssertCalled(GinkgoT(), "OnCRNotFound")
		})

		Context("Istio configuration tests", func() {
			BeforeEach(func() {
				createResources()
			})

			It("should handle basic Istio spec configuration", func() {
				r := &ReconcileIstio{
					Client:   cli,
					scheme:   scheme,
					provider: operatorv1.ProviderNone,
					status:   mockStatus,
				}

				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
				// The controller should successfully handle the basic configuration
				Expect(err).ShouldNot(HaveOccurred())

				// Verify that we got to the point where we found both CRs
				mockStatus.AssertCalled(GinkgoT(), "OnCRFound")
				mockStatus.AssertCalled(GinkgoT(), "SetMetaData", mock.Anything)
			})

			It("should handle Istiod deployment customization", func() {
				istio.Spec.IstiodDeployment = &operatorv1.IstiodDeployment{
					Spec: &operatorv1.IstiodDeploymentSpec{
						Template: &operatorv1.IstiodDeploymentSpecTemplate{
							Spec: &operatorv1.IstiodDeploymentPodSpec{
								NodeSelector: map[string]string{
									"kubernetes.io/os": "linux",
								},
							},
						},
					},
				}
				Expect(cli.Update(ctx, istio)).NotTo(HaveOccurred())

				r := &ReconcileIstio{
					Client:   cli,
					scheme:   scheme,
					provider: operatorv1.ProviderNone,
					status:   mockStatus,
				}

				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
				// The controller should successfully handle the Istiod deployment customization
				Expect(err).ShouldNot(HaveOccurred())
			})

			It("should handle Istio CNI daemonset customization", func() {
				istio.Spec.IstioCNIDaemonset = &operatorv1.IstioCNIDaemonset{
					Spec: &operatorv1.IstioCNIDaemonsetSpec{
						Template: &operatorv1.IstioCNIDaemonsetSpecTemplate{
							Spec: &operatorv1.IstioCNIDaemonsetPodSpec{
								NodeSelector: map[string]string{
									"kubernetes.io/os": "linux",
								},
							},
						},
					},
				}
				Expect(cli.Update(ctx, istio)).NotTo(HaveOccurred())

				r := &ReconcileIstio{
					Client:   cli,
					scheme:   scheme,
					provider: operatorv1.ProviderNone,
					status:   mockStatus,
				}

				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
				// The controller should successfully handle the Istio CNI daemonset customization
				Expect(err).ShouldNot(HaveOccurred())
			})
		})
	})

	Context("Status tests", func() {
		BeforeEach(func() {
			createResources()
		})

		It("should update status when reconciliation is successful", func() {
			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			Expect(err).ShouldNot(HaveOccurred())

			mockStatus.AssertCalled(GinkgoT(), "OnCRFound")
			//mockStatus.AssertCalled(GinkgoT(), "ClearDegraded")
			mockStatus.AssertCalled(GinkgoT(), "ReadyToMonitor")
		})

		It("should handle reconciliation without errors", func() {

			r := &ReconcileIstio{
				Client:   cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
			}

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
			// The reconciliation should be successful
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

	Context("Provider-specific tests", func() {
		DescribeTable("should handle different providers correctly",
			func(provider operatorv1.Provider) {
				createResources()

				r := &ReconcileIstio{
					Client:   cli,
					scheme:   scheme,
					provider: provider,
					status:   mockStatus,
				}

				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
				// The controller should handle all providers successfully
				Expect(err).ShouldNot(HaveOccurred())
			},
			Entry("None provider", operatorv1.ProviderNone),
			Entry("GKE provider", operatorv1.ProviderGKE),
			Entry("AKS provider", operatorv1.ProviderAKS),
			Entry("EKS provider", operatorv1.ProviderEKS),
			Entry("OpenShift provider", operatorv1.ProviderOpenShift),
		)
	})
})
