// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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

package status

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	certV1 "k8s.io/api/certificates/v1"
	certV1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	controllerRuntimeClient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
)

var _ = Describe("Status reporting tests", func() {
	var sm *statusManager
	var oldVersionSm *statusManager
	var client controllerRuntimeClient.Client
	var oldVersionClient controllerRuntimeClient.Client
	var (
		ctx    = context.Background()
		label  = "label"
		labels = map[string]string{"k8s-app": label}
	)
	BeforeEach(func() {
		// Setup Scheme for all resources
		scheme := runtime.NewScheme()
		Expect(certV1.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
		Expect(appsv1.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(corev1.AddToScheme(scheme)).NotTo(HaveOccurred())
		client = fake.NewClientBuilder().WithScheme(scheme).Build()

		sm = New(client, "test-component", &common.VersionInfo{Major: 1, Minor: 19}).(*statusManager)
		Expect(sm.IsAvailable()).To(BeFalse())

		oldScheme := runtime.NewScheme()
		Expect(certV1beta1.AddToScheme(oldScheme)).ShouldNot(HaveOccurred())
		err = apis.AddToScheme(oldScheme)
		Expect(err).NotTo(HaveOccurred())
		oldVersionClient = fake.NewClientBuilder().WithScheme(oldScheme).Build()

		oldVersionSm = New(oldVersionClient, "test-component", &common.VersionInfo{Major: 1, Minor: 18}).(*statusManager)
		Expect(oldVersionSm.IsAvailable()).To(BeFalse())
	})

	Context("without CR found", func() {
		It("status is not created", func() {
			sm.updateStatus()
			stat := &operator.TigeraStatus{}
			err := client.Get(context.TODO(), types.NamespacedName{Name: "test-component"}, stat)
			Expect(err).To(HaveOccurred())
			Expect(apierrs.IsNotFound(err)).To(BeTrue())
		})

		It("existing status is not removed before CR is queried", func() {
			ts := &operator.TigeraStatus{ObjectMeta: metav1.ObjectMeta{Name: "test-component"}}
			err := client.Create(context.TODO(), ts)
			Expect(err).NotTo(HaveOccurred())
			sm.updateStatus()
			stat := &operator.TigeraStatus{}
			err = client.Get(context.TODO(), types.NamespacedName{Name: "test-component"}, stat)
			Expect(err).NotTo(HaveOccurred())
		})

		It("existing status is removed after CR query attempt", func() {
			// Convince the status manager that its CR has previously existed.
			sm.crExists = true
			ts := &operator.TigeraStatus{ObjectMeta: metav1.ObjectMeta{Name: "test-component"}}
			err := client.Create(context.TODO(), ts)
			Expect(err).NotTo(HaveOccurred())

			// Simulate the controller failing to find its CR.
			sm.OnCRNotFound()
			sm.updateStatus()

			// Expect the status manager to have cleaned up the tigera status CR.
			stat := &operator.TigeraStatus{}
			err = client.Get(context.TODO(), types.NamespacedName{Name: "test-component"}, stat)
			Expect(err).To(HaveOccurred())
			Expect(apierrs.IsNotFound(err)).To(BeTrue())
		})
	})

	Context("with CR found", func() {
		BeforeEach(func() {
			sm.OnCRFound()
			// sync doesn't actually run so it needs to be set explicitly here.
			sm.hasSynced = true
		})

		Context("ReadyToMonitor not called", func() {
			When("it is not progressing or failing", func() {
				It("should not be available, progressing, or degraded", func() {
					Expect(sm.IsAvailable()).To(BeFalse())
					Expect(sm.IsProgressing()).To(BeFalse())
					Expect(sm.IsDegraded()).To(BeFalse())
				})
			})
			When("it is not progressing or failing but there is an explicit degraded reasons", func() {
				It("should not be available or progressing but should be degraded", func() {
					sm.SetDegraded("some message", "some message", nil, log)

					Expect(sm.IsAvailable()).To(BeFalse())
					Expect(sm.IsProgressing()).To(BeFalse())
					Expect(sm.IsDegraded()).To(BeTrue())
				})
			})
			When("it is progressing", func() {
				It("should not be available, progressing or degraded", func() {
					sm.progressing = []string{"progressing message"}

					Expect(sm.IsAvailable()).To(BeFalse())
					Expect(sm.IsProgressing()).To(BeFalse())
					Expect(sm.IsDegraded()).To(BeFalse())
				})
			})
			When("it is failing", func() {
				It("should not be available, progressing or degraded", func() {
					sm.failing = []string{"failing message"}

					Expect(sm.IsAvailable()).To(BeFalse())
					Expect(sm.IsProgressing()).To(BeFalse())
					Expect(sm.IsDegraded()).To(BeFalse())
				})
			})
		})

		Context("ReadyToMonitor called", func() {
			BeforeEach(func() {
				sm.ReadyToMonitor()
			})
			When("it is not progressing or failing", func() {
				It("should be available, but not progressing or degraded", func() {
					Expect(sm.IsAvailable()).To(BeTrue())
					Expect(sm.IsProgressing()).To(BeFalse())
					Expect(sm.IsDegraded()).To(BeFalse())
				})
			})
			When("it is progressing and not failing", func() {
				It("should not be available or degraded but should be progressing", func() {
					sm.progressing = []string{"progressing message"}

					Expect(sm.IsAvailable()).To(BeFalse())
					Expect(sm.IsProgressing()).To(BeTrue())
					Expect(sm.IsDegraded()).To(BeFalse())
				})
			})

			When("it is not progressing and is failing", func() {
				It("should not be available or degraded but should be progressing", func() {
					sm.failing = []string{"failing message"}

					Expect(sm.IsAvailable()).To(BeFalse())
					Expect(sm.IsProgressing()).To(BeFalse())
					Expect(sm.IsDegraded()).To(BeTrue())
				})
			})
		})

		Context("when pod is failed", func() {
			var gen int64
			BeforeEach(func() {
				sm.ReadyToMonitor()
				Expect(client.Create(ctx, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "NS1",
						Name:      "DP1pod",
						Labels: map[string]string{
							"dp1Key": "dp1Value",
						},
					},
					Spec: corev1.PodSpec{},
					Status: corev1.PodStatus{
						Phase: corev1.PodFailed,
					},
				})).NotTo(HaveOccurred())
				Expect(client.Create(ctx, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "NS1",
						Name:      "DS1pod",
						Labels: map[string]string{
							"ds1Key": "ds1Value",
						},
					},
					Spec: corev1.PodSpec{},
					Status: corev1.PodStatus{
						Phase: corev1.PodFailed,
					},
				})).NotTo(HaveOccurred())
				Expect(client.Create(ctx, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "NS1",
						Name:      "SS1pod",
						Labels: map[string]string{
							"ss1Key": "ss1Value",
						},
					},
					Spec: corev1.PodSpec{},
					Status: corev1.PodStatus{
						Phase: corev1.PodFailed,
					},
				})).NotTo(HaveOccurred())
				gen = 5
			})
			It("should not degrade when daemonset has the proper pod counts", func() {
				sm.AddDaemonsets([]types.NamespacedName{{Namespace: "NS1", Name: "DS1"}})
				replicas := int32(1)

				Expect(client.Create(ctx, &appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "NS1", Name: "DS1",
						Generation: gen,
					},
					Spec: appsv1.DaemonSetSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"ds1Key": "ds1Value"},
						},
					},
					Status: appsv1.DaemonSetStatus{
						ObservedGeneration:     gen,
						CurrentNumberScheduled: replicas,
						NumberMisscheduled:     0,
						DesiredNumberScheduled: replicas,
						NumberReady:            replicas,
						UpdatedNumberScheduled: replicas,
						NumberAvailable:        replicas,
						NumberUnavailable:      0,
					},
				})).NotTo(HaveOccurred())
				sm.updateStatus()
				Expect(sm.IsDegraded()).To(BeFalse())
			})
			It("should degrade when the daemonsetdoes not have the correct pod counts", func() {
				sm.AddDaemonsets([]types.NamespacedName{{Namespace: "NS1", Name: "DS1"}})
				replicas := int32(1)

				Expect(client.Create(ctx, &appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "NS1", Name: "DS1",
						Generation: gen,
					},
					Spec: appsv1.DaemonSetSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"ds1Key": "ds1Value"},
						},
					},
					Status: appsv1.DaemonSetStatus{
						ObservedGeneration:     gen,
						CurrentNumberScheduled: replicas,
						NumberMisscheduled:     0,
						DesiredNumberScheduled: replicas,
						NumberReady:            0, // correct value should be `replicas`
						UpdatedNumberScheduled: replicas,
						NumberAvailable:        replicas,
						NumberUnavailable:      0,
					},
				})).NotTo(HaveOccurred())
				sm.updateStatus()
				Expect(sm.IsDegraded()).To(BeTrue())
			})
			It("should not degrade when deployment has the pod counts", func() {
				sm.AddDeployments([]types.NamespacedName{{Namespace: "NS1", Name: "DP1"}})
				replicas := int32(1)

				Expect(client.Create(ctx, &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "NS1", Name: "DP1",
						Generation: gen,
					},
					Spec: appsv1.DeploymentSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"dp1Key": "dp1Value"},
						},
						Replicas: &replicas,
					},
					Status: appsv1.DeploymentStatus{
						ObservedGeneration:  gen,
						UnavailableReplicas: 0,
						AvailableReplicas:   replicas,
						ReadyReplicas:       replicas,
					},
				})).NotTo(HaveOccurred())
				sm.updateStatus()
				Expect(sm.IsDegraded()).To(BeFalse())
			})
			It("should degrade when the deployment does not have the correct pod counts", func() {
				sm.AddDeployments([]types.NamespacedName{{Namespace: "NS1", Name: "DP1"}})
				replicas := int32(1)

				Expect(client.Create(ctx, &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "NS1", Name: "DP1",
						Generation: gen,
					},
					Spec: appsv1.DeploymentSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"dp1Key": "dp1Value"},
						},
						Replicas: &replicas,
					},
					Status: appsv1.DeploymentStatus{
						ObservedGeneration:  gen,
						UnavailableReplicas: 0,
						AvailableReplicas:   0, // correct value should be `replicas`
						ReadyReplicas:       replicas,
					},
				})).NotTo(HaveOccurred())
				sm.updateStatus()
				Expect(sm.IsDegraded()).To(BeTrue())
			})
			It("should not degrade when statefulset has the proper pod counts", func() {
				sm.AddStatefulSets([]types.NamespacedName{{Namespace: "NS1", Name: "SS1"}})
				replicas := int32(1)

				Expect(client.Create(ctx, &appsv1.StatefulSet{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "NS1", Name: "SS1",
						Generation: gen,
					},
					Spec: appsv1.StatefulSetSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"ss1Key": "ss1Value"},
						},
						Replicas: &replicas,
					},
					Status: appsv1.StatefulSetStatus{
						ObservedGeneration: gen,
						Replicas:           replicas,
						ReadyReplicas:      replicas,
						CurrentReplicas:    replicas,
						UpdatedReplicas:    replicas,
					},
				})).NotTo(HaveOccurred())
				sm.updateStatus()
				Expect(sm.IsDegraded()).To(BeFalse())
			})
			It("should degrade when the deployment does not have the correct pod counts", func() {
				sm.AddStatefulSets([]types.NamespacedName{{Namespace: "NS1", Name: "SS1"}})
				replicas := int32(1)

				Expect(client.Create(ctx, &appsv1.StatefulSet{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "NS1", Name: "SS1",
						Generation: gen,
					},
					Spec: appsv1.StatefulSetSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"ss1Key": "ss1Value"},
						},
						Replicas: &replicas,
					},
					Status: appsv1.StatefulSetStatus{
						ObservedGeneration: gen,
						Replicas:           replicas,
						ReadyReplicas:      0, // correct value should be `replicas`
						CurrentReplicas:    replicas,
						UpdatedReplicas:    replicas,
					},
				})).NotTo(HaveOccurred())
				sm.updateStatus()
				Expect(sm.IsDegraded()).To(BeTrue())
			})
		})

		It("Should handle basic state changes", func() {
			// We expect no state to be "True" at boot.
			Expect(sm.IsAvailable()).To(BeFalse())
			Expect(sm.IsDegraded()).To(BeFalse())
			Expect(sm.IsProgressing()).To(BeFalse())

			By("Setting a degraded state explicitly")
			sm.explicitDegradedMsg = "Explicit degraded message"
			sm.explicitDegradedReason = "Explicit degraded reason"
			sm.degraded = true
			Expect(sm.IsAvailable()).To(BeFalse())
			Expect(sm.IsDegraded()).To(BeTrue())
			Expect(sm.IsProgressing()).To(BeFalse())

			By("Telling the Status Manager we're ready to start monitoring")
			sm.ReadyToMonitor()

			By("Setting a degraded state via pod status")
			sm.explicitDegradedMsg = ""
			sm.explicitDegradedReason = ""
			sm.degraded = false
			sm.failing = []string{"A failing container"}
			sm.progressing = []string{"Some progressing status"}
			Expect(sm.IsAvailable()).To(BeFalse())
			Expect(sm.IsDegraded()).To(BeTrue())
			// We don't expect progressing, even though we have set internal state saying it is,
			// because the "degraded" takes precedence.
			Expect(sm.IsProgressing()).To(BeFalse())

			By("Setting a progressing state")
			sm.failing = []string{}
			Expect(sm.IsAvailable()).To(BeFalse())
			Expect(sm.IsDegraded()).To(BeFalse())
			Expect(sm.IsProgressing()).To(BeTrue())

			By("Setting an available state")
			sm.progressing = []string{}
			Expect(sm.IsAvailable()).To(BeTrue())
			Expect(sm.IsDegraded()).To(BeFalse())
			Expect(sm.IsProgressing()).To(BeFalse())

			By("Setting a degraded state via pod status after being available")
			sm.explicitDegradedMsg = ""
			sm.explicitDegradedReason = ""
			sm.degraded = false
			sm.failing = []string{"A failing container"}
			sm.progressing = []string{"Some progressing status"}
			Expect(sm.IsAvailable()).To(BeFalse())
			Expect(sm.IsDegraded()).To(BeTrue())
			Expect(sm.IsProgressing()).To(BeFalse())
		})

		It("should prioritize explicit degraded reason over pod failure", func() {
			Expect(sm.degradedReason()).To(Equal(operator.Unknown))
			sm.failing = []string{"This pod has died"}
			Expect(sm.degradedReason()).To(Equal(operator.PodFailure))
			sm.SetDegraded(operator.ResourceNotFound, "error message", nil, log)
			Expect(sm.degradedReason()).To(Equal(operator.ResourceNotFound))
		})

		It("should generate correct degraded messages", func() {
			Expect(sm.degradedReason()).To(Equal(operator.Unknown))
			sm.failing = []string{"This pod has died"}
			Expect(sm.degradedMessage()).To(Equal("This pod has died"))
			sm.SetDegraded(operator.ResourceNotFound, "Controller set us degraded", nil, log)
			Expect(sm.degradedMessage()).To(Equal("Controller set us degraded: \nThis pod has died"))
		})

		It("should contain all the NamespacesNames for all the resources added by multiple calls to Set<Resources>", func() {
			sm.AddStatefulSets([]types.NamespacedName{{Namespace: "NS1", Name: "SS1"}})
			sm.AddStatefulSets([]types.NamespacedName{{Namespace: "NS1", Name: "SS2"}})
			sm.AddDeployments([]types.NamespacedName{{Namespace: "NS1", Name: "DP1"}})
			sm.AddDeployments([]types.NamespacedName{{Namespace: "NS1", Name: "DP2"}})
			sm.AddDaemonsets([]types.NamespacedName{{Namespace: "NS1", Name: "DS1"}})
			sm.AddDaemonsets([]types.NamespacedName{{Namespace: "NS1", Name: "DS2"}})
			sm.AddCronJobs([]types.NamespacedName{{Namespace: "NS1", Name: "CJ1"}})
			sm.AddCronJobs([]types.NamespacedName{{Namespace: "NS1", Name: "CJ2"}})
			sm.AddCertificateSigningRequests("CSR1", map[string]string{"k8s-app": "CSR1"})
			sm.AddCertificateSigningRequests("CSR2", map[string]string{"k8s-app": "CSR2"})

			Expect(sm.statefulsets).Should(Equal(map[string]types.NamespacedName{
				"NS1/SS1": {Namespace: "NS1", Name: "SS1"},
				"NS1/SS2": {Namespace: "NS1", Name: "SS2"},
			}))
			Expect(sm.deployments).Should(Equal(map[string]types.NamespacedName{
				"NS1/DP1": {Namespace: "NS1", Name: "DP1"},
				"NS1/DP2": {Namespace: "NS1", Name: "DP2"},
			}))
			Expect(sm.daemonsets).Should(Equal(map[string]types.NamespacedName{
				"NS1/DS1": {Namespace: "NS1", Name: "DS1"},
				"NS1/DS2": {Namespace: "NS1", Name: "DS2"},
			}))
			Expect(sm.cronjobs).Should(Equal(map[string]types.NamespacedName{
				"NS1/CJ1": {Namespace: "NS1", Name: "CJ1"},
				"NS1/CJ2": {Namespace: "NS1", Name: "CJ2"},
			}))
			Expect(sm.certificatestatusrequests).Should(Equal(map[string]map[string]string{
				"CSR1": {"k8s-app": "CSR1"},
				"CSR2": {"k8s-app": "CSR2"},
			}))
		})

		It("should not contain the NamespacedNames for resources removed by calls to Remove<Resource", func() {
			sm.AddStatefulSets([]types.NamespacedName{
				{Namespace: "NS1", Name: "SS1"},
				{Namespace: "NS1", Name: "SS2"},
			})
			sm.AddDeployments([]types.NamespacedName{
				{Namespace: "NS1", Name: "DP1"},
				{Namespace: "NS1", Name: "DP2"},
			})
			sm.AddDaemonsets([]types.NamespacedName{
				{Namespace: "NS1", Name: "DS1"},
				{Namespace: "NS1", Name: "DS2"},
			})
			sm.AddCronJobs([]types.NamespacedName{
				{Namespace: "NS1", Name: "CJ1"},
				{Namespace: "NS1", Name: "CJ2"},
			})
			sm.AddCertificateSigningRequests("CSR1", map[string]string{"k8s-app": "CSR1"})
			sm.AddCertificateSigningRequests("CSR2", map[string]string{"k8s-app": "CSR2"})

			sm.RemoveStatefulSets(types.NamespacedName{Namespace: "NS1", Name: "SS2"})
			sm.RemoveDeployments(types.NamespacedName{Namespace: "NS1", Name: "DP2"})
			sm.RemoveDaemonsets(types.NamespacedName{Namespace: "NS1", Name: "DS2"})
			sm.RemoveCronJobs(types.NamespacedName{Namespace: "NS1", Name: "CJ2"})
			sm.RemoveCertificateSigningRequests("CSR2")

			Expect(sm.statefulsets).Should(Equal(map[string]types.NamespacedName{
				"NS1/SS1": {Namespace: "NS1", Name: "SS1"},
			}))
			Expect(sm.deployments).Should(Equal(map[string]types.NamespacedName{
				"NS1/DP1": {Namespace: "NS1", Name: "DP1"},
			}))
			Expect(sm.daemonsets).Should(Equal(map[string]types.NamespacedName{
				"NS1/DS1": {Namespace: "NS1", Name: "DS1"},
			}))
			Expect(sm.cronjobs).Should(Equal(map[string]types.NamespacedName{
				"NS1/CJ1": {Namespace: "NS1", Name: "CJ1"},
			}))
			Expect(sm.certificatestatusrequests).Should(Equal(map[string]map[string]string{
				"CSR1": {"k8s-app": "CSR1"},
			}))
		})

		DescribeTable("Monitor CSRs - k8s v1.18",
			func(csrs []*certV1beta1.CertificateSigningRequest, expectErr bool, expectPending bool) {
				for _, csr := range csrs {
					Expect(oldVersionClient.Create(ctx, csr)).NotTo(HaveOccurred())
				}
				pending, err := hasPendingCSR(ctx, oldVersionSm, map[string]string{"k8s-app": label})
				Expect(err != nil).To(Equal(expectErr))
				Expect(pending).To(Equal(expectPending))
			},
			Entry("no CSR is present - k8s v1.18", nil, false, false),
			Entry("1 pending CSR is present - k8s v1.18",
				[]*certV1beta1.CertificateSigningRequest{
					{ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels}}},
				false, true),
			Entry("1 pending CSR is present, but no labels - k8s v1.18",
				[]*certV1beta1.CertificateSigningRequest{
					{ObjectMeta: metav1.ObjectMeta{Name: "csr1"}}},
				false, false),
			Entry("1 approved CSR is present - k8s v1.18",
				[]*certV1beta1.CertificateSigningRequest{
					{ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status: certV1beta1.CertificateSigningRequestStatus{Certificate: []byte("cert"),
							Conditions: []certV1beta1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1beta1.CertificateApproved}}}},
				}, false, false),
			Entry("2 approved CSR are present - k8s v1.18",
				[]*certV1beta1.CertificateSigningRequest{
					{ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status: certV1beta1.CertificateSigningRequestStatus{Certificate: []byte("cert"),
							Conditions: []certV1beta1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1beta1.CertificateApproved}}}},
					{ObjectMeta: metav1.ObjectMeta{Name: "csr2", Labels: labels},
						Status: certV1beta1.CertificateSigningRequestStatus{Certificate: []byte("cert"),
							Conditions: []certV1beta1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1beta1.CertificateApproved}}}},
				}, false, false),
			Entry("1 approved, 1 pending CSR are present - k8s v1.18",
				[]*certV1beta1.CertificateSigningRequest{
					{ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status: certV1beta1.CertificateSigningRequestStatus{Certificate: []byte("cert"),
							Conditions: []certV1beta1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1beta1.CertificateApproved}}}},
					{ObjectMeta: metav1.ObjectMeta{Name: "csr2", Labels: labels}},
				}, false, true),
			Entry("1 pending CSR are present (approved: no, cert: yes) - k8s v1.18",
				[]*certV1beta1.CertificateSigningRequest{
					{ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status: certV1beta1.CertificateSigningRequestStatus{Certificate: []byte("cert")}},
				}, false, true),
			Entry("1 pending CSR are present (approved: yes, cert: no) - k8s v1.18",
				[]*certV1beta1.CertificateSigningRequest{
					{ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status: certV1beta1.CertificateSigningRequestStatus{
							Conditions: []certV1beta1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1beta1.CertificateApproved}}}},
					{ObjectMeta: metav1.ObjectMeta{Name: "csr2", Labels: labels}},
				}, false, true),
		)

		DescribeTable("Monitor CSRs - k8s v1.19",
			func(csrs []*certV1.CertificateSigningRequest, expectErr bool, expectPending bool) {
				for _, csr := range csrs {
					Expect(client.Create(ctx, csr)).NotTo(HaveOccurred())
				}
				pending, err := hasPendingCSR(ctx, sm, map[string]string{"k8s-app": label})
				Expect(err != nil).To(Equal(expectErr))
				Expect(pending).To(Equal(expectPending))
			},
			Entry("no CSR is present - k8s v1.19", nil, false, false),
			Entry("1 pending CSR is present - k8s v1.19",
				[]*certV1.CertificateSigningRequest{
					{ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels}}},
				false, true),
			Entry("1 pending CSR is present, but no labels - k8s v1.19",
				[]*certV1.CertificateSigningRequest{
					{ObjectMeta: metav1.ObjectMeta{Name: "csr1"}}},
				false, false),
			Entry("1 approved CSR is present - k8s v1.19",
				[]*certV1.CertificateSigningRequest{
					{ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status: certV1.CertificateSigningRequestStatus{Certificate: []byte("cert"),
							Conditions: []certV1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1.CertificateApproved}}}},
				}, false, false),
			Entry("2 approved CSR are present - k8s v1.19",
				[]*certV1.CertificateSigningRequest{
					{ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status: certV1.CertificateSigningRequestStatus{Certificate: []byte("cert"),
							Conditions: []certV1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1.CertificateApproved}}}},
					{ObjectMeta: metav1.ObjectMeta{Name: "csr2", Labels: labels},
						Status: certV1.CertificateSigningRequestStatus{Certificate: []byte("cert"),
							Conditions: []certV1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1.CertificateApproved}}}},
				}, false, false),
			Entry("1 approved, 1 pending CSR are present - k8s v1.19",
				[]*certV1.CertificateSigningRequest{
					{ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status: certV1.CertificateSigningRequestStatus{Certificate: []byte("cert"),
							Conditions: []certV1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1.CertificateApproved}}}},
					{ObjectMeta: metav1.ObjectMeta{Name: "csr2", Labels: labels}},
				}, false, true),
			Entry("1 pending CSR are present (approved: no, cert: yes) - k8s v1.19",
				[]*certV1.CertificateSigningRequest{
					{ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status: certV1.CertificateSigningRequestStatus{Certificate: []byte("cert")}},
				}, false, true),
			Entry("1 pending CSR are present (approved: yes, cert: no) - k8s v1.19",
				[]*certV1.CertificateSigningRequest{
					{ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status: certV1.CertificateSigningRequestStatus{
							Conditions: []certV1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1.CertificateApproved}}}},
					{ObjectMeta: metav1.ObjectMeta{Name: "csr2", Labels: labels}},
				}, false, true),
		)
	})
})
