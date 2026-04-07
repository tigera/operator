// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
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
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
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
		err := apis.AddToScheme(scheme, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(appsv1.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(batchv1.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(corev1.AddToScheme(scheme)).NotTo(HaveOccurred())
		client = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		sm = New(client, "test-component", &common.VersionInfo{Major: 1, Minor: 19}).(*statusManager)
		Expect(sm.IsAvailable()).To(BeFalse())

		oldScheme := runtime.NewScheme()
		Expect(certV1beta1.AddToScheme(oldScheme)).ShouldNot(HaveOccurred())
		err = apis.AddToScheme(oldScheme, false)
		Expect(err).NotTo(HaveOccurred())
		oldVersionClient = fake.NewClientBuilder().WithScheme(oldScheme).Build()

		oldVersionSm = New(oldVersionClient, "test-component", &common.VersionInfo{Major: 1, Minor: 18}).(*statusManager)
		Expect(oldVersionSm.IsAvailable()).To(BeFalse())
	})

	boolPtr := func(b bool) *bool { return &b }

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

		Context("when pod is crash looping", func() {
			var gen int64

			createCrashLoopPodAndDeployment := func(lastTermination *corev1.ContainerStateTerminated) {
				sm.ReadyToMonitor()
				podStatus := corev1.PodStatus{
					Phase: corev1.PodRunning,
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name: "test-container",
							State: corev1.ContainerState{
								Waiting: &corev1.ContainerStateWaiting{
									Reason: "CrashLoopBackOff",
								},
							},
							LastTerminationState: corev1.ContainerState{
								Terminated: lastTermination,
							},
						},
					},
				}
				Expect(client.Create(ctx, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "NS1",
						Name:      "DP1pod-crash",
						Labels:    map[string]string{"dp1Key": "dp1Value"},
					},
					Spec:   corev1.PodSpec{},
					Status: podStatus,
				})).NotTo(HaveOccurred())

				gen = 5
				replicas := int32(1)
				sm.AddDeployments([]types.NamespacedName{{Namespace: "NS1", Name: "DP1"}})
				Expect(client.Create(ctx, &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:  "NS1",
						Name:       "DP1",
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
						UnavailableReplicas: 1,
						AvailableReplicas:   0,
						ReadyReplicas:       0,
					},
				})).NotTo(HaveOccurred())
			}

			It("should include OOMKilled reason in degraded message", func() {
				createCrashLoopPodAndDeployment(&corev1.ContainerStateTerminated{
					Reason:   "OOMKilled",
					ExitCode: 137,
				})
				sm.updateStatus()
				Expect(sm.IsDegraded()).To(BeTrue())
				Expect(sm.failing).To(ContainElement(ContainSubstring("(OOMKilled, exit code 137)")))
			})

			It("should suggest liveness probe failure for exit code 137 with Error reason", func() {
				createCrashLoopPodAndDeployment(&corev1.ContainerStateTerminated{
					Reason:   "Error",
					ExitCode: 137,
				})
				sm.updateStatus()
				Expect(sm.IsDegraded()).To(BeTrue())
				Expect(sm.failing).To(ContainElement(ContainSubstring("possible liveness probe failure")))
			})

			It("should include exit code for other termination reasons", func() {
				createCrashLoopPodAndDeployment(&corev1.ContainerStateTerminated{
					Reason:   "Error",
					ExitCode: 1,
				})
				sm.updateStatus()
				Expect(sm.IsDegraded()).To(BeTrue())
				Expect(sm.failing).To(ContainElement(ContainSubstring("(Error, exit code 1)")))
			})

			It("should report crash loop without detail when no last termination state", func() {
				createCrashLoopPodAndDeployment(nil)
				sm.updateStatus()
				Expect(sm.IsDegraded()).To(BeTrue())
				Expect(sm.failing).To(ContainElement(And(
					ContainSubstring("crash looping container"),
					Not(ContainSubstring("exit code")),
				)))
			})
		})

		Context("when pod is running but not ready", func() {
			var gen int64
			BeforeEach(func() {
				sm.ReadyToMonitor()
				Expect(client.Create(ctx, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "NS1",
						Name:      "DP1pod-notready",
						Labels: map[string]string{
							"dp1Key": "dp1Value",
						},
					},
					Spec: corev1.PodSpec{},
					Status: corev1.PodStatus{
						Phase: corev1.PodRunning,
						Conditions: []corev1.PodCondition{
							{
								Type:   corev1.ContainersReady,
								Status: corev1.ConditionFalse,
							},
						},
					},
				})).NotTo(HaveOccurred())
				gen = 5
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
						UnavailableReplicas: 1,
						AvailableReplicas:   0,
						ReadyReplicas:       0,
					},
				})).NotTo(HaveOccurred())
				sm.updateStatus()
				Expect(sm.IsDegraded()).To(BeTrue())
				Expect(sm.failing).To(ContainElement(ContainSubstring("running but not ready")))
			})
		})

		Context("when a monitored workload is not found", func() {
			BeforeEach(func() {
				sm.ReadyToMonitor()
			})

			It("should report degraded when a DaemonSet is not found", func() {
				sm.AddDaemonsets([]types.NamespacedName{{Namespace: "NS1", Name: "missing-ds"}})
				sm.updateStatus()
				Expect(sm.IsDegraded()).To(BeTrue())
				Expect(sm.failing).To(ContainElement(ContainSubstring(`DaemonSet "NS1/missing-ds" not found`)))
			})

			It("should report degraded when a Deployment is not found", func() {
				sm.AddDeployments([]types.NamespacedName{{Namespace: "NS1", Name: "missing-dep"}})
				sm.updateStatus()
				Expect(sm.IsDegraded()).To(BeTrue())
				Expect(sm.failing).To(ContainElement(ContainSubstring(`Deployment "NS1/missing-dep" not found`)))
			})

			It("should report degraded when a StatefulSet is not found", func() {
				sm.AddStatefulSets([]types.NamespacedName{{Namespace: "NS1", Name: "missing-ss"}})
				sm.updateStatus()
				Expect(sm.IsDegraded()).To(BeTrue())
				Expect(sm.failing).To(ContainElement(ContainSubstring(`StatefulSet "NS1/missing-ss" not found`)))
			})

			It("should report degraded when a CronJob is not found", func() {
				sm.AddCronJobs([]types.NamespacedName{{Namespace: "NS1", Name: "missing-cj"}})
				sm.updateStatus()
				Expect(sm.IsDegraded()).To(BeTrue())
				Expect(sm.failing).To(ContainElement(ContainSubstring(`CronJob "NS1/missing-cj" not found`)))
			})
		})

		Context("during a rollout with mixed old and new revision pods", func() {
			BeforeEach(func() {
				sm.ReadyToMonitor()
			})

			It("should prioritize new-revision pod failures over old-revision failures", func() {
				sm.AddDeployments([]types.NamespacedName{{Namespace: "NS1", Name: "DP1"}})
				replicas := int32(2)
				gen := int64(5)

				// Create the Deployment.
				Expect(client.Create(ctx, &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:  "NS1",
						Name:       "DP1",
						UID:        "dp1-uid",
						Generation: gen,
					},
					Spec: appsv1.DeploymentSpec{
						Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "dp1"}},
						Replicas: &replicas,
					},
					Status: appsv1.DeploymentStatus{
						ObservedGeneration:  gen,
						UnavailableReplicas: 2,
						AvailableReplicas:   0,
						ReadyReplicas:       0,
					},
				})).NotTo(HaveOccurred())

				// Current ReplicaSet.
				Expect(client.Create(ctx, &appsv1.ReplicaSet{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "NS1",
						Name:      "DP1-new",
						Labels:    map[string]string{"app": "dp1", appsv1.DefaultDeploymentUniqueLabelKey: "new-hash"},
						OwnerReferences: []metav1.OwnerReference{
							{UID: "dp1-uid", Controller: boolPtr(true)},
						},
					},
					Spec: appsv1.ReplicaSetSpec{
						Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "dp1"}},
					},
					Status: appsv1.ReplicaSetStatus{Replicas: 1},
				})).NotTo(HaveOccurred())

				// Old ReplicaSet.
				Expect(client.Create(ctx, &appsv1.ReplicaSet{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "NS1",
						Name:      "DP1-old",
						Labels:    map[string]string{"app": "dp1", appsv1.DefaultDeploymentUniqueLabelKey: "old-hash"},
						OwnerReferences: []metav1.OwnerReference{
							{UID: "dp1-uid", Controller: boolPtr(true)},
						},
					},
					Spec: appsv1.ReplicaSetSpec{
						Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "dp1"}},
					},
					Status: appsv1.ReplicaSetStatus{Replicas: 0},
				})).NotTo(HaveOccurred())

				// New-revision pod: crash looping.
				Expect(client.Create(ctx, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "NS1",
						Name:      "dp1-new-pod",
						Labels:    map[string]string{"app": "dp1", appsv1.DefaultDeploymentUniqueLabelKey: "new-hash"},
					},
					Spec: corev1.PodSpec{},
					Status: corev1.PodStatus{
						Phase: corev1.PodRunning,
						ContainerStatuses: []corev1.ContainerStatus{
							{
								Name:  "c1",
								State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
							},
						},
					},
				})).NotTo(HaveOccurred())

				// Old-revision pod: also crash looping but with different reason.
				Expect(client.Create(ctx, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "NS1",
						Name:      "dp1-old-pod",
						Labels:    map[string]string{"app": "dp1", appsv1.DefaultDeploymentUniqueLabelKey: "old-hash"},
					},
					Spec: corev1.PodSpec{},
					Status: corev1.PodStatus{
						Phase: corev1.PodRunning,
						ContainerStatuses: []corev1.ContainerStatus{
							{
								Name: "c1",
								State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
								LastTerminationState: corev1.ContainerState{
									Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled", ExitCode: 137},
								},
							},
						},
					},
				})).NotTo(HaveOccurred())

				sm.updateStatus()
				Expect(sm.IsDegraded()).To(BeTrue())
				Expect(sm.failing).To(HaveLen(2))
				// New-revision issue should appear first.
				Expect(sm.failing[0]).NotTo(ContainSubstring("old revision"))
				Expect(sm.failing[1]).To(ContainSubstring("old revision"))
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

		It("should include warnings in Available message", func() {
			sm.ReadyToMonitor()
			Expect(sm.IsAvailable()).To(BeTrue())

			sm.SetWarning("cert-a", "BYO certificate \"a\" expires in 10 days")
			sm.updateStatus()

			stat := &operator.TigeraStatus{}
			err := client.Get(context.TODO(), types.NamespacedName{Name: "test-component"}, stat)
			Expect(err).NotTo(HaveOccurred())
			for _, c := range stat.Status.Conditions {
				if c.Type == operator.ComponentAvailable && c.Status == operator.ConditionTrue {
					Expect(c.Message).To(ContainSubstring("All objects available"))
					Expect(c.Message).To(ContainSubstring("BYO certificate \"a\" expires in 10 days"))
				}
			}
		})

		It("should clear warnings from Available message", func() {
			sm.ReadyToMonitor()
			sm.SetWarning("cert-a", "BYO certificate \"a\" expires in 10 days")
			sm.updateStatus()
			sm.ClearWarning("cert-a")
			sm.updateStatus()

			stat := &operator.TigeraStatus{}
			err := client.Get(context.TODO(), types.NamespacedName{Name: "test-component"}, stat)
			Expect(err).NotTo(HaveOccurred())
			for _, c := range stat.Status.Conditions {
				if c.Type == operator.ComponentAvailable && c.Status == operator.ConditionTrue {
					Expect(c.Message).To(Equal("All objects available"))
				}
			}
		})

		It("should sort multiple warnings deterministically", func() {
			sm.ReadyToMonitor()
			sm.SetWarning("cert-b", "warning B")
			sm.SetWarning("cert-a", "warning A")
			Expect(sm.warningMessage()).To(Equal("warning A; warning B"))
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
			Expect(sm.degradedMessage()).To(Equal("Controller set us degraded\nThis pod has died"))
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
					{ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels}},
				},
				false, true),
			Entry("1 pending CSR is present, but no labels - k8s v1.18",
				[]*certV1beta1.CertificateSigningRequest{
					{ObjectMeta: metav1.ObjectMeta{Name: "csr1"}},
				},
				false, false),
			Entry("1 approved CSR is present - k8s v1.18",
				[]*certV1beta1.CertificateSigningRequest{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status: certV1beta1.CertificateSigningRequestStatus{
							Certificate: []byte("cert"),
							Conditions:  []certV1beta1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1beta1.CertificateApproved}},
						},
					},
				}, false, false),
			Entry("2 approved CSR are present - k8s v1.18",
				[]*certV1beta1.CertificateSigningRequest{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status: certV1beta1.CertificateSigningRequestStatus{
							Certificate: []byte("cert"),
							Conditions:  []certV1beta1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1beta1.CertificateApproved}},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{Name: "csr2", Labels: labels},
						Status: certV1beta1.CertificateSigningRequestStatus{
							Certificate: []byte("cert"),
							Conditions:  []certV1beta1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1beta1.CertificateApproved}},
						},
					},
				}, false, false),
			Entry("1 approved, 1 pending CSR are present - k8s v1.18",
				[]*certV1beta1.CertificateSigningRequest{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status: certV1beta1.CertificateSigningRequestStatus{
							Certificate: []byte("cert"),
							Conditions:  []certV1beta1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1beta1.CertificateApproved}},
						},
					},
					{ObjectMeta: metav1.ObjectMeta{Name: "csr2", Labels: labels}},
				}, false, true),
			Entry("1 pending CSR are present (approved: no, cert: yes) - k8s v1.18",
				[]*certV1beta1.CertificateSigningRequest{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status:     certV1beta1.CertificateSigningRequestStatus{Certificate: []byte("cert")},
					},
				}, false, true),
			Entry("1 pending CSR are present (approved: yes, cert: no) - k8s v1.18",
				[]*certV1beta1.CertificateSigningRequest{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status: certV1beta1.CertificateSigningRequestStatus{
							Conditions: []certV1beta1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1beta1.CertificateApproved}},
						},
					},
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
					{ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels}},
				},
				false, true),
			Entry("1 pending CSR is present, but no labels - k8s v1.19",
				[]*certV1.CertificateSigningRequest{
					{ObjectMeta: metav1.ObjectMeta{Name: "csr1"}},
				},
				false, false),
			Entry("1 approved CSR is present - k8s v1.19",
				[]*certV1.CertificateSigningRequest{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status: certV1.CertificateSigningRequestStatus{
							Certificate: []byte("cert"),
							Conditions:  []certV1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1.CertificateApproved}},
						},
					},
				}, false, false),
			Entry("2 approved CSR are present - k8s v1.19",
				[]*certV1.CertificateSigningRequest{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status: certV1.CertificateSigningRequestStatus{
							Certificate: []byte("cert"),
							Conditions:  []certV1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1.CertificateApproved}},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{Name: "csr2", Labels: labels},
						Status: certV1.CertificateSigningRequestStatus{
							Certificate: []byte("cert"),
							Conditions:  []certV1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1.CertificateApproved}},
						},
					},
				}, false, false),
			Entry("1 approved, 1 pending CSR are present - k8s v1.19",
				[]*certV1.CertificateSigningRequest{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status: certV1.CertificateSigningRequestStatus{
							Certificate: []byte("cert"),
							Conditions:  []certV1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1.CertificateApproved}},
						},
					},
					{ObjectMeta: metav1.ObjectMeta{Name: "csr2", Labels: labels}},
				}, false, true),
			Entry("1 pending CSR are present (approved: no, cert: yes) - k8s v1.19",
				[]*certV1.CertificateSigningRequest{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status:     certV1.CertificateSigningRequestStatus{Certificate: []byte("cert")},
					},
				}, false, true),
			Entry("1 pending CSR are present (approved: yes, cert: no) - k8s v1.19",
				[]*certV1.CertificateSigningRequest{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "csr1", Labels: labels},
						Status: certV1.CertificateSigningRequestStatus{
							Conditions: []certV1.CertificateSigningRequestCondition{{Status: corev1.ConditionTrue, Type: certV1.CertificateApproved}},
						},
					},
					{ObjectMeta: metav1.ObjectMeta{Name: "csr2", Labels: labels}},
				}, false, true),
		)
	})

	Describe("podIssue", func() {
		It("should produce distinct keys for different crash reasons", func() {
			oom := podIssue{
				issueType:         issueCrashLoopBackOff,
				terminationReason: "OOMKilled",
				exitCode:          137,
			}
			errExit1 := podIssue{
				issueType:         issueCrashLoopBackOff,
				terminationReason: terminationReasonError,
				exitCode:          1,
			}
			Expect(oom.key()).NotTo(Equal(errExit1.key()))
		})

		It("should produce the same key for same issue type with no termination context", func() {
			a := podIssue{issueType: issueNotReady}
			b := podIssue{issueType: issueNotReady}
			Expect(a.key()).To(Equal(b.key()))
		})

		It("should produce distinct keys for different issue types", func() {
			a := podIssue{issueType: issueCrashLoopBackOff}
			b := podIssue{issueType: issueImagePull}
			Expect(a.key()).NotTo(Equal(b.key()))
		})
	})

	Describe("summarizeIssues", func() {
		It("should deduplicate issues with the same key", func() {
			issues := []podIssue{
				{severity: severityFailing, issueType: issueCrashLoopBackOff, message: "Pod ns/pod1 has crash looping container: c1", terminationReason: "OOMKilled", exitCode: 137},
				{severity: severityFailing, issueType: issueCrashLoopBackOff, message: "Pod ns/pod2 has crash looping container: c1", terminationReason: "OOMKilled", exitCode: 137},
				{severity: severityFailing, issueType: issueCrashLoopBackOff, message: "Pod ns/pod3 has crash looping container: c1", terminationReason: "OOMKilled", exitCode: 137},
			}
			failing, progressing := summarizeIssues(issues)
			Expect(failing).To(HaveLen(1))
			Expect(failing[0]).To(ContainSubstring("3 pods affected"))
			Expect(progressing).To(BeEmpty())
		})

		It("should cap at 3 unique reasons", func() {
			issues := []podIssue{
				{severity: severityFailing, issueType: issueCrashLoopBackOff, message: "msg1", terminationReason: "OOMKilled", exitCode: 137},
				{severity: severityFailing, issueType: issueImagePull, message: "msg2"},
				{severity: severityFailing, issueType: issueTerminated, message: "msg3", terminationReason: terminationReasonError, exitCode: 1},
				{severity: severityFailing, issueType: issuePodFailed, message: "msg4"},
			}
			failing, _ := summarizeIssues(issues)
			Expect(failing).To(HaveLen(3))
		})

		It("should prioritize new-revision pods over old-revision pods", func() {
			issues := []podIssue{
				{severity: severityFailing, issueType: issueCrashLoopBackOff, message: "old pod crash", isOldRevision: true, terminationReason: "OOMKilled", exitCode: 137},
				{severity: severityFailing, issueType: issueCrashLoopBackOff, message: "new pod crash", isOldRevision: false, terminationReason: terminationReasonError, exitCode: 1},
			}
			failing, _ := summarizeIssues(issues)
			Expect(failing).To(HaveLen(2))
			Expect(failing[0]).To(ContainSubstring("new pod crash"))
			Expect(failing[1]).To(ContainSubstring("old pod crash"))
			Expect(failing[1]).To(ContainSubstring("old revision"))
		})

		It("should split failing and progressing", func() {
			issues := []podIssue{
				{severity: severityFailing, issueType: issueNotReady, message: "Pod ns/p1 is running but not ready"},
				{severity: severityProgressing, issueType: issuePending, message: "Pod ns/p2 is pending: Unschedulable"},
			}
			failing, progressing := summarizeIssues(issues)
			Expect(failing).To(HaveLen(1))
			Expect(progressing).To(HaveLen(1))
			Expect(progressing[0]).To(ContainSubstring("pending"))
		})

		It("should annotate old revision issues", func() {
			issues := []podIssue{
				{severity: severityFailing, issueType: issueNotReady, message: "Pod ns/p1 is running but not ready", isOldRevision: true},
			}
			failing, _ := summarizeIssues(issues)
			Expect(failing).To(HaveLen(1))
			Expect(failing[0]).To(ContainSubstring("old revision"))
		})

		It("should return empty slices for no issues", func() {
			failing, progressing := summarizeIssues(nil)
			Expect(failing).To(BeEmpty())
			Expect(progressing).To(BeEmpty())
		})
	})

	Describe("diagnosePods", func() {
		var sm *statusManager
		var cl controllerRuntimeClient.Client
		var ctx = context.Background()

		BeforeEach(func() {
			scheme := runtime.NewScheme()
			Expect(appsv1.AddToScheme(scheme)).NotTo(HaveOccurred())
			Expect(corev1.AddToScheme(scheme)).NotTo(HaveOccurred())
			err := apis.AddToScheme(scheme, false)
			Expect(err).NotTo(HaveOccurred())
			cl = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
			sm = New(cl, "test", &common.VersionInfo{Major: 1, Minor: 19}).(*statusManager)
		})

		selector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}}
		podMeta := metav1.ObjectMeta{Namespace: "ns", Name: "pod1", Labels: map[string]string{"app": "test"}}

		It("should detect CrashLoopBackOff with OOMKilled context", func() {
			Expect(cl.Create(ctx, &corev1.Pod{
				ObjectMeta: podMeta,
				Spec:       corev1.PodSpec{},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name:  "c1",
							State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
							LastTerminationState: corev1.ContainerState{
								Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled", ExitCode: 137},
							},
						},
					},
				},
			})).NotTo(HaveOccurred())
			issues := sm.diagnosePods(selector, "ns", "")
			Expect(issues).To(HaveLen(1))
			Expect(issues[0].issueType).To(Equal(issueCrashLoopBackOff))
			Expect(issues[0].severity).To(Equal(severityFailing))
			Expect(issues[0].terminationReason).To(Equal("OOMKilled"))
			Expect(issues[0].exitCode).To(BeEquivalentTo(137))
			Expect(issues[0].message).To(ContainSubstring("OOMKilled"))
		})

		It("should detect CrashLoopBackOff with possible liveness probe failure", func() {
			Expect(cl.Create(ctx, &corev1.Pod{
				ObjectMeta: podMeta,
				Spec:       corev1.PodSpec{},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name:  "c1",
							State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
							LastTerminationState: corev1.ContainerState{
								Terminated: &corev1.ContainerStateTerminated{Reason: terminationReasonError, ExitCode: exitCodeSIGKILL},
							},
						},
					},
				},
			})).NotTo(HaveOccurred())
			issues := sm.diagnosePods(selector, "ns", "")
			Expect(issues).To(HaveLen(1))
			Expect(issues[0].message).To(ContainSubstring("possible liveness probe failure"))
		})

		It("should detect ImagePullBackOff", func() {
			Expect(cl.Create(ctx, &corev1.Pod{
				ObjectMeta: podMeta,
				Spec:       corev1.PodSpec{},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name:  "c1",
							State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff"}},
						},
					},
				},
			})).NotTo(HaveOccurred())
			issues := sm.diagnosePods(selector, "ns", "")
			Expect(issues).To(HaveLen(1))
			Expect(issues[0].issueType).To(Equal(issueImagePull))
			Expect(issues[0].severity).To(Equal(severityFailing))
		})

		It("should detect terminated container with Error", func() {
			Expect(cl.Create(ctx, &corev1.Pod{
				ObjectMeta: podMeta,
				Spec:       corev1.PodSpec{},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name:  "c1",
							State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: terminationReasonError}},
						},
					},
				},
			})).NotTo(HaveOccurred())
			issues := sm.diagnosePods(selector, "ns", "")
			Expect(issues).To(HaveLen(1))
			Expect(issues[0].issueType).To(Equal(issueTerminated))
		})

		It("should detect pod in Failed phase", func() {
			Expect(cl.Create(ctx, &corev1.Pod{
				ObjectMeta: podMeta,
				Spec:       corev1.PodSpec{},
				Status:     corev1.PodStatus{Phase: corev1.PodFailed},
			})).NotTo(HaveOccurred())
			issues := sm.diagnosePods(selector, "ns", "")
			Expect(issues).To(HaveLen(1))
			Expect(issues[0].issueType).To(Equal(issuePodFailed))
			Expect(issues[0].severity).To(Equal(severityFailing))
		})

		It("should detect running but not ready", func() {
			Expect(cl.Create(ctx, &corev1.Pod{
				ObjectMeta: podMeta,
				Spec:       corev1.PodSpec{},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					Conditions: []corev1.PodCondition{
						{Type: corev1.ContainersReady, Status: corev1.ConditionFalse},
					},
				},
			})).NotTo(HaveOccurred())
			issues := sm.diagnosePods(selector, "ns", "")
			Expect(issues).To(HaveLen(1))
			Expect(issues[0].issueType).To(Equal(issueNotReady))
			Expect(issues[0].severity).To(Equal(severityFailing))
		})

		It("should detect pending unschedulable pod with scheduler reason", func() {
			Expect(cl.Create(ctx, &corev1.Pod{
				ObjectMeta: podMeta,
				Spec:       corev1.PodSpec{},
				Status: corev1.PodStatus{
					Phase: corev1.PodPending,
					Conditions: []corev1.PodCondition{
						{
							Type:    corev1.PodScheduled,
							Status:  corev1.ConditionFalse,
							Message: "0/3 nodes are available: 3 Insufficient memory",
						},
					},
				},
			})).NotTo(HaveOccurred())
			issues := sm.diagnosePods(selector, "ns", "")
			Expect(issues).To(HaveLen(1))
			Expect(issues[0].issueType).To(Equal(issuePending))
			Expect(issues[0].severity).To(Equal(severityProgressing))
			Expect(issues[0].message).To(ContainSubstring("Insufficient memory"))
		})

		It("should detect pending pod without scheduler condition", func() {
			Expect(cl.Create(ctx, &corev1.Pod{
				ObjectMeta: podMeta,
				Spec:       corev1.PodSpec{},
				Status:     corev1.PodStatus{Phase: corev1.PodPending},
			})).NotTo(HaveOccurred())
			issues := sm.diagnosePods(selector, "ns", "")
			Expect(issues).To(HaveLen(1))
			Expect(issues[0].issueType).To(Equal(issuePending))
			Expect(issues[0].severity).To(Equal(severityProgressing))
		})

		It("should report multiple issues from different pods", func() {
			pod1 := podMeta.DeepCopy()
			pod1.Name = "pod-crash"
			Expect(cl.Create(ctx, &corev1.Pod{
				ObjectMeta: *pod1,
				Spec:       corev1.PodSpec{},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name:  "c1",
							State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
						},
					},
				},
			})).NotTo(HaveOccurred())

			pod2 := podMeta.DeepCopy()
			pod2.Name = "pod-pending"
			Expect(cl.Create(ctx, &corev1.Pod{
				ObjectMeta: *pod2,
				Spec:       corev1.PodSpec{},
				Status:     corev1.PodStatus{Phase: corev1.PodPending},
			})).NotTo(HaveOccurred())

			issues := sm.diagnosePods(selector, "ns", "")
			Expect(issues).To(HaveLen(2))
		})

		It("should return no issues for healthy pods", func() {
			Expect(cl.Create(ctx, &corev1.Pod{
				ObjectMeta: podMeta,
				Spec:       corev1.PodSpec{},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					Conditions: []corev1.PodCondition{
						{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
					},
				},
			})).NotTo(HaveOccurred())
			issues := sm.diagnosePods(selector, "ns", "")
			Expect(issues).To(BeEmpty())
		})
	})

	Describe("currentRevision helpers", func() {
		var sm *statusManager
		var cl controllerRuntimeClient.Client
		var ctx = context.Background()

		BeforeEach(func() {
			scheme := runtime.NewScheme()
			Expect(appsv1.AddToScheme(scheme)).NotTo(HaveOccurred())
			Expect(corev1.AddToScheme(scheme)).NotTo(HaveOccurred())
			err := apis.AddToScheme(scheme, false)
			Expect(err).NotTo(HaveOccurred())
			cl = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
			sm = New(cl, "test", &common.VersionInfo{Major: 1, Minor: 19}).(*statusManager)
		})

		Describe("currentDeploymentRevision", func() {
			It("should return the pod-template-hash of the newest ReplicaSet", func() {
				dep := &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "dep1", UID: "dep-uid"},
					Spec: appsv1.DeploymentSpec{
						Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
					},
				}
				// Current ReplicaSet.
				Expect(cl.Create(ctx, &appsv1.ReplicaSet{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns",
						Name:      "dep1-abc123",
						Labels:    map[string]string{"app": "test", appsv1.DefaultDeploymentUniqueLabelKey: "abc123"},
						OwnerReferences: []metav1.OwnerReference{
							{UID: "dep-uid", Controller: boolPtr(true)},
						},
					},
					Spec: appsv1.ReplicaSetSpec{
						Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
					},
					Status: appsv1.ReplicaSetStatus{Replicas: 1},
				})).NotTo(HaveOccurred())
				// Old ReplicaSet.
				Expect(cl.Create(ctx, &appsv1.ReplicaSet{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns",
						Name:      "dep1-old999",
						Labels:    map[string]string{"app": "test", appsv1.DefaultDeploymentUniqueLabelKey: "old999"},
						OwnerReferences: []metav1.OwnerReference{
							{UID: "dep-uid", Controller: boolPtr(true)},
						},
					},
					Spec: appsv1.ReplicaSetSpec{
						Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
					},
					Status: appsv1.ReplicaSetStatus{Replicas: 0},
				})).NotTo(HaveOccurred())

				rev := sm.currentDeploymentRevision(dep)
				Expect(rev).To(Equal("abc123"))
			})

			It("should return empty string when no ReplicaSets exist", func() {
				dep := &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "dep1", UID: "dep-uid"},
					Spec: appsv1.DeploymentSpec{
						Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
					},
				}
				rev := sm.currentDeploymentRevision(dep)
				Expect(rev).To(BeEmpty())
			})
		})

		Describe("currentDaemonSetRevision", func() {
			It("should return the hash of the highest-revision ControllerRevision", func() {
				ds := &appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ds1", UID: "ds-uid"},
				}
				Expect(cl.Create(ctx, &appsv1.ControllerRevision{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns",
						Name:      "ds1-rev1",
						Labels:    map[string]string{appsv1.ControllerRevisionHashLabelKey: "hash-old"},
						OwnerReferences: []metav1.OwnerReference{
							{UID: "ds-uid", Controller: boolPtr(true)},
						},
					},
					Revision: 1,
				})).NotTo(HaveOccurred())
				Expect(cl.Create(ctx, &appsv1.ControllerRevision{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns",
						Name:      "ds1-rev2",
						Labels:    map[string]string{appsv1.ControllerRevisionHashLabelKey: "hash-new"},
						OwnerReferences: []metav1.OwnerReference{
							{UID: "ds-uid", Controller: boolPtr(true)},
						},
					},
					Revision: 2,
				})).NotTo(HaveOccurred())

				rev := sm.currentDaemonSetRevision(ds)
				Expect(rev).To(Equal("hash-new"))
			})

			It("should return empty string when no ControllerRevisions exist", func() {
				ds := &appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ds1", UID: "ds-uid"},
				}
				rev := sm.currentDaemonSetRevision(ds)
				Expect(rev).To(BeEmpty())
			})
		})
	})
})
