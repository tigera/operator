// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/gomega"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
)

var _ = Describe("Status reporting tests", func() {
	var sm *statusManager
	var client client.Client
	BeforeEach(func() {
		// Setup Scheme for all resources
		scheme := runtime.NewScheme()
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
		client = fake.NewFakeClientWithScheme(scheme)

		sm = &statusManager{
			client:       client,
			component:    "test-component",
			daemonsets:   make(map[string]types.NamespacedName),
			deployments:  make(map[string]types.NamespacedName),
			statefulsets: make(map[string]types.NamespacedName),
			cronjobs:     make(map[string]types.NamespacedName),
		}

		Expect(sm.IsAvailable()).To(BeFalse())
	})

	Describe("without CR found", func() {
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
			ts := &operator.TigeraStatus{ObjectMeta: metav1.ObjectMeta{Name: "test-component"}}
			err := client.Create(context.TODO(), ts)
			Expect(err).NotTo(HaveOccurred())
			sm.OnCRNotFound()
			sm.updateStatus()
			stat := &operator.TigeraStatus{}
			err = client.Get(context.TODO(), types.NamespacedName{Name: "test-component"}, stat)
			Expect(err).To(HaveOccurred())
			Expect(apierrs.IsNotFound(err)).To(BeTrue())
		})
	})

	Describe("with CR found", func() {
		BeforeEach(func() {
			sm.OnCRFound()
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

		It("should generate correct degraded reasons", func() {
			Expect(sm.degradedReason()).To(Equal(""))
			sm.failing = []string{"This pod has died"}
			Expect(sm.degradedReason()).To(Equal("Some pods are failing"))
			sm.explicitDegradedReason = "Controller set us degraded"
			Expect(sm.degradedReason()).To(Equal("Controller set us degraded; Some pods are failing"))
		})

		It("should generate correct degraded messages", func() {
			Expect(sm.degradedReason()).To(Equal(""))
			sm.failing = []string{"This pod has died"}
			Expect(sm.degradedMessage()).To(Equal("This pod has died"))
			sm.explicitDegradedMsg = "Controller set us degraded"
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

			sm.RemoveStatefulSets(types.NamespacedName{Namespace: "NS1", Name: "SS2"})
			sm.RemoveDeployments(types.NamespacedName{Namespace: "NS1", Name: "DP2"})
			sm.RemoveDaemonsets(types.NamespacedName{Namespace: "NS1", Name: "DS2"})
			sm.RemoveCronJobs(types.NamespacedName{Namespace: "NS1", Name: "CJ2"})

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
		})
	})
})
