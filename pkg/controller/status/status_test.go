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

package status_test

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/tigera/operator/pkg/apis"
	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/status"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Status reporting tests", func() {
	var sm *status.StatusManager
	var client client.Client
	BeforeEach(func() {
		// Setup Scheme for all resources
		scheme := runtime.NewScheme()
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
		client = fake.NewFakeClientWithScheme(scheme)

		sm = status.New(client, "test-component")
		Expect(sm.IsAvailable()).To(BeFalse())
		sm.Enable()
	})

	It("Should handle basic state changes", func() {
		By("Setting a degraded state")
		sm.SetDegraded("Degraded message", "Degraded reason")
		Expect(sm.IsAvailable()).To(BeFalse())
		expectState(client, operator.ConditionTrue, operator.ConditionFalse, operator.ConditionFalse)

		By("Setting a progressing state")
		sm.SetProgressing("Progressing message", "Progressing reason")
		Expect(sm.IsAvailable()).To(BeFalse())
		expectState(client, operator.ConditionTrue, operator.ConditionTrue, operator.ConditionFalse)

		By("Setting an available state")
		sm.SetAvailable("Available message", "Available reason")
		Expect(sm.IsAvailable()).To(BeTrue())
		expectState(client, operator.ConditionTrue, operator.ConditionFalse, operator.ConditionTrue)

		By("Clearing degraded state")
		sm.ClearDegraded()
		Expect(sm.IsAvailable()).To(BeTrue())
		expectState(client, operator.ConditionFalse, operator.ConditionFalse, operator.ConditionTrue)

		By("Clearing available state")
		sm.ClearAvailable()
		Expect(sm.IsAvailable()).To(BeFalse())
		expectState(client, operator.ConditionFalse, operator.ConditionFalse, operator.ConditionFalse)
	})
})

func expectState(client client.Client, degraded, progressing, available operator.ConditionStatus) {
	ts := &operator.TigeraStatus{ObjectMeta: metav1.ObjectMeta{Name: "test-component"}}
	err := client.Get(context.TODO(), types.NamespacedName{Name: "test-component"}, ts)
	Expect(err).NotTo(HaveOccurred())

	for _, condition := range ts.Status.Conditions {
		if condition.Type == operator.ComponentAvailable {
			Expect(condition.Status).To(Equal(available))
		} else if condition.Type == operator.ComponentDegraded {
			Expect(condition.Status).To(Equal(degraded))
		} else if condition.Type == operator.ComponentProgressing {
			Expect(condition.Status).To(Equal(progressing))
		}
	}
}
