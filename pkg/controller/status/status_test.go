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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/tigera/operator/pkg/apis"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Status reporting tests", func() {
	var sm *StatusManager
	var client client.Client
	BeforeEach(func() {
		// Setup Scheme for all resources
		scheme := runtime.NewScheme()
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
		client = fake.NewFakeClientWithScheme(scheme)

		sm = New(client, "test-component")
		Expect(sm.IsAvailable()).To(BeFalse())
		sm.Enable()
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

})
