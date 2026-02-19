// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package admission

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"

	opv1 "github.com/tigera/operator/api/v1"
)

var _ = Describe("MutatingAdmissionPolicies", func() {
	It("returns Calico MAPs when v3=true", func() {
		objs := GetMutatingAdmissionPolicies(opv1.Calico, true)
		Expect(objs).To(HaveLen(2))

		// Verify we get one MAP and one MAPB.
		var mapCount, mapbCount int
		for _, obj := range objs {
			switch obj.(type) {
			case *admissionv1beta1.MutatingAdmissionPolicy:
				mapCount++
			case *admissionv1beta1.MutatingAdmissionPolicyBinding:
				mapbCount++
			}
			// Verify the managed label is set.
			Expect(obj.GetLabels()).To(HaveKeyWithValue(ManagedMAPLabel, ManagedMAPLabelValue))
		}
		Expect(mapCount).To(Equal(1))
		Expect(mapbCount).To(Equal(1))
	})

	It("returns Enterprise MAPs when v3=true", func() {
		objs := GetMutatingAdmissionPolicies(opv1.TigeraSecureEnterprise, true)
		Expect(objs).To(HaveLen(2))

		var mapCount, mapbCount int
		for _, obj := range objs {
			switch obj.(type) {
			case *admissionv1beta1.MutatingAdmissionPolicy:
				mapCount++
			case *admissionv1beta1.MutatingAdmissionPolicyBinding:
				mapbCount++
			}
			Expect(obj.GetLabels()).To(HaveKeyWithValue(ManagedMAPLabel, ManagedMAPLabelValue))
		}
		Expect(mapCount).To(Equal(1))
		Expect(mapbCount).To(Equal(1))
	})

	It("returns empty when v3=false", func() {
		Expect(GetMutatingAdmissionPolicies(opv1.Calico, false)).To(BeEmpty())
		Expect(GetMutatingAdmissionPolicies(opv1.TigeraSecureEnterprise, false)).To(BeEmpty())
	})

	It("parses MAP names correctly", func() {
		objs := GetMutatingAdmissionPolicies(opv1.Calico, true)
		for _, obj := range objs {
			Expect(obj.GetName()).ToNot(BeEmpty())
		}
	})
})
