// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package apiserver

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("APIServer controller tests", func() {
	checkAnnotation := func(annotationValue string, expectedResult bool) {
		By("Creating a CRD")
		instance := &operatorv1.APIServer{
			TypeMeta: metav1.TypeMeta{Kind: "APIServer", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: "tigera-secure",
				Annotations: map[string]string{
					"tech-preview.operator.tigera.io/admission-controller-support": annotationValue,
				},
			},
		}
		By("Checking that the annotation is parsed")
		supportEnabled := isAdmissionControllerSupportEnabled(instance)
		Expect(supportEnabled).To(Equal(expectedResult))
	}

	It("should parse tech-preview annotation", func() {
		checkAnnotation("enabled", true)
		checkAnnotation("Enabled", true)
		checkAnnotation("somethingelse", false)
		checkAnnotation("", false)
	})

	It("should return false when annotation is not present", func() {
		instance := &operatorv1.APIServer{
			TypeMeta:   metav1.TypeMeta{Kind: "APIServer", APIVersion: "operator.tigera.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		}
		By("Checking that a missing annotation is considered as support not enabled")
		supportEnabled := isAdmissionControllerSupportEnabled(instance)
		Expect(supportEnabled).To(Equal(false))
	})

})
