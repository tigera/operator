// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.

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

package crds

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	opv1 "github.com/tigera/operator/api/v1"
)

var _ = Describe("test crds pkg", func() {
	Context("GetCalicoCRDSource", func() {
		Measure("should quickly load calico source CRDs", func(b Benchmarker) {
			runtime := b.Time("runtime", func() {
				_ = getCalicoCRDSource()
			})
			Expect(runtime.Seconds()).Should(BeNumerically("<", 0.2), "loading calico CRDs shouldnt take too long.")
		}, 50)
	})
	Context("GetEnterpriseCRDSource", func() {
		Measure("should quickly load enterprise source CRDs", func(b Benchmarker) {
			runtime := b.Time("runtime", func() {
				_ = getEnterpriseCRDSource()
			})
			Expect(runtime.Seconds()).Should(BeNumerically("<", 0.2), "loading enterprise CRDs shouldnt take too long.")
		}, 50)
	})
	Context("GetOperatorCRDSource", func() {
		Measure("should quickly load operator source CRDs", func(b Benchmarker) {
			runtime := b.Time("runtime", func() {
				_ = getEnterpriseCRDSource()
			})
			Expect(runtime.Seconds()).Should(BeNumerically("<", 0.2), "loading operator CRDs shouldnt take too long.")
		}, 50)
	})
	Context("GetCRDs", func() {
		Measure("should quickly load calico CRDs", func(b Benchmarker) {
			runtime := b.Time("runtime", func() {
				_ = GetCRDs(opv1.Calico)
			})
			Expect(runtime.Seconds()).Should(BeNumerically("<", 0.2), "loading calico CRDs shouldnt take too long.")
		}, 50)
		Measure("should quickly load enterprise CRDs", func(b Benchmarker) {
			runtime := b.Time("runtime", func() {
				_ = GetCRDs(opv1.TigeraSecureEnterprise)
			})
			Expect(runtime.Seconds()).Should(BeNumerically("<", 0.2), "loading enterprise CRDs shouldnt take too long.")
		}, 50)
	})
})
