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

// The real test here is simply calling these functions will result in a panic if any of the CRDs cannot be parsed

var _ = Describe("test crds pkg", func() {
	It("can parse Calico CRDs", func() {
		Expect(func() { Expect(getCalicoCRDSource()).ToNot(BeEmpty()) }).ToNot(Panic())
	})
	It("can parse Enterprise CRDs", func() {
		Expect(func() { Expect(getEnterpriseCRDSource()).ToNot(BeEmpty()) }).ToNot(Panic())
	})
	It("can parse Operator CRDs used with calico", func() {
		Expect(func() { Expect(getOperatorCRDSource(opv1.Calico)).ToNot(BeEmpty()) }).ToNot(Panic())
	})
	It("can parse Operator CRDs used with Enterprise", func() {
		Expect(func() { Expect(getOperatorCRDSource(opv1.TigeraSecureEnterprise)).ToNot(BeEmpty()) }).ToNot(Panic())
	})
	It("can get all CRDS used with Calico", func() {
		Expect(func() { Expect(GetCRDs(opv1.Calico)).ToNot(BeEmpty()) }).ToNot(Panic())
	})
	It("can get all CRDS used with Enterprise", func() {
		Expect(func() { Expect(GetCRDs(opv1.TigeraSecureEnterprise)).ToNot(BeEmpty()) }).ToNot(Panic())
	})
})
