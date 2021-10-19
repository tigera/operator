// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package common

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Test get expected Typha scale", func() {

	It("should return expected Typha scale", func() {
		Expect(GetExpectedTyphaScale(-1)).To(Equal(1))
		Expect(GetExpectedTyphaScale(0)).To(Equal(1))
		Expect(GetExpectedTyphaScale(3)).To(Equal(3))
		Expect(GetExpectedTyphaScale(4)).To(Equal(3))
		Expect(GetExpectedTyphaScale(200)).To(Equal(3))
		Expect(GetExpectedTyphaScale(400)).To(Equal(4))
		Expect(GetExpectedTyphaScale(800)).To(Equal(6))
	})

})
