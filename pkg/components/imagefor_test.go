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

package components

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	operator "github.com/tigera/operator/api/v1"
)

var _ = Describe("ImageFor", func() {
	// The generated component lists are the source of truth, so a key that no longer
	// names an entry in either list would make ImageFor error at render time.
	It("resolves every key for both variants", func() {
		for _, key := range ImageKeys {
			cal, err := ImageFor(operator.Calico, key)
			Expect(err).NotTo(HaveOccurred(), "Calico image for %q", key)
			Expect(cal.Image).To(Equal(key))

			ent, err := ImageFor(operator.CalicoEnterprise, key)
			Expect(err).NotTo(HaveOccurred(), "Enterprise image for %q", key)
			Expect(ent.Image).To(Equal(key))

			Expect(cal).NotTo(Equal(ent), "%q resolves to the same image for both variants, so it needs no key", key)
		}
	})

	It("errors on an image the variant does not supply", func() {
		_, err := ImageFor(operator.CalicoEnterprise, "whisker")
		Expect(err).To(HaveOccurred())
	})
})
