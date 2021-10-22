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

package components

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	op "github.com/tigera/operator/api/v1"
)

var _ = Describe("test external ES GetReference", func() {
	BeforeEach(func() {
		ElasticExternal = true
	})
	AfterEach(func() {
		ElasticExternal = false
	})
	Context("check esproxy", func() {
		It("should render a es-proxy image correctly", func() {
			Expect(GetReference(ComponentEsProxy, "", "", "", nil)).To(Equal("gcr.io/tigera-tesla/tigera/es-proxy:tesla-" + ComponentEsProxy.Version))
		})
		It("should render a es-proxy with UseDefault", func() {
			ud := "UseDefault"
			Expect(GetReference(ComponentEsProxy, ud, ud, "", nil)).To(Equal("gcr.io/tigera-tesla/tigera/es-proxy:tesla-" + ComponentEsProxy.Version))
		})
		It("should render a es-proxy with registry override", func() {
			Expect(GetReference(ComponentEsProxy, "quay.io/", "", "", nil)).To(Equal("quay.io/tigera/es-proxy:tesla-" + ComponentEsProxy.Version))
		})
		It("should render a calico image correctly", func() {
			is := &op.ImageSet{
				Spec: op.ImageSetSpec{
					Images: []op.Image{
						{Image: "tigera/es-proxy", Digest: "sha256:esproxyhash"},
					},
				},
			}
			Expect(GetReference(ComponentEsProxy, "quay.io/extra/", "userpath", "", is)).To(Equal("quay.io/extra/userpath/es-proxy@sha256:esproxyhash"))
		})
	})
})
