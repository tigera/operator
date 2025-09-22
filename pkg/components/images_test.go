// Copyright (c) 2019-2025 Tigera, Inc. All rights reserved.

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
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	op "github.com/tigera/operator/api/v1"
)

var _ = Describe("test GetReference", func() {
	Context("No registry override", func() {
		DescribeTable("should render",
			func(c Component, registry, image string) {
				Expect(GetReference(c, "", "", "", nil)).To(Equal(fmt.Sprintf("%s%s:%s", registry, image, c.Version)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, CalicoRegistry, "calico/node"),
			Entry("a tigera image correctly", ComponentTigeraNode, TigeraRegistry, "tigera/node"),
			Entry("an ECK image correctly", ComponentElasticsearchOperator, TigeraRegistry, "tigera/eck-operator"),
			Entry("an operator init image correctly", ComponentOperatorInit, InitRegistry, "tigera/operator"),
			Entry("a CSR init image correctly", ComponentCalicoCSRInitContainer, CalicoRegistry, "calico/key-cert-provisioner"),
			Entry("a CSR init image correctly", ComponentTigeraCSRInitContainer, TigeraRegistry, "tigera/key-cert-provisioner"),
		)
	})

	Context("UseDefault for registry and imagepath", func() {
		DescribeTable("should render",
			func(c Component, registry, image string) {
				ud := "UseDefault"
				Expect(GetReference(c, ud, ud, "", nil)).To(Equal(fmt.Sprintf("%s%s:%s", registry, image, c.Version)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, CalicoRegistry, "calico/node"),
			Entry("a tigera image correctly", ComponentTigeraNode, TigeraRegistry, "tigera/node"),
			Entry("an ECK image correctly", ComponentElasticsearchOperator, TigeraRegistry, "tigera/eck-operator"),
			Entry("an operator init image correctly", ComponentOperatorInit, InitRegistry, "tigera/operator"),
			Entry("a CSR init image correctly", ComponentCalicoCSRInitContainer, CalicoRegistry, "calico/key-cert-provisioner"),
			Entry("a CSR init image correctly", ComponentTigeraCSRInitContainer, TigeraRegistry, "tigera/key-cert-provisioner"),
		)
	})

	Context("registry override", func() {
		DescribeTable("should render",
			func(c Component, image string) {
				Expect(GetReference(c, "quay.io/", "", "", nil)).To(Equal(fmt.Sprintf("%s%s:%s", "quay.io/", image, c.Version)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, "calico/node"),
			Entry("a tigera image correctly", ComponentTigeraNode, "tigera/node"),
			Entry("an ECK image correctly", ComponentElasticsearchOperator, "tigera/eck-operator"),
			Entry("an operator init image correctly", ComponentOperatorInit, "tigera/operator"),
			Entry("a CSR init image correctly", ComponentCalicoCSRInitContainer, "calico/key-cert-provisioner"),
			Entry("a CSR init image correctly", ComponentTigeraCSRInitContainer, "tigera/key-cert-provisioner"),
		)
	})

	Context("image prefix override", func() {
		DescribeTable("should render",
			func(c Component, image string) {
				Expect(GetReference(c, "quay.io/", "", "prefix-", nil)).To(Equal(fmt.Sprintf("quay.io/%s:%s", image, c.Version)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, "calico/prefix-node"),
			Entry("a tigera image correctly", ComponentTigeraNode, "tigera/prefix-node"),
			Entry("an ECK image correctly", ComponentElasticsearchOperator, "tigera/prefix-eck-operator"),
			Entry("an operator init image correctly", ComponentOperatorInit, "tigera/prefix-operator"),
			Entry("a CSR init image correctly", ComponentCalicoCSRInitContainer, "calico/prefix-key-cert-provisioner"),
			Entry("a CSR init image correctly", ComponentTigeraCSRInitContainer, "tigera/prefix-key-cert-provisioner"),
		)
	})

	Context("imagepath override", func() {
		DescribeTable("should render",
			func(c Component, registry, image string) {
				Expect(GetReference(c, "", "userpath", "", nil)).To(Equal(fmt.Sprintf("%suserpath/%s:%s", registry, image, c.Version)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, CalicoRegistry, "node"),
			Entry("a tigera image correctly", ComponentTigeraNode, TigeraRegistry, "node"),
			Entry("an ECK image correctly", ComponentElasticsearchOperator, TigeraRegistry, "eck-operator"),
			Entry("an operator init image correctly", ComponentOperatorInit, InitRegistry, "operator"),
			Entry("a CSR init image correctly", ComponentCalicoCSRInitContainer, CalicoRegistry, "key-cert-provisioner"),
			Entry("a CSR init image correctly", ComponentTigeraCSRInitContainer, TigeraRegistry, "key-cert-provisioner"),
		)
	})
	Context("registry and imagepath override", func() {
		DescribeTable("should render",
			func(c Component, image string) {
				Expect(GetReference(c, "quay.io/extra/", "userpath", "", nil)).To(Equal(fmt.Sprintf("quay.io/extra/userpath/%s:%s", image, c.Version)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, "node"),
			Entry("a tigera image correctly", ComponentTigeraNode, "node"),
			Entry("an ECK image correctly", ComponentElasticsearchOperator, "eck-operator"),
			Entry("an operator init image correctly", ComponentOperatorInit, "operator"),
			Entry("a CSR init image correctly", ComponentCalicoCSRInitContainer, "key-cert-provisioner"),
			Entry("a CSR init image correctly", ComponentTigeraCSRInitContainer, "key-cert-provisioner"),
		)
	})
	Context("with an ImageSet", func() {
		DescribeTable("should render",
			func(c Component, image, hash string) {
				is := &op.ImageSet{
					Spec: op.ImageSetSpec{
						Images: []op.Image{
							{Image: "calico/node", Digest: "sha256:caliconodehash"},
							{Image: "tigera/node", Digest: "sha256:tigeranodehash"},
							{Image: "tigera/eck-operator", Digest: "sha256:eckeckoperatorhash"},
							{Image: "tigera/operator", Digest: "sha256:tigeraoperatorhash"},
							{Image: "tigera/key-cert-provisioner", Digest: "sha256:tigerakeycertprovisionerhash"},
						},
					},
				}
				Expect(GetReference(c, "quay.io/extra/", "userpath", "", is)).To(Equal(fmt.Sprintf("quay.io/extra/userpath/%s%s", image, hash)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, "node", "@sha256:caliconodehash"),
			Entry("a tigera image correctly", ComponentTigeraNode, "node", "@sha256:tigeranodehash"),
			Entry("an ECK image correctly", ComponentElasticsearchOperator, "eck-operator", "@sha256:eckeckoperatorhash"),
			Entry("an operator init image correctly", ComponentOperatorInit, "operator", "@sha256:tigeraoperatorhash"),
			Entry("a CSR init image correctly", ComponentTigeraCSRInitContainer, "key-cert-provisioner", "@sha256:tigerakeycertprovisionerhash"),
		)
	})
})
