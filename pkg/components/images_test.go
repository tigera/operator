// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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
			func(c component, registry, image string) {
				Expect(GetReference(c, "", "", "", nil)).To(Equal(fmt.Sprintf("%s%s:%s", registry, image, c.Version)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, CalicoRegistry, "calico/node"),
			Entry("a tigera image correctly", ComponentTigeraNode, TigeraRegistry, "tigera/cnx-node"),
			Entry("an ECK image correctly", ComponentElasticsearchOperator, TigeraRegistry, "tigera/eck-operator"),
			Entry("an operator init image correctly", ComponentOperatorInit, InitRegistry, "tigera/operator"),
			Entry("a CSR init image correctly", ComponentCalicoCSRInitContainer, CalicoRegistry, "calico/key-cert-provisioner"),
			Entry("a CSR init image correctly", ComponentTigeraCSRInitContainer, TigeraRegistry, "tigera/key-cert-provisioner"),
		)
	})

	Context("UseDefault for registry and imagepath", func() {
		DescribeTable("should render",
			func(c component, registry, image string) {
				ud := "UseDefault"
				Expect(GetReference(c, ud, ud, "", nil)).To(Equal(fmt.Sprintf("%s%s:%s", registry, image, c.Version)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, CalicoRegistry, "calico/node"),
			Entry("a tigera image correctly", ComponentTigeraNode, TigeraRegistry, "tigera/cnx-node"),
			Entry("an ECK image correctly", ComponentElasticsearchOperator, TigeraRegistry, "tigera/eck-operator"),
			Entry("an operator init image correctly", ComponentOperatorInit, InitRegistry, "tigera/operator"),
			Entry("a CSR init image correctly", ComponentCalicoCSRInitContainer, CalicoRegistry, "calico/key-cert-provisioner"),
			Entry("a CSR init image correctly", ComponentTigeraCSRInitContainer, TigeraRegistry, "tigera/key-cert-provisioner"),
		)
	})

	Context("registry override", func() {
		DescribeTable("should render",
			func(c component, image string) {
				Expect(GetReference(c, "quay.io/", "", "", nil)).To(Equal(fmt.Sprintf("%s%s:%s", "quay.io/", image, c.Version)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, "calico/node"),
			Entry("a tigera image correctly", ComponentTigeraNode, "tigera/cnx-node"),
			Entry("an ECK image correctly", ComponentElasticsearchOperator, "tigera/eck-operator"),
			Entry("an operator init image correctly", ComponentOperatorInit, "tigera/operator"),
			Entry("a CSR init image correctly", ComponentCalicoCSRInitContainer, "calico/key-cert-provisioner"),
			Entry("a CSR init image correctly", ComponentTigeraCSRInitContainer, "tigera/key-cert-provisioner"),
		)
	})

	Context("image prefix override", func() {
		DescribeTable("should render",
			func(c component, image string) {
				Expect(GetReference(c, "quay.io/", "", "prefix-", nil)).To(Equal(fmt.Sprintf("quay.io/%s:%s", image, c.Version)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, "calico/prefix-node"),
			Entry("a tigera image correctly", ComponentTigeraNode, "tigera/prefix-cnx-node"),
			Entry("an ECK image correctly", ComponentElasticsearchOperator, "tigera/prefix-eck-operator"),
			Entry("an operator init image correctly", ComponentOperatorInit, "tigera/prefix-operator"),
			Entry("a CSR init image correctly", ComponentCalicoCSRInitContainer, "calico/prefix-key-cert-provisioner"),
			Entry("a CSR init image correctly", ComponentTigeraCSRInitContainer, "tigera/prefix-key-cert-provisioner"),
		)
	})

	Context("imagepath override", func() {
		DescribeTable("should render",
			func(c component, registry, image string) {
				Expect(GetReference(c, "", "userpath", "", nil)).To(Equal(fmt.Sprintf("%s%s:%s", registry, image, c.Version)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, CalicoRegistry, "userpath/node"),
			Entry("a tigera image correctly", ComponentTigeraNode, TigeraRegistry, "userpath/cnx-node"),
			Entry("an ECK image correctly", ComponentElasticsearchOperator, TigeraRegistry, "userpath/eck-operator"),
			Entry("an operator init image correctly", ComponentOperatorInit, InitRegistry, "userpath/operator"),
			Entry("a CSR init image correctly", ComponentCalicoCSRInitContainer, CalicoRegistry, "userpath/key-cert-provisioner"),
			Entry("a CSR init image correctly", ComponentTigeraCSRInitContainer, TigeraRegistry, "userpath/key-cert-provisioner"),
		)
	})
	Context("registry and imagepath override", func() {
		DescribeTable("should render",
			func(c component, image string) {
				Expect(GetReference(c, "quay.io/extra/", "userpath", "", nil)).To(Equal(fmt.Sprintf("quay.io/extra/%s:%s", image, c.Version)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, "userpath/node"),
			Entry("a tigera image correctly", ComponentTigeraNode, "userpath/cnx-node"),
			Entry("an ECK image correctly", ComponentElasticsearchOperator, "userpath/eck-operator"),
			Entry("an operator init image correctly", ComponentOperatorInit, "userpath/operator"),
			Entry("a CSR init image correctly", ComponentCalicoCSRInitContainer, "userpath/key-cert-provisioner"),
			Entry("a CSR init image correctly", ComponentTigeraCSRInitContainer, "userpath/key-cert-provisioner"),
		)
	})
	Context("with an ImageSet", func() {
		DescribeTable("should render",
			func(c component, image, hash string) {
				is := &op.ImageSet{
					Spec: op.ImageSetSpec{
						Images: []op.Image{
							{Image: "calico/node", Digest: "sha256:caliconodehash"},
							{Image: "tigera/cnx-node", Digest: "sha256:tigeracnxnodehash"},
							{Image: "tigera/eck-operator", Digest: "sha256:eckeckoperatorhash"},
							{Image: "tigera/operator", Digest: "sha256:tigeraoperatorhash"},
							{Image: "tigera/key-cert-provisioner", Digest: "sha256:tigerakeycertprovisionerhash"},
						},
					},
				}
				Expect(GetReference(c, "quay.io/extra/", "userpath", "", is)).To(Equal(fmt.Sprintf("quay.io/extra/%s%s", image, hash)))
			},
			Entry("a calico image correctly", ComponentCalicoNode, "userpath/node", "@sha256:caliconodehash"),
			Entry("a tigera image correctly", ComponentTigeraNode, "userpath/cnx-node", "@sha256:tigeracnxnodehash"),
			Entry("an ECK image correctly", ComponentElasticsearchOperator, "userpath/eck-operator", "@sha256:eckeckoperatorhash"),
			Entry("an operator init image correctly", ComponentOperatorInit, "userpath/operator", "@sha256:tigeraoperatorhash"),
			Entry("a CSR init image correctly", ComponentTigeraCSRInitContainer, "userpath/key-cert-provisioner", "@sha256:tigerakeycertprovisionerhash"),
		)
	})
})
