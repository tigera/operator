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

package components

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	op "github.com/tigera/operator/api/v1"
)

var _ = Describe("test GetReference", func() {
	Context("No registry override", func() {
		It("should render a calico image correctly", func() {
			Expect(GetReference(ComponentCalicoNode, "", "", "", nil)).To(Equal("docker.io/calico/node:" + ComponentCalicoNode.Version))
		})
		It("should render a tigera image correctly", func() {
			Expect(GetReference(ComponentTigeraNode, "", "", "", nil)).To(Equal(TigeraRegistry + "tigera/cnx-node:" + ComponentTigeraNode.Version))
		})
		It("should render an ECK image correctly", func() {
			Expect(GetReference(ComponentElasticsearchOperator, "", "", "", nil)).To(Equal("quay.io/tigera/eck-operator:" + ComponentElasticsearchOperator.Version))
		})
		It("should render an operator init image correctly", func() {
			Expect(GetReference(ComponentOperatorInit, "", "", "", nil)).To(Equal(InitRegistry + "tigera/operator:" + ComponentOperatorInit.Version))
		})
	})

	Context("UseDefault for registry and imagepath", func() {
		ud := "UseDefault"
		It("should render a calico image correctly", func() {
			Expect(GetReference(ComponentCalicoNode, ud, ud, "", nil)).To(Equal("docker.io/calico/node:" + ComponentCalicoNode.Version))
		})
		It("should render a tigera image correctly", func() {
			Expect(GetReference(ComponentTigeraNode, ud, ud, "", nil)).To(Equal(TigeraRegistry + "tigera/cnx-node:" + ComponentTigeraNode.Version))
		})
		It("should render an ECK image correctly", func() {
			Expect(GetReference(ComponentElasticsearchOperator, ud, ud, "", nil)).To(Equal("quay.io/tigera/eck-operator:" + ComponentElasticsearchOperator.Version))
		})
		It("should render an operator init image correctly", func() {
			Expect(GetReference(ComponentOperatorInit, ud, ud, "", nil)).To(Equal(InitRegistry + "tigera/operator:" + ComponentOperatorInit.Version))
		})
	})

	Context("registry override", func() {
		It("should render a calico image correctly", func() {
			Expect(GetReference(ComponentCalicoNode, "quay.io/", "", "", nil)).To(Equal("quay.io/calico/node:" + ComponentCalicoNode.Version))
		})
		It("should render a tigera image correctly", func() {
			Expect(GetReference(ComponentTigeraNode, "quay.io/", "", "", nil)).To(Equal("quay.io/tigera/cnx-node:" + ComponentTigeraNode.Version))
		})
		It("should render an ECK image correctly", func() {
			Expect(GetReference(ComponentElasticsearchOperator, "quay.io/", "", "", nil)).To(Equal("quay.io/tigera/eck-operator:" + ComponentElasticsearchOperator.Version))
		})
		It("should render an operator init image correctly", func() {
			Expect(GetReference(ComponentOperatorInit, "gcr.io/", "", "", nil)).To(Equal("gcr.io/tigera/operator:" + ComponentOperatorInit.Version))
		})
	})

	Context("image prefix override", func() {
		It("should render a calico image correctly", func() {
			Expect(GetReference(ComponentCalicoNode, "quay.io/", "", "pref", nil)).To(Equal("quay.io/calico/prefnode:" + ComponentCalicoNode.Version))
		})
		It("should render a tigera image correctly", func() {
			Expect(GetReference(ComponentTigeraNode, "quay.io/", "", "pref", nil)).To(Equal("quay.io/tigera/prefcnx-node:" + ComponentTigeraNode.Version))
		})
		It("should render an ECK image correctly", func() {
			Expect(GetReference(ComponentElasticsearchOperator, "quay.io/", "", "pref", nil)).To(Equal("quay.io/tigera/prefeck-operator:" + ComponentElasticsearchOperator.Version))
		})
		It("should render an operator init image correctly", func() {
			Expect(GetReference(ComponentOperatorInit, "gcr.io/", "", "pref", nil)).To(Equal("gcr.io/tigera/prefoperator:" + ComponentOperatorInit.Version))
		})
		It("should render a calico image with UseDefault", func() {
			Expect(GetReference(ComponentCalicoNode, "gcr.io/", "", "UseDefault", nil)).To(Equal("gcr.io/calico/node:" + ComponentCalicoNode.Version))
		})
	})

	Context("imagepath override", func() {
		It("should render a calico image correctly", func() {
			Expect(GetReference(ComponentCalicoNode, "", "userpath", "", nil)).To(Equal("docker.io/userpath/node:" + ComponentCalicoNode.Version))
		})
		It("should render a tigera image correctly", func() {
			Expect(GetReference(ComponentTigeraNode, "", "userpath", "", nil)).To(Equal(TigeraRegistry + "userpath/cnx-node:" + ComponentTigeraNode.Version))
		})
		It("should render an ECK image correctly", func() {
			Expect(GetReference(ComponentElasticsearchOperator, "", "userpath", "", nil)).To(Equal("quay.io/userpath/eck-operator:" + ComponentElasticsearchOperator.Version))
		})
		It("should render an operator init image correctly", func() {
			Expect(GetReference(ComponentOperatorInit, "", "userpath", "", nil)).To(Equal(InitRegistry + "userpath/operator:" + ComponentOperatorInit.Version))
		})
	})
	Context("registry and imagepath override", func() {
		It("should render a calico image correctly", func() {
			Expect(GetReference(ComponentCalicoNode, "quay.io/extra/", "userpath", "", nil)).To(Equal("quay.io/extra/userpath/node:" + ComponentCalicoNode.Version))
		})
		It("should render a tigera image correctly", func() {
			Expect(GetReference(ComponentTigeraNode, "quay.io/extra/", "userpath", "", nil)).To(Equal("quay.io/extra/userpath/cnx-node:" + ComponentTigeraNode.Version))
		})
		It("should render an ECK image correctly", func() {
			Expect(GetReference(ComponentElasticsearchOperator, "quay.io/extra/", "userpath", "", nil)).To(Equal("quay.io/extra/userpath/eck-operator:" + ComponentElasticsearchOperator.Version))
		})
		It("should render an operator init image correctly", func() {
			Expect(GetReference(ComponentOperatorInit, "gcr.io/extra/", "userpath", "", nil)).To(Equal("gcr.io/extra/userpath/operator:" + ComponentOperatorInit.Version))
		})
	})
	Context("with an ImageSet", func() {
		is := &op.ImageSet{
			Spec: op.ImageSetSpec{
				Images: []op.Image{
					{Image: "calico/node", Digest: "sha256:caliconodehash"},
					{Image: "tigera/cnx-node", Digest: "sha256:tigeracnxnodehash"},
					{Image: "tigera/eck-operator", Digest: "sha256:eckeckoperatorhash"},
					{Image: "tigera/operator", Digest: "sha256:tigeraoperatorhash"},
				},
			},
		}
		It("should render a calico image correctly", func() {
			Expect(GetReference(ComponentCalicoNode, "quay.io/extra/", "userpath", "", is)).To(Equal("quay.io/extra/userpath/node@sha256:caliconodehash"))
		})
		It("should render a tigera image correctly", func() {
			Expect(GetReference(ComponentTigeraNode, "quay.io/extra/", "userpath", "", is)).To(Equal("quay.io/extra/userpath/cnx-node@sha256:tigeracnxnodehash"))
		})
		It("should render an ECK image correctly", func() {
			Expect(GetReference(ComponentElasticsearchOperator, "quay.io/extra/", "userpath", "", is)).To(Equal("quay.io/extra/userpath/eck-operator@sha256:eckeckoperatorhash"))
		})
		It("should render an operator init image correctly", func() {
			Expect(GetReference(ComponentOperatorInit, "gcr.io/extra/", "userpath", "", is)).To(Equal("gcr.io/extra/userpath/operator@sha256:tigeraoperatorhash"))
		})
	})
})
