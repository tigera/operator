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
)

var _ = Describe("No registry override", func() {
	It("should render a calico image correctly", func() {
		Expect(GetReference(ComponentCalicoNode, "", "", nil)).To(Equal("docker.io/calico/node:" + ComponentCalicoNode.Version))
	})
	It("should render a tigera image correctly", func() {
		Expect(GetReference(ComponentTigeraNode, "", "", nil)).To(Equal(TigeraRegistry + "tigera/cnx-node:" + ComponentTigeraNode.Version))
	})
	It("should render an ECK image correctly", func() {
		Expect(GetReference(ComponentElasticsearchOperator, "", "", nil)).To(Equal("docker.elastic.co/eck/eck-operator:" + ComponentElasticsearchOperator.Version))
	})
	It("should render an operator init image correctly", func() {
		Expect(GetReference(ComponentOperatorInit, "", "", nil)).To(Equal(InitRegistry + "tigera/operator:" + ComponentOperatorInit.Version))
	})
})

var _ = Describe("registry override", func() {
	It("should render a calico image correctly", func() {
		Expect(GetReference(ComponentCalicoNode, "quay.io/", "", nil)).To(Equal("quay.io/calico/node:" + ComponentCalicoNode.Version))
	})
	It("should render a tigera image correctly", func() {
		Expect(GetReference(ComponentTigeraNode, "quay.io/", "", nil)).To(Equal("quay.io/tigera/cnx-node:" + ComponentTigeraNode.Version))
	})
	It("should render an ECK image correctly", func() {
		Expect(GetReference(ComponentElasticsearchOperator, "quay.io/", "", nil)).To(Equal("quay.io/eck/eck-operator:" + ComponentElasticsearchOperator.Version))
	})
	It("should render an operator init image correctly", func() {
		Expect(GetReference(ComponentOperatorInit, "gcr.io/", "", nil)).To(Equal("gcr.io/tigera/operator:" + ComponentOperatorInit.Version))
	})
})
var _ = Describe("imagepath override", func() {
	It("should render a calico image correctly", func() {
		Expect(GetReference(ComponentCalicoNode, "", "userpath", nil)).To(Equal("docker.io/userpath/node:" + ComponentCalicoNode.Version))
	})
	It("should render a tigera image correctly", func() {
		Expect(GetReference(ComponentTigeraNode, "", "userpath", nil)).To(Equal(TigeraRegistry + "userpath/cnx-node:" + ComponentTigeraNode.Version))
	})
	It("should render an ECK image correctly", func() {
		Expect(GetReference(ComponentElasticsearchOperator, "", "userpath", nil)).To(Equal("docker.elastic.co/userpath/eck-operator:" + ComponentElasticsearchOperator.Version))
	})
	It("should render an operator init image correctly", func() {
		Expect(GetReference(ComponentOperatorInit, "", "userpath", nil)).To(Equal(InitRegistry + "userpath/operator:" + ComponentOperatorInit.Version))
	})
})
var _ = Describe("registry and imagepath override", func() {
	It("should render a calico image correctly", func() {
		Expect(GetReference(ComponentCalicoNode, "quay.io/extra/", "userpath", nil)).To(Equal("quay.io/extra/userpath/node:" + ComponentCalicoNode.Version))
	})
	It("should render a tigera image correctly", func() {
		Expect(GetReference(ComponentTigeraNode, "quay.io/extra/", "userpath", nil)).To(Equal("quay.io/extra/userpath/cnx-node:" + ComponentTigeraNode.Version))
	})
	It("should render an ECK image correctly", func() {
		Expect(GetReference(ComponentElasticsearchOperator, "quay.io/extra/", "userpath", nil)).To(Equal("quay.io/extra/userpath/eck-operator:" + ComponentElasticsearchOperator.Version))
	})
	It("should render an operator init image correctly", func() {
		Expect(GetReference(ComponentOperatorInit, "gcr.io/extra/", "userpath", nil)).To(Equal("gcr.io/extra/userpath/operator:" + ComponentOperatorInit.Version))
	})
})
