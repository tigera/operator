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
		Expect(GetReference(ComponentCalicoNode, "", "")).To(Equal("docker.io/calico/node:" + ComponentCalicoNode.Digest))
	})
	It("should render a tigera image correctly", func() {
		Expect(GetReference(ComponentTigeraNode, "", "")).To(Equal("gcr.io/unique-caldron-775/cnx/tigera/cnx-node:" + ComponentTigeraNode.Digest))
	})
	It("should render an ECK image correctly", func() {
		Expect(GetReference(ComponentElasticsearchOperator, "", "")).To(Equal("docker.elastic.co/eck/eck-operator:" + ComponentElasticsearchOperator.Digest))
	})
})

var _ = Describe("registry override", func() {
	It("should render a calico image correctly", func() {
		Expect(GetReference(ComponentCalicoNode, "quay.io/", "")).To(Equal("quay.io/calico/node:" + ComponentCalicoNode.Digest))
	})
	It("should render a tigera image correctly", func() {
		Expect(GetReference(ComponentTigeraNode, "quay.io/", "")).To(Equal("quay.io/tigera/cnx-node:" + ComponentTigeraNode.Digest))
	})
	It("should render an ECK image correctly", func() {
		Expect(GetReference(ComponentElasticsearchOperator, "quay.io/", "")).To(Equal("quay.io/eck/eck-operator:" + ComponentElasticsearchOperator.Digest))
	})
})
var _ = Describe("imagepath override", func() {
	It("should render a calico image correctly", func() {
		Expect(GetReference(ComponentCalicoNode, "", "userpath")).To(Equal("docker.io/userpath/node:" + ComponentCalicoNode.Digest))
	})
	It("should render a tigera image correctly", func() {
		Expect(GetReference(ComponentTigeraNode, "", "userpath")).To(Equal("quay.io/userpath/cnx-node:" + ComponentTigeraNode.Digest))
	})
	It("should render an ECK image correctly", func() {
		Expect(GetReference(ComponentElasticsearchOperator, "", "userpath")).To(Equal("docker.elastic.co/userpath/eck-operator:" + ComponentElasticsearchOperator.Digest))
	})
})
var _ = Describe("registry and imagepath override", func() {
	It("should render a calico image correctly", func() {
		Expect(GetReference(ComponentCalicoNode, "quay.io/extra", "userpath")).To(Equal("quay.io/extra/userpath/node:" + ComponentCalicoNode.Digest))
	})
	It("should render a tigera image correctly", func() {
		Expect(GetReference(ComponentTigeraNode, "quay.io/extra", "userpath")).To(Equal("quay.io/extra/userpath/cnx-node:" + ComponentTigeraNode.Digest))
	})
	It("should render an ECK image correctly", func() {
		Expect(GetReference(ComponentElasticsearchOperator, "quay.io/extra", "userpath")).To(Equal("quay.io/extra/userpath/eck-operator:" + ComponentElasticsearchOperator.Digest))
	})
})
