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

package render

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/components"
)

var _ = Describe("No registry override", func() {
	It("should render a calico image correctly", func() {
		Expect(components.GetImageReference(NodeImageNameCalico, "")).To(Equal("docker.io/calico/node:" + components.VersionCalicoNode))
	})
	It("should render a tigera image correctly", func() {
		Expect(components.GetImageReference(NodeImageNameTigera, "")).To(Equal("gcr.io/unique-caldron-775/cnx/tigera/cnx-node:" + components.VersionTigeraNode))
	})
	It("should render an ECK image correctly", func() {
		Expect(components.GetImageReference(ECKOperatorImageName, "")).To(Equal("docker.elastic.co/eck/eck-operator:" + components.VersionECKOperator))
	})
})

var _ = Describe("registry override", func() {
	It("should render a calico image correctly", func() {
		Expect(components.GetImageReference(NodeImageNameCalico, "quay.io/")).To(Equal("quay.io/calico/node:" + components.VersionCalicoNode))
	})
	It("should render a tigera image correctly", func() {
		Expect(components.GetImageReference(NodeImageNameTigera, "quay.io/")).To(Equal("quay.io/tigera/cnx-node:" + components.VersionTigeraNode))
	})
	It("should render an ECK image correctly", func() {
		Expect(components.GetImageReference(ECKOperatorImageName, "quay.io/")).To(Equal("quay.io/eck/eck-operator:" + components.VersionECKOperator))
	})
})
