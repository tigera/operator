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

package enterprise_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/enterprise"
	"github.com/tigera/operator/pkg/operator"
)

var _ = Describe("node enterprise image override", func() {
	BeforeEach(func() { enterprise.Register() })
	AfterEach(func() {
		operator.ResetForTest()
		operator.ResetExtensionsForTest()
	})

	It("selects the enterprise node image for the enterprise variant", func() {
		ent := &operatorv1.InstallationSpec{Variant: operatorv1.TigeraSecureEnterprise}
		Expect(operator.ResolveImage("node", components.ComponentCalicoNode, ent)).To(Equal(components.ComponentTigeraNode))
	})

	It("leaves the default in place for the Calico variant", func() {
		oss := &operatorv1.InstallationSpec{Variant: operatorv1.Calico}
		Expect(operator.ResolveImage("node", components.ComponentCalicoNode, oss)).To(Equal(components.ComponentCalicoNode))
	})
})
