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

package operator_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/operator"
)

var _ = Describe("image overrides", func() {
	AfterEach(func() {
		operator.ResetForTest()
	})

	It("uses the override when one matches", func() {
		operator.OverrideImage("node", func(in *operatorv1.InstallationSpec) (components.Component, bool) {
			if !in.Variant.IsEnterprise() {
				return components.Component{}, false
			}
			return components.ComponentTigeraNode, true
		})

		ent := &operatorv1.InstallationSpec{Variant: operatorv1.TigeraSecureEnterprise}
		Expect(operator.ResolveImage("node", components.ComponentCalicoNode, ent)).To(Equal(components.ComponentTigeraNode))
	})

	It("falls back to the default when no override matches", func() {
		oss := &operatorv1.InstallationSpec{Variant: operatorv1.Calico}
		Expect(operator.ResolveImage("node", components.ComponentCalicoNode, oss)).To(Equal(components.ComponentCalicoNode))
	})
})
