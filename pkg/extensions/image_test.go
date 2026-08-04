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

package extensions_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/extensions"
)

var _ = Describe("image overrides", func() {
	var r *extensions.Registry
	BeforeEach(func() {
		r = extensions.NewRegistry(operatorv1.CalicoEnterprise)
		r.RegisterImage("node", components.ComponentTigeraNode)
	})

	It("uses the override registered for the installation variant", func() {
		ent := &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise}
		Expect(r.Images().Resolve("node", components.ComponentCalicoNode, ent)).To(Equal(components.ComponentTigeraNode))
	})

	It("falls back to the default for a variant with no override", func() {
		calico := &operatorv1.InstallationSpec{Variant: operatorv1.Calico}
		Expect(r.Images().Resolve("node", components.ComponentCalicoNode, calico)).To(Equal(components.ComponentCalicoNode))
	})
})
