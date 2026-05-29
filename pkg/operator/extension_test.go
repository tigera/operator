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

	"github.com/tigera/operator/pkg/operator"
)

var _ = Describe("controller extensions", func() {
	AfterEach(func() { operator.ResetExtensionsForTest() })

	It("returns the registered installation extension", func() {
		ext := &fakeInstallationExtension{}
		operator.RegisterInstallationExtension(ext)
		Expect(operator.GetInstallationExtension()).To(BeIdenticalTo(ext))
	})

	It("returns nil when none is registered", func() {
		Expect(operator.GetInstallationExtension()).To(BeNil())
	})
})

type fakeInstallationExtension struct{}

func (f *fakeInstallationExtension) Prepare(_ operator.InstallationPrep) (operator.Context, error) {
	return operator.Context{}, nil
}
