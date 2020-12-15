// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package common_test

import (
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/tigera/operator/pkg/common"
)

var _ = Describe("Common Tests", func() {
	Context("DNS Resolution", func() {

		It("Should have the right value for the alternative resolv.conf", func() {
			dir, err := os.Getwd()
			if err != nil {
				panic(err)
			}
			resolvConfPath := dir + "/testdata/resolv.conf"
			localDNS, err := common.GetLocalDNSName(resolvConfPath)
			Expect(localDNS).To(Equal("svc.othername.local"))
			Expect(err).ToNot(HaveOccurred())
		})

		It("Should throw an error for a nonexisting file", func() {
			_, err := common.GetLocalDNSName("does-not.exist")
			Expect(err).To(HaveOccurred())
		})
	})
})
