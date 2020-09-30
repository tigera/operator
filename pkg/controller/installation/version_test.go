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

package installation

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	gv "github.com/hashicorp/go-version"
	"github.com/onsi/ginkgo/extensions/table"
	"github.com/tigera/operator/version"
)

var _ = Describe("Version validation logic tests", func() {
	table.DescribeTable("should validate required operator version",
		func(minOperatorVersion, thisOperatorVersion string, expectedErr error) {
			buildVersion, _ = gv.NewVersion(thisOperatorVersion)
			err := checkOperatorVersion(minOperatorVersion)
			if expectedErr == nil {
				Expect(err).To(BeNil())
			} else {
				Expect(err).To(Equal(expectedErr))
			}
		},
		table.Entry("minRequiredVersion = thisVersion 1", "v1.0.0", "v1.0.0", nil),
		table.Entry("minRequiredVersion = thisVersion 2", "v1", "1.0.0", nil),
		table.Entry("minRequiredVersion < thisVersion", "v1.0.0", "v1.0.1", nil),
		table.Entry("minRequiredVersion > thisVersion", "v1.2.1", "v1.2",
			fmt.Errorf("specified operator version does not meet minimum requirement")),
		table.Entry("empty min version", "", "v1", nil),
		table.Entry("invalid minRequiredVersion", "invalid", "v1.2",
			fmt.Errorf("invalid version specified: Malformed version: invalid")),
	)

	It("should not return an error if operator version is invalid", func() {
		version.VERSION = "invalid"
		Expect(checkOperatorVersion("v1")).To(BeNil())
	})

	table.DescribeTable("should convert build version strings",
		func(buildVersion, expectedVersion string, expectedErr error) {
			v, err := versionFromBuildVersion(buildVersion)
			if expectedErr != nil {
				Expect(err).To(Equal(expectedErr))
			} else {
				Expect(v.String()).To(Equal(expectedVersion))
			}
		},
		table.Entry("happy path 1", "v1.0", "1.0.0", nil),
		table.Entry("happy path 2", "v1.0-1-ga64a5a6", "1.0.0", nil),
		table.Entry("happy path 3", "v1.0.1-11-ga64", "1.0.1", nil),
		table.Entry("happy path 4", "v3-11-ga64", "3.0.0", nil),
		table.Entry("invalid build version", "ga64a5a6", "",
			fmt.Errorf(`Invalid build version: "ga64a5a6"`)),
		table.Entry("dirty build version", "ga64a5a6-dirty", "",
			fmt.Errorf(`Invalid build version: "ga64a5a6-dirty"`)),
		table.Entry("empty build version", "", "",
			fmt.Errorf(`Invalid build version: ""`)),
	)
})
