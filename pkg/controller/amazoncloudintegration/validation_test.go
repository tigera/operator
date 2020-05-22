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

package amazoncloudintegration

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
)

var _ = Describe("Installation validation tests", func() {
	var instance *operator.Installation

	BeforeEach(func() {
		instance = &operator.AmazonCloudIntegration{
			Spec: operator.AmazonCloudIntegrationSpec{
				NodeSecurityGroupIds:         []string{"sg-nodesgid"},
				PodSecurityGroupId:           "sg-podsgid",
				Vpcs:                         []string{"vpc-id"},
				SqsUrl:                       "sqs/url",
				AwsRegion:                    "us-west",
				EnforcedSecurityGroupId:      "sg-enforcedsgid",
				TrustEnforcedSecurityGroupId: "sg-trustenforcedsgid",
			},
		}
	})

	It("normal values should validate", func() {
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})
})
