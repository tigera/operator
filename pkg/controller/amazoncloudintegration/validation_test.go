// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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

	operatorv1 "github.com/tigera/operator/api/v1"
)

var _ = Describe("Installation validation tests", func() {
	var instance *operatorv1.AmazonCloudIntegration

	BeforeEach(func() {
		instance = &operatorv1.AmazonCloudIntegration{
			Spec: operatorv1.AmazonCloudIntegrationSpec{
				NodeSecurityGroupIDs:         []string{"sg-nodesgid"},
				PodSecurityGroupID:           "sg-podsgid",
				VPCS:                         []string{"vpc-id"},
				SQSURL:                       "sqs/url",
				AWSRegion:                    "us-west",
				EnforcedSecurityGroupID:      "sg-enforcedsgid",
				TrustEnforcedSecurityGroupID: "sg-trustenforcedsgid",
			},
		}
	})

	It("normal values should validate", func() {
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})
})
