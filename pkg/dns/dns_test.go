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

package dns_test

import (
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/tigera/operator/pkg/dns"
)

var _ = Describe("Common Tests", func() {
	Context("Get cluster domain", func() {

		It("Should have the right value for the alternative resolv.conf", func() {
			dir, err := os.Getwd()
			if err != nil {
				panic(err)
			}
			resolvConfPath := dir + "/testdata/resolv.conf"
			clusterDomain, err := dns.GetClusterDomain(resolvConfPath)
			Expect(clusterDomain).To(Equal("othername.local"))
			Expect(err).ToNot(HaveOccurred())
		})

		It("Should throw an error for a nonexisting file", func() {
			_, err := dns.GetClusterDomain("does-not.exist")
			Expect(err).To(HaveOccurred())
		})
	})

	Context("Get qualified names for a service", func() {
		DescribeTable("Should return the correct qualified names from the service's FQDN", func(fqdn, clusterDomain string, expectError bool, expectedPQDNs []string) {
			pqdns, err := dns.GetServiceDNSNames(fqdn, clusterDomain)
			if !expectError {
				Expect(err).To(BeNil())
			}
			Expect(pqdns).To(ConsistOf(expectedPQDNs))
		},
			Entry("default", "a.b.svc.cluster.local", "cluster.local", false, []string{"a", "a.b", "a.b.svc", "a.b.svc.cluster.local"}),
			Entry("default", "a.b.svc.somedomain", "somedomain", false, []string{"a", "a.b", "a.b.svc", "a.b.svc.somedomain"}),
			Entry("default", "a.b.svc", "cluster.local", true, []string{}),
			Entry("default", "a.b", "cluster.local", true, []string{}),
		)
	})
})
