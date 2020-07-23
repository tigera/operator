package render_test

import (
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/tigera/operator/pkg/render"
)

type expectValue bool

const (
	expectOK  expectValue = true
	expectErr expectValue = false
)

var _ = DescribeTable("K8sServiceEndpoint validation",
	func(host, port string, exp expectValue) {
		k8sEP := render.K8sServiceEndpoint{
			Host: host,
			Port: port,
		}

		if exp == expectOK {
			Expect(k8sEP.Validate()).ShouldNot(HaveOccurred())
		} else {
			Expect(k8sEP.Validate()).Should(HaveOccurred())
		}
	},
	Entry("valid void values", "", "", expectOK),
	Entry("void host", "", "5678", expectErr),
	Entry("void port", "1.2.3.4", "", expectErr),
	Entry("valid ip:port", "1.2.3.4", "5678", expectOK),
	Entry("valid ipv6:port", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "5678", expectOK),
	Entry("valid domainname:port", "abc.cde.com", "5678", expectOK),
	Entry("valid ip invalid port <= 0", "1.2.3.4", "-3", expectErr),
	Entry("valid ip invalid port >= 2^16", "1.2.3.4", "65536", expectErr),
	Entry("invalid chars in domainname valid port", "^cde.com", "5678", expectErr),
	Entry("invalid schema in domainname valid port", "https://abs.cde.com", "5678", expectErr),
	Entry("invalid port in domainname valid port", "abs.cde.com:8080", "5678", expectErr),
)
