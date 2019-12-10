package utils_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/controller/utils"
)

var _ = Describe("MCM utils test", func() {

	It("should correctly validate values for the voltron address and be able to format them", func() {

		// Test some valid inputs
		expect("example.com:8080", false, "example.com:8080", "8080")
		expect("foo.bar.com:8080", false, "foo.bar.com:8080", "8080")
		expect("0.0.0.0:8080", false, "0.0.0.0:8080", "8080")
		expect("[2001:db8:85a3::8a2e:370:7334]:8080", false, "[2001:db8:85a3::8a2e:370:7334]:8080", "8080")
		expect("tcp://0.0.0.0:8080", false, "0.0.0.0:8080", "8080")

		// Test some invalid inputs
		expect("http://example.com", true, "", "")
		expect("tcp://0.0.0.0:8080234", true, "", "")
		expect("https://0.0.0.0:-8080", true, "", "")
		expect("https://user@example.com:8080", true, "", "")
	})
})

func expect(s string, expectedErr bool, expectedAddr string, expectedPort string) {
	uri, err := utils.GetManagementClusterURL(s)
	if expectedErr {
		Expect(err).To(HaveOccurred())
		return
	}
	Expect(err).To(Not(HaveOccurred()))
	Expect(utils.FormatManagementClusterURL(uri)).To(Equal(expectedAddr))
	Expect(uri.Port()).To(Equal(expectedPort))
}
