package convert

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Parser", func() {
	It("should convert a string", func() {
		fe, err := patchFromVal("dataplanedriver", "foo")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/dataplaneDriver",
			Value: "foo",
		}))
	})

	It("should convert a boolean", func() {
		fe, err := patchFromVal("useinternaldataplanedriver", "true")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/useInternalDataplaneDriver",
			Value: "true",
		}))
	})
})
