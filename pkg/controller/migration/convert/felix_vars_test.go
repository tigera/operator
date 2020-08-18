package convert

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
			Value: true,
		}))
	})

	It("should convert a duration", func() {
		fe, err := patchFromVal("routerefreshinterval", "4s")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/routeRefreshInterval",
			Value: metav1.Duration{4 * time.Second},
		}))
	})
})
