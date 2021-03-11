package convert

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
)

var _ = Describe("Convert typha check tests", func() {
	Context("typha prometheus metrics", func() {
		var (
			comps = emptyComponents()
			i     = &operatorv1.Installation{}
		)

		BeforeEach(func() {
			comps = emptyComponents()
			i = &operatorv1.Installation{}
		})
		It("with metrics enabled the default port is used", func() {
			comps.typha.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "TYPHA_PROMETHEUSMETRICSENABLED",
				Value: "true",
			}}
			Expect(handleTyphaMetrics(&comps, i)).ToNot(HaveOccurred())
			Expect(*i.Spec.TyphaMetricsPort).To(Equal(int32(9091)))
		})
		It("defaults prometheus off when no prometheus environment variables set", func() {

			Expect(handleFelixNodeMetrics(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.TyphaMetricsPort).To(BeNil())
		})
		It("with metrics port env var only, metrics are still disabled", func() {
			comps.typha.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "TYPHA_PROMETHEUSMETRICSPORT",
				Value: "5555",
			}}

			Expect(handleTyphaMetrics(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.TyphaMetricsPort).To(BeNil())
		})
		It("with metrics port and enabled is reflected in installation", func() {
			comps.typha.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "TYPHA_PROMETHEUSMETRICSENABLED",
				Value: "true",
			}, {
				Name:  "TYPHA_PROMETHEUSMETRICSPORT",
				Value: "7777",
			}}

			Expect(handleTyphaMetrics(&comps, i)).ToNot(HaveOccurred())
			Expect(*i.Spec.TyphaMetricsPort).To(Equal(int32(7777)))
		})
	})
})
