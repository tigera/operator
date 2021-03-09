package convert

import (
	"context"

	. "github.com/onsi/ginkgo"
	//. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kscheme "k8s.io/client-go/kubernetes/scheme"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
)

var _ = Describe("Convert typha check tests", func() {
	var ctx = context.Background()
	var scheme *runtime.Scheme
	var pool *crdv1.IPPool
	BeforeEach(func() {
		scheme = kscheme.Scheme
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
		pool = crdv1.NewIPPool()
		pool.Spec = crdv1.IPPoolSpec{
			CIDR:        "192.168.4.0/24",
			IPIPMode:    crdv1.IPIPModeAlways,
			NATOutgoing: true,
		}
	})
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
