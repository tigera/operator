package convert

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/libcalico-go/lib/numorstring"

	"github.com/tigera/operator/pkg/apis"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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
		t := true
		fe, err := patchFromVal("useinternaldataplanedriver", "true")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/useInternalDataplaneDriver",
			Value: &t,
		}))
	})

	It("converts a duration", func() {
		fe, err := patchFromVal("routerefreshinterval", "4s")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/routeRefreshInterval",
			Value: &metav1.Duration{4 * time.Second},
		}))
	})

	It("converts a *uint32", func() {
		m := uint32(20)
		fe, err := patchFromVal("iptablesmarkmask", "20")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/iptablesMarkMask",
			Value: &m,
		}))
	})

	It("converts a slice of protoports", func() {
		fe, err := patchFromVal("failsafeinboundhostports", "tcp:10250")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/failsafeInboundHostPorts",
			Value: &[]crdv1.ProtoPort{{Port: 10250, Protocol: "tcp"}},
		}))
	})

	It("converts a RouteTableRange", func() {
		fe, err := patchFromVal("routetablerange", "22-44")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/routeTableRange",
			Value: &crdv1.RouteTableRange{Min: 22, Max: 44},
		}))
	})

	It("converts a AWSSrcDstCheckOption", func() {
		d := crdv1.AWSSrcDstCheckOption(crdv1.AWSSrcDstCheckOptionDisable)
		fe, err := patchFromVal("awssrcdstcheck", "Disable")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe.Value).To(Equal(&d))
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/awsSrcDstCheck",
			Value: &d,
		}))
	})

	It("converts a *[]string", func() {
		fe, err := patchFromVal("externalnodescidrlist", "1.1.1.1,2.2.2.2")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/externalNodesList",
			Value: &[]string{"1.1.1.1", "2.2.2.2"},
		}))
	})

	It("converts a numorstring", func() {
		fe, err := patchFromVal("kubenodeportranges", "10250:10260")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/kubeNodePortRanges",
			Value: &[]numorstring.Port{{MinPort: 10250, MaxPort: 10260}},
		}))
	})

	Context("", func() {
		var c = emptyComponents()

		BeforeEach(func() {
			c = emptyComponents()

			scheme := kscheme.Scheme
			Expect(apis.AddToScheme(scheme)).ToNot(HaveOccurred())
			c.client = fake.NewFakeClientWithScheme(scheme, emptyFelixConfig())
		})

		It("sets a boolean", func() {
			c.node.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{{
				Name:  "FELIX_BPFENABLED",
				Value: "true",
			}}

			Expect(handleFelixVars(&c)).ToNot(HaveOccurred())

			f := crdv1.FelixConfiguration{}
			Expect(c.client.Get(ctx, types.NamespacedName{Name: "default"}, &f)).ToNot(HaveOccurred())
			Expect(f.Spec.BPFEnabled).ToNot(BeNil())
			Expect(*f.Spec.BPFEnabled).To(BeTrue())
		})

		It("sets a duration", func() {
			c.node.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{{
				Name:  "FELIX_IPTABLESREFRESHINTERVAL",
				Value: "20s",
			}}

			Expect(handleFelixVars(&c)).ToNot(HaveOccurred())

			f := crdv1.FelixConfiguration{}
			Expect(c.client.Get(ctx, types.NamespacedName{Name: "default"}, &f)).ToNot(HaveOccurred())
			Expect(f.Spec.IptablesRefreshInterval).ToNot(BeNil())
			Expect(f.Spec.IptablesRefreshInterval).To(Equal(&metav1.Duration{20 * time.Second}))
		})

		It("sets iptablesbackend", func() {
			c.node.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{{
				Name:  "FELIX_IPTABLESBACKEND",
				Value: "Legacy",
			}}

			Expect(handleFelixVars(&c)).ToNot(HaveOccurred())

			f := crdv1.FelixConfiguration{}
			Expect(c.client.Get(ctx, types.NamespacedName{Name: "default"}, &f)).ToNot(HaveOccurred())
			Expect(f.Spec.IptablesBackend).ToNot(BeNil())
			legacy := crdv1.IptablesBackend(crdv1.IptablesBackendLegacy)
			Expect(f.Spec.IptablesBackend).To(Equal(&legacy))
		})
	})
})
