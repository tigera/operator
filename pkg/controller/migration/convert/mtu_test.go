package convert

import (
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/migration/cni"
	v1 "k8s.io/api/core/v1"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("mtu handler", func() {
	var (
		comps = emptyComponents()
		i     = &operatorv1.Installation{}
	)

	BeforeEach(func() {
		comps = emptyComponents()
		i = &operatorv1.Installation{}
	})
	It("should not set mtu if none defined", func() {
		err := handleMTU(&comps, i)
		Expect(err).ToNot(HaveOccurred())
		Expect(i.Spec.CalicoNetwork).To(BeNil())
	})

	It("should read mtu from cni config", func() {
		comps.cni.CalicoConfig = &cni.CalicoConf{
			MTU: 1234,
		}
		err := handleMTU(&comps, i)
		Expect(err).ToNot(HaveOccurred())
		Expect(i.Spec.CalicoNetwork).ToNot(BeNil())
		Expect(*i.Spec.CalicoNetwork.MTU).To(BeEquivalentTo(1234))
	})

	table.DescribeTable("should read mtu from env vars on calico-node", func(env string) {
		comps.node.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{{
			Name:  env,
			Value: "1324",
		}}
		err := handleMTU(&comps, i)
		Expect(err).ToNot(HaveOccurred())
		Expect(i.Spec.CalicoNetwork).ToNot(BeNil())
		Expect(*i.Spec.CalicoNetwork.MTU).To(BeEquivalentTo(1324))
	},
		table.Entry("ipip", "FELIX_IPINIPMTU"),
		table.Entry("vxlan", "FELIX_VXLANMTU"),
		table.Entry("wireguard", "FELIX_WIREGUARDMTU"),
	)

	It("should error if given conflicting mtu values between env vars", func() {
		comps.node.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{
			{
				Name:  "FELIX_IPINIPMTU",
				Value: "1324",
			},
			{
				Name:  "FELIX_VXLANMTU",
				Value: "999",
			},
		}
		err := handleMTU(&comps, i)
		Expect(err).To(HaveOccurred())
	})

	It("should error if given conflicting mtu values between cni and env var", func() {
		comps.node.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{{
			Name:  "FELIX_IPINIPMTU",
			Value: "1324",
		}}
		comps.cni.CalicoConfig = &cni.CalicoConf{
			MTU: 1234,
		}
		err := handleMTU(&comps, i)
		Expect(err).To(HaveOccurred())
	})
})
