package cni

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const cniTemplate = `{
	"name": "k8s-pod-network",
	"cniVersion": "0.3.1",
	"plugins": [
	  {
		"type": "calico",
		"log_level": "info",
		"datastore_type": "kubernetes",
		"nodename": "__KUBERNETES_NODE_NAME__",
		"mtu": __CNI_MTU__,
		"ipam": %s,
		"policy": {
			"type": "k8s"
		},
		"kubernetes": {
			"kubeconfig": "__KUBECONFIG_FILEPATH__"
		}
	  },
	  {
		"type": "portmap",
		"snat": true,
		"capabilities": {"portMappings": true}
	  },
	  {
		"type": "bandwidth",
		"capabilities": {"bandwidth": true}
	  }
	]
  }`

var defaultCNI = fmt.Sprintf(cniTemplate, `{"type": "calico-ipam"}`)

var _ = Describe("CNI", func() {
	It("should unmarshal a valid cni conf list", func() {
		_, err := unmarshalCNIConfList(defaultCNI)
		Expect(err).ToNot(HaveOccurred())
	})

	It("should parse basic calico cni", func() {
		c, err := Parse(defaultCNI)
		Expect(err).ToNot(HaveOccurred())
		Expect(c.CalicoCNIConfig).ToNot(BeNil())
		// check that any field was unmarshaled correctly.
		Expect(c.CalicoCNIConfig.IPAM.Type).To(Equal("calico-ipam"), fmt.Sprintf("Got %+v", c.CalicoCNIConfig))
	})

	It("should parse ranges and routes", func() {
		cni := fmt.Sprintf(cniTemplate, `{
			"type": "host-local",
			"ranges": [
                [
                    { "subnet": "usePodCidr" }
                ],
                [
                    { "subnet": "2001:db8::/96" }
                ]
            ],
            "routes": [
                { "dst": "0.0.0.0/0" },
                { "dst": "2001:db8::/96" }
            ]
        }`)
		c, err := Parse(cni)
		Expect(err).ToNot(HaveOccurred())
		Expect(c.CalicoCNIConfig).ToNot(BeNil())
		Expect(c.CalicoCNIConfig.IPAM.Type).To(Equal("host-local"), fmt.Sprintf("Got %+v", c.CalicoCNIConfig))
		Expect(c.HostLocalIPAMConfig.Ranges).To(HaveLen(2))
		Expect(c.HostLocalIPAMConfig.Routes).To(HaveLen(2))
	})
	It("should raise error if IPAM with unknown field is detected", func() {
		cni := fmt.Sprintf(cniTemplate, `{
			"type": "host-local",
			"unknown": "whocares"
          }`)
		_, err := Parse(cni)
		Expect(err).To(HaveOccurred())
	})
})
