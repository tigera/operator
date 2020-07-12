package parser

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const defaultCNI = `{
	"name": "k8s-pod-network",
	"cniVersion": "0.3.1",
	"plugins": [
	  {
		"type": "calico",
		"log_level": "info",
		"datastore_type": "kubernetes",
		"nodename": "__KUBERNETES_NODE_NAME__",
		"mtu": __CNI_MTU__,
		"ipam": {
			"type": "calico-ipam"
		},
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

var _ = Describe("CNI", func() {
	It("should work", func() {
		_, err := loadCNIConfig(defaultCNI)
		Expect(err).ToNot(HaveOccurred())
	})

	It("should also work", func() {

	})
})
