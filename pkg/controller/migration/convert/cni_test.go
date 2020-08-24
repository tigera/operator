package convert

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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
	It("should load cni from correct fields on calico-node", func() {
		ds := emptyNodeSpec()
		ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{
			{
				Name:  "CNI_NETWORK_CONFIG",
				Value: defaultCNI,
			},
		}

		cli := fake.NewFakeClient(ds, emptyKubeControllerSpec())
		c := components{
			node: CheckedDaemonSet{
				DaemonSet:   *ds,
				checkedVars: map[string]checkedFields{},
			},
			client: cli,
		}

		nc, err := loadCNI(&c)
		Expect(err).ToNot(HaveOccurred())
		Expect(nc.calicoCNIConfig).ToNot(BeNil())
		Expect(nc.calicoCNIConfig.IPAM.Type).To(Equal("calico-ipam"), fmt.Sprintf("Got %+v", c.calicoCNIConfig))
	})

	It("should unmarshal a valid cni conf list", func() {
		_, err := unmarshalCNIConfList(defaultCNI)
		Expect(err).ToNot(HaveOccurred())
	})

	It("should parse basic calico cni", func() {
		c, err := parseCNIConfig(defaultCNI)
		Expect(err).ToNot(HaveOccurred())
		Expect(c.calicoCNIConfig).ToNot(BeNil())
		// check that any field was unmarshaled correctly.
		Expect(c.calicoCNIConfig.IPAM.Type).To(Equal("calico-ipam"), fmt.Sprintf("Got %+v", c.calicoCNIConfig))
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
		c, err := parseCNIConfig(cni)
		Expect(err).ToNot(HaveOccurred())
		Expect(c.calicoCNIConfig).ToNot(BeNil())
		Expect(c.calicoCNIConfig.IPAM.Type).To(Equal("host-local"), fmt.Sprintf("Got %+v", c.calicoCNIConfig))
		Expect(c.hostLocalIPAMConfig.Ranges).To(HaveLen(2))
		Expect(c.hostLocalIPAMConfig.Routes).To(HaveLen(2))
	})
	It("should raise error if IPAM with unknown field is detected", func() {
		cni := fmt.Sprintf(cniTemplate, `{
			"type": "host-local",
			"unknown": "whocares"
          }`)
		_, err := parseCNIConfig(cni)
		Expect(err).To(HaveOccurred())
	})
})
