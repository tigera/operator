package convert

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	corev1 "k8s.io/api/core/v1"
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
		_, err := unmarshalCNIConfList(defaultCNI)
		Expect(err).ToNot(HaveOccurred())
	})

	It("expect values", func() {
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
		Expect(loadCNI(&c)).ToNot(HaveOccurred())
		Expect(c.calicoCNIConfig).ToNot(BeNil())
		Expect(c.calicoCNIConfig.IPAM.Type).To(Equal("calico-ipam"), fmt.Sprintf("Got %+v", c.calicoCNIConfig))
	})

	It("expect parse with ranges and routes", func() {
		ds := emptyNodeSpec()
		ipamSnippet := `{
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
          }`
		ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{
			{
				Name: "CNI_NETWORK_CONFIG",
				Value: fmt.Sprintf(`{
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
	  }
	]
  }`, ipamSnippet),
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
		Expect(loadCNI(&c)).ToNot(HaveOccurred())
		Expect(c.calicoCNIConfig).ToNot(BeNil())
		Expect(c.calicoCNIConfig.IPAM.Type).To(Equal("host-local"), fmt.Sprintf("Got %+v", c.calicoCNIConfig))
		Expect(c.hostLocalIPAMConfig.Ranges).To(HaveLen(2))
		Expect(c.hostLocalIPAMConfig.Routes).To(HaveLen(2))
	})
	It("expect parse of IPAM with unknown field is detected", func() {
		ds := emptyNodeSpec()
		ipamSnippet := `{
			"type": "host-local",
			"unknown": "whocares"
          }`
		ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{
			{
				Name: "CNI_NETWORK_CONFIG",
				Value: fmt.Sprintf(`{
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
	  }
	]
  }`, ipamSnippet),
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
		Expect(loadCNI(&c)).To(HaveOccurred())
	})
})
