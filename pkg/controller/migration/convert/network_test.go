package convert

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func ConfigList(x string) string {
	return fmt.Sprintf(`{
	"name": "k8s-pod-network",
	"cniVersion": "0.3.1",
	"plugins": [ ` + x + `] }`)
}

var _ = Describe("Convert network tests", func() {
	var ctx = context.Background()

	Describe("handle alternate CNI migration", func() {
		DescribeTable("non-calico plugins", func(envs []corev1.EnvVar, plugin operatorv1.CNIPluginType) {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers = nil
			ds.Spec.Template.Spec.Containers[0].Env = append(envs, corev1.EnvVar{
				Name:  "CALICO_NETWORKING_BACKEND",
				Value: "none",
			})

			c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
			cfg := &operatorv1.Installation{}
			err := Convert(ctx, c, cfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CNI.Type).To(Equal(plugin))
		},
			Entry("AzureVNET", []corev1.EnvVar{{Name: "FELIX_INTERFACEPREFIX", Value: "avz"}}, operatorv1.PluginAzureVNET),
			Entry("AmazonVPC", []corev1.EnvVar{
				{Name: "FELIX_INTERFACEPREFIX", Value: "eni"},
				{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
			}, operatorv1.PluginAmazonVPC),
			Entry("GKE", []corev1.EnvVar{
				{Name: "FELIX_INTERFACEPREFIX", Value: "gke"},
				{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
				{Name: "FELIX_IPTABLESFILTERALLOWACTION", Value: "Return"},
			}, operatorv1.PluginGKE),
		)
		It("should convert AWS CNI install", func() {
			c := fake.NewFakeClient(awsCNIPolicyOnlyConfig()...)
			err := Convert(ctx, c, &operatorv1.Installation{})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("handle Calico CNI migration", func() {
		It("migrate default", func() {
			c := fake.NewFakeClient(emptyNodeSpec(), emptyKubeControllerSpec())
			cfg := &operatorv1.Installation{}
			err := Convert(ctx, c, cfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
			Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginCalico))
			Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPEnabled))
		})
		It("migrate cloud route config", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "ipam": {"type": "host-local"}}`,
			}}
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "CALICO_NETWORKING_BACKEND",
				Value: "none",
			}}
			c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
			cfg := &operatorv1.Installation{}
			err := Convert(ctx, c, cfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
			Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginHostLocal))
			Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPDisabled))
		})
		It("migrate calico-ipam and vxlan config", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "ipam": {"type": "calico-ipam"}}`,
			}}
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "CALICO_NETWORKING_BACKEND",
				Value: "vxlan",
			}}
			c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
			cfg := &operatorv1.Installation{}
			err := Convert(ctx, c, cfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
			Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginCalico))
			Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPDisabled))
		})
		DescribeTable("test invalid ipam and backend",
			func(ipam, backend string) {
				ds := emptyNodeSpec()
				ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
					Name:  "CNI_NETWORK_CONFIG",
					Value: fmt.Sprintf(`{"type": "calico", "ipam": {"type": "%s"}}`, ipam),
				}}
				ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
					Name:  "CALICO_NETWORKING_BACKEND",
					Value: backend,
				}}
				c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
				cfg := &operatorv1.Installation{}
				err := Convert(ctx, c, cfg)
				Expect(err).To(HaveOccurred())
			},
			Entry("host-local and vxlan", "host-local", "vxlan"),
			Entry("calico and none", "calico-ipam", "none"),
		)
		It("test unknown ipam plugin", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "ipam": {"type": "unknown"}}`,
			}}
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "CALICO_NETWORKING_BACKEND",
				Value: "none",
			}}
			c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
			cfg := &operatorv1.Installation{}
			err := Convert(ctx, c, cfg)
			Expect(err).To(HaveOccurred())
		})
		Context("HostLocal IPAM", func() {
			DescribeTable("migrate HostLocal BGP config",
				func(backend string) {
					ds := emptyNodeSpec()
					ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
						Name:  "CNI_NETWORK_CONFIG",
						Value: `{"type": "calico", "ipam": {"type": "host-local"}}`,
					}}
					ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
						Name:  "CALICO_NETWORKING_BACKEND",
						Value: backend,
					}}
					c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
					cfg := &operatorv1.Installation{}
					err := Convert(ctx, c, cfg)
					Expect(err).ToNot(HaveOccurred())
					Expect(cfg).ToNot(BeNil())
					Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
					Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginHostLocal))
					Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPEnabled))
				},
				Entry("bird backend", "bird"),
				Entry("<empty> backend", ""),
			)
			DescribeTable("test unsupported CNI config",
				func(ipamExtra string) {
					ds := emptyNodeSpec()
					ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
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
		"ipam": {
			"type": "host-local",
			%s
		},
		"policy": {
			"type": "k8s"
		},
		"kubernetes": {
			"kubeconfig": "__KUBECONFIG_FILEPATH__"
		}
	  }
	]
  }`, ipamExtra),
					}}
					ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
						Name:  "CALICO_NETWORKING_BACKEND",
						Value: "bird",
					}}
					c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
					cfg := &operatorv1.Installation{}
					err := Convert(ctx, c, cfg)
					Expect(err).To(HaveOccurred())
				},
				Entry("ranges", `"ranges": [[{ "subnet": "usePodCidr" }],[{ "subnet": "2001:db8::/96" }]]`),
				Entry("routes", `"routes": [{ "dst": "0.0.0.0/0" },{ "dst": "2001:db8::/96" }]`),
				Entry("dataDir", `"dataDir": "/some/path/i/think/would/be/here"`),
				Entry("unknown field", `"unknownField": "something"`),
			)
			DescribeTable("test valid HostLocal config with usePodCidr configs",
				func(ipamExtra string) {
					ds := emptyNodeSpec()
					ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
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
		"ipam": {
			"type": "host-local",
			%s
		},
		"policy": {
			"type": "k8s"
		},
		"kubernetes": {
			"kubeconfig": "__KUBECONFIG_FILEPATH__"
		}
	  }
	]
  }`, ipamExtra),
					}}
					ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
						Name:  "CALICO_NETWORKING_BACKEND",
						Value: "bird",
					}}
					c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
					cfg := &operatorv1.Installation{}
					err := Convert(ctx, c, cfg)
					Expect(err).NotTo(HaveOccurred())
				},
				Entry("subnet in ipam section", `"subnet": "usePodCidr"`),
				Entry("subnet in ranges section under ipam", `"ranges": [[{ "subnet": "usePodCidr" }]]`),
			)
		})

		Context("Calico CNI config flags", func() {
			Describe("migrate portmap setting", func() {
				It("no portmap in config", func() {
					ds := emptyNodeSpec()
					ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
						Name: "CNI_NETWORK_CONFIG",
						Value: `{
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
		"type": "host-local"
	},
	"policy": {
		"type": "k8s"
	},
	"kubernetes": {
		"kubeconfig": "__KUBECONFIG_FILEPATH__"
	}
  }
  ]
}`,
					}}
					ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
						Name:  "CALICO_NETWORKING_BACKEND",
						Value: "bird",
					}}
					c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
					cfg := &operatorv1.Installation{}
					err := Convert(ctx, c, cfg)
					Expect(err).ToNot(HaveOccurred())
					Expect(cfg).ToNot(BeNil())
					Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
					Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginHostLocal))
					Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPEnabled))
					Expect(*cfg.Spec.CalicoNetwork.HostPorts).To(Equal(operatorv1.HostPortsDisabled))
				})
				It("portmap in config", func() {
					ds := emptyNodeSpec()
					ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
						Name: "CNI_NETWORK_CONFIG",
						Value: `{
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
		"type": "host-local"
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
    }
  ]
}`,
					}}
					ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
						Name:  "CALICO_NETWORKING_BACKEND",
						Value: "bird",
					}}
					c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
					cfg := &operatorv1.Installation{}
					err := Convert(ctx, c, cfg)
					Expect(err).ToNot(HaveOccurred())
					Expect(cfg).ToNot(BeNil())
					Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
					Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginHostLocal))
					Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPEnabled))
					Expect(*cfg.Spec.CalicoNetwork.HostPorts).To(Equal(operatorv1.HostPortsEnabled))
				})
			})
			DescribeTable("block on IPAM flags", func(ipam string) {
				ds := emptyNodeSpec()
				ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
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
	"ipam": { "type": "calico-ipam", %s },
	"policy": {
		"type": "k8s"
	},
	"kubernetes": {
		"kubeconfig": "__KUBECONFIG_FILEPATH__"
	}
  }
  ]
}`, ipam),
				}}
				ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
					Name:  "CALICO_NETWORKING_BACKEND",
					Value: "bird",
				}}
				c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
				cfg := &operatorv1.Installation{}
				err := Convert(ctx, c, cfg)
				Expect(err).To(HaveOccurred())
			},
				Entry("subnet", `"subnet": "usePodCidr"`),
				Entry("ipv4_pools", `"ipv4_pools": ["10.0.0.0/24"]`),
				Entry("ipv6_pools", `"ipv6_pools": ["2001:db8::1/120"]`),
				Entry("both pools", `"ipv4_pools": ["10.0.0.0/24"], "ipv6_pools": ["2001:db8::1/120"]`),
			)
		})
	})
})
