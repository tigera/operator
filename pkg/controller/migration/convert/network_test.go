package convert

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	clientset "github.com/tigera/operator/pkg/client/generated/clientset"
	fakecrd "github.com/tigera/operator/pkg/client/generated/clientset/fake"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func ConfigList(x string) string {
	return fmt.Sprintf(`{
	"name": "k8s-pod-network",
	"cniVersion": "0.3.1",
	"plugins": [ ` + x + `] }`)
}

func int32Ptr(x int32) *int32 {
	return &x
}

var _ = Describe("Convert network tests", func() {
	var ctx = context.Background()
	var fakeCrd clientset.Interface
	BeforeEach(func() {
		fakeCrd = fakecrd.NewSimpleClientset()
		pool := crdv1.NewIPPool()
		pool.Spec = crdv1.IPPoolSpec{
			CIDR:        "192.168.4.0/24",
			IPIPMode:    crdv1.IPIPModeAlways,
			NATOutgoing: true,
		}
		fakeCrd = fakecrd.NewSimpleClientset(pool)
	})

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
			err := Convert(ctx, c, fakeCrd, cfg)
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
			err := Convert(ctx, c, fakeCrd, &operatorv1.Installation{})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("handle Calico CNI migration", func() {
		It("migrate default", func() {
			c := fake.NewFakeClient(emptyNodeSpec(), emptyKubeControllerSpec())
			cfg := &operatorv1.Installation{}
			err := Convert(ctx, c, fakeCrd, cfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
			Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginCalico))
			Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPEnabled))
		})
		It("should convert Calico v3.15 manifest", func() {
			c := fake.NewFakeClient(calicoDefaultConfig()...)
			cfg := operatorv1.Installation{}
			pool := crdv1.NewIPPool()
			pool.Spec = crdv1.IPPoolSpec{
				CIDR:        "192.168.4.0/24",
				IPIPMode:    crdv1.IPIPModeAlways,
				NATOutgoing: true,
			}
			fakeCrd = fakecrd.NewSimpleClientset(pool)
			err := Convert(ctx, c, fakeCrd, &cfg)
			Expect(err).NotTo(HaveOccurred())
			var _1440 int32 = 1440
			_1intstr := intstr.FromInt(1)
			Expect(cfg).To(Equal(operatorv1.Installation{Spec: operatorv1.InstallationSpec{
				CNI: &operatorv1.CNISpec{
					Type: operatorv1.PluginCalico,
					IPAM: &operatorv1.IPAMSpec{Type: operatorv1.IPAMPluginCalico},
				},
				CalicoNetwork: &operatorv1.CalicoNetworkSpec{
					BGP:       operatorv1.BGPOptionPtr(operatorv1.BGPEnabled),
					MTU:       &_1440,
					HostPorts: operatorv1.HostPortsTypePtr(operatorv1.HostPortsEnabled),
					IPPools: []operatorv1.IPPool{{
						CIDR:          "192.168.4.0/24",
						Encapsulation: operatorv1.EncapsulationIPIP,
						NATOutgoing:   operatorv1.NATOutgoingEnabled,
					}},
				},
				FlexVolumePath: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds",
				NodeUpdateStrategy: appsv1.DaemonSetUpdateStrategy{
					Type: "RollingUpdate",
					RollingUpdate: &appsv1.RollingUpdateDaemonSet{
						MaxUnavailable: &_1intstr,
					},
				},
				ComponentResources: []*operatorv1.ComponentResource{
					&operatorv1.ComponentResource{
						ComponentName: operatorv1.ComponentNameNode,
						ResourceRequirements: &corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU: resource.MustParse("250m"),
							},
						},
					},
				},
			}}))
		})
		It("migrate cloud route config", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "host-local"}}`,
			}}
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "CALICO_NETWORKING_BACKEND",
				Value: "none",
			}}
			c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
			cfg := &operatorv1.Installation{}
			err := Convert(ctx, c, fakeCrd, cfg)
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
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam"}}`,
			}}
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "CALICO_NETWORKING_BACKEND",
				Value: "vxlan",
			}}
			c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
			cfg := &operatorv1.Installation{}
			err := Convert(ctx, c, fakeCrd, cfg)
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
					Value: fmt.Sprintf(`{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "%s"}}`, ipam),
				}}
				ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
					Name:  "CALICO_NETWORKING_BACKEND",
					Value: backend,
				}}
				c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
				cfg := &operatorv1.Installation{}
				err := Convert(ctx, c, fakeCrd, cfg)
				Expect(err).To(HaveOccurred())
			},
			Entry("host-local and vxlan", "host-local", "vxlan"),
			Entry("calico and none", "calico-ipam", "none"),
		)
		It("test unknown ipam plugin", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "unknown"}}`,
			}}
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "CALICO_NETWORKING_BACKEND",
				Value: "none",
			}}
			c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
			cfg := &operatorv1.Installation{}
			err := Convert(ctx, c, fakeCrd, cfg)
			Expect(err).To(HaveOccurred())
		})
		Context("HostLocal IPAM", func() {
			DescribeTable("migrate HostLocal BGP config",
				func(backend string) {
					ds := emptyNodeSpec()
					ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
						Name:  "CNI_NETWORK_CONFIG",
						Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "host-local"}}`,
					}}
					ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
						Name:  "CALICO_NETWORKING_BACKEND",
						Value: backend,
					}}
					c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
					cfg := &operatorv1.Installation{}
					err := Convert(ctx, c, fakeCrd, cfg)
					Expect(err).ToNot(HaveOccurred())
					Expect(cfg).ToNot(BeNil())
					Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
					Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginHostLocal))
					Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPEnabled))
				},
				Entry("bird backend", "bird"),
				Entry("<empty> backend", ""),
			)
			DescribeTable("test CNI config name",
				func(cni string) {
					ds := emptyNodeSpec()
					ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
						Name:  "CNI_NETWORK_CONFIG",
						Value: cni,
					}}
					ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
						Name:  "CALICO_NETWORKING_BACKEND",
						Value: "bird",
					}}
					c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
					cfg := &operatorv1.Installation{}
					err := Convert(ctx, c, fakeCrd, cfg)
					Expect(err).NotTo(HaveOccurred())
				},
				Entry("name in conflist", `{"name": "k8s-pod-network",
	"plugins": [
	  {
		"type": "calico",
		"datastore_type": "kubernetes",
		"nodename": "__KUBERNETES_NODE_NAME__",
		"ipam": {"type": "host-local"},
		"policy": {"type": "k8s"}
	  }
	]
  }`),
				Entry("name in single conf", `{"name": "k8s-pod-network",
		"type": "calico",
		"datastore_type": "kubernetes",
		"nodename": "__KUBERNETES_NODE_NAME__",
		"ipam": {"type": "host-local"},
		"policy": {"type": "k8s"}
  }`),
			)
			DescribeTable("test bad CNI config name",
				func(cni string) {
					ds := emptyNodeSpec()
					ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
						Name:  "CNI_NETWORK_CONFIG",
						Value: cni,
					}}
					ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
						Name:  "CALICO_NETWORKING_BACKEND",
						Value: "bird",
					}}
					c := fake.NewFakeClient(ds, emptyKubeControllerSpec())
					cfg := &operatorv1.Installation{}
					err := Convert(ctx, c, fakeCrd, cfg)
					Expect(err).To(HaveOccurred())
				},
				Entry("no name in conflist", `{
	"plugins": [
	  {
		"type": "calico",
		"datastore_type": "kubernetes",
		"nodename": "__KUBERNETES_NODE_NAME__",
		"ipam": {"type": "host-local"},
		"policy": {"type": "k8s"}
	  }
	]
  }`),
				Entry("no name in single conf", `{
		"type": "calico",
		"datastore_type": "kubernetes",
		"nodename": "__KUBERNETES_NODE_NAME__",
		"ipam": {"type": "host-local"},
		"policy": {"type": "k8s"}
  }`),
				Entry("wrong name in conflist", `{"name": "wrong-name",
	"plugins": [
	  {
		"type": "calico",
		"datastore_type": "kubernetes",
		"nodename": "__KUBERNETES_NODE_NAME__",
		"ipam": {"type": "host-local"},
		"policy": {"type": "k8s"}
	  }
	]
  }`),
				Entry("wrong name in single conf", `{"name": "wrong-name",
		"type": "calico",
		"datastore_type": "kubernetes",
		"nodename": "__KUBERNETES_NODE_NAME__",
		"ipam": {"type": "host-local"},
		"policy": {"type": "k8s"}
  }`),
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
					err := Convert(ctx, c, fakeCrd, cfg)
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
					err := Convert(ctx, c, fakeCrd, cfg)
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
					err := Convert(ctx, c, fakeCrd, cfg)
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
					err := Convert(ctx, c, fakeCrd, cfg)
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
				err := Convert(ctx, c, fakeCrd, cfg)
				Expect(err).To(HaveOccurred())
			},
				Entry("subnet", `"subnet": "usePodCidr"`),
				Entry("ipv4_pools", `"ipv4_pools": ["10.0.0.0/24"]`),
				Entry("ipv6_pools", `"ipv6_pools": ["2001:db8::1/120"]`),
				Entry("both pools", `"ipv4_pools": ["10.0.0.0/24"], "ipv6_pools": ["2001:db8::1/120"]`),
			)
		})
	})
	Describe("handle IPPool migration", func() {
		var v4pool1 *crdv1.IPPool
		var v4pool2 *crdv1.IPPool
		var v4pooldefault *crdv1.IPPool
		var v6pool1 *crdv1.IPPool
		var v6pool2 *crdv1.IPPool
		var v6pooldefault *crdv1.IPPool
		BeforeEach(func() {
			v4pool1 = crdv1.NewIPPool()
			v4pool1.Name = "not-default"
			v4pool1.Spec = crdv1.IPPoolSpec{
				CIDR:        "1.168.4.0/24",
				IPIPMode:    crdv1.IPIPModeAlways,
				NATOutgoing: true,
			}
			v4pool2 = crdv1.NewIPPool()
			v4pool2.Name = "not-default2"
			v4pool2.Spec = crdv1.IPPoolSpec{
				CIDR:        "2.168.4.0/24",
				IPIPMode:    crdv1.IPIPModeAlways,
				NATOutgoing: true,
			}
			v4pooldefault = crdv1.NewIPPool()
			v4pooldefault.Name = "default-ipv4-pool"
			v4pooldefault.Spec = crdv1.IPPoolSpec{
				CIDR:        "3.168.4.0/24",
				IPIPMode:    crdv1.IPIPModeAlways,
				NATOutgoing: true,
			}
			v6pool1 = crdv1.NewIPPool()
			v6pool1.Name = "not-default1-v6"
			v6pool1.Spec = crdv1.IPPoolSpec{
				CIDR:        "ff00:0001::/24",
				IPIPMode:    crdv1.IPIPModeNever,
				NATOutgoing: true,
			}
			v6pool2 = crdv1.NewIPPool()
			v6pool2.Name = "not-default2"
			v6pool2.Spec = crdv1.IPPoolSpec{
				CIDR:        "ff00:0002::/24",
				IPIPMode:    crdv1.IPIPModeNever,
				NATOutgoing: true,
			}
			v6pooldefault = crdv1.NewIPPool()
			v6pooldefault.Name = "default-ipv6-pool"
			v6pooldefault.Spec = crdv1.IPPoolSpec{
				CIDR:        "ff00:0003::/24",
				IPIPMode:    crdv1.IPIPModeNever,
				NATOutgoing: true,
			}
		})
		It("should convert default IPv4 pool", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam"}}`,
			}}
			c := fake.NewFakeClient(ds)
			cfg := operatorv1.Installation{}
			fakeCrd = fakecrd.NewSimpleClientset(v4pool1)
			err := Convert(ctx, c, fakeCrd, &cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.Spec.CalicoNetwork.IPPools).To(Equal([]operatorv1.IPPool{{
				CIDR:          "1.168.4.0/24",
				Encapsulation: operatorv1.EncapsulationIPIP,
				NATOutgoing:   operatorv1.NATOutgoingEnabled,
			}}))
		})
		DescribeTable("should pick v4 pool based on CIDR env", func(envcidr, expectcidr string) {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam"}}`,
			}}
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "CALICO_IPV4POOL_CIDR",
				Value: envcidr,
			}}
			c := fake.NewFakeClient(ds)
			cfg := operatorv1.Installation{}
			fakeCrd = fakecrd.NewSimpleClientset(v4pool1, v4pool2, v4pooldefault)
			err := Convert(ctx, c, fakeCrd, &cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.Spec.CalicoNetwork.IPPools).To(HaveLen(1))
			Expect(cfg.Spec.CalicoNetwork.IPPools[0].Encapsulation).To(Equal(operatorv1.EncapsulationIPIP))
			Expect(cfg.Spec.CalicoNetwork.IPPools[0].NATOutgoing).To(Equal(operatorv1.NATOutgoingEnabled))
			Expect(cfg.Spec.CalicoNetwork.IPPools[0].CIDR).To(Equal(expectcidr))
		},
			Entry("find pool 1", "1.168.4.0/24", "1.168.4.0/24"),
			Entry("find pool 2", "2.168.4.0/24", "2.168.4.0/24"),
			Entry("find default pool", "5.168.4.0/24", "3.168.4.0/24"),
		)
		DescribeTable("should pick v6 pool based on CIDR env", func(envcidr, expectcidr string) {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name: "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network",
				         "ipam": {"type": "calico-ipam", "assign_ipv4":"false", "assign_ipv6":"true"}}`,
			}}
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "CALICO_IPV6POOL_CIDR",
				Value: envcidr,
			}}
			c := fake.NewFakeClient(ds)
			cfg := operatorv1.Installation{}
			fakeCrd = fakecrd.NewSimpleClientset(v6pool1, v6pool2, v6pooldefault)
			err := Convert(ctx, c, fakeCrd, &cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.Spec.CalicoNetwork.IPPools).To(HaveLen(1))
			Expect(cfg.Spec.CalicoNetwork.IPPools[0].Encapsulation).To(Equal(operatorv1.EncapsulationNone))
			Expect(cfg.Spec.CalicoNetwork.IPPools[0].NATOutgoing).To(Equal(operatorv1.NATOutgoingEnabled))
			Expect(cfg.Spec.CalicoNetwork.IPPools[0].CIDR).To(Equal(expectcidr))
		},
			Entry("find pool 1", "ff00:0001::/24", "ff00:0001::/24"),
			Entry("find pool 2", "ff00:0002::/24", "ff00:0002::/24"),
			Entry("find default pool", "ff00:0005::/24", "ff00:0003::/24"),
		)
		It("should error on bad pool CIDR", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam"}}`,
			}}
			c := fake.NewFakeClient(ds)
			cfg := operatorv1.Installation{}
			v4pool1.Spec.CIDR = "1.168.0/24"
			fakeCrd = fakecrd.NewSimpleClientset(v4pool1)
			err := Convert(ctx, c, fakeCrd, &cfg)
			Expect(err).To(HaveOccurred())
		})
		It("should ignore disabled pools", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam"}}`,
			}}
			// Set env var that would cause us to pick pool
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "CALICO_IPV4POOL_CIDR",
				Value: "3.168.4.0/24",
			}}
			c := fake.NewFakeClient(ds)
			cfg := operatorv1.Installation{}
			v4pooldefault.Spec.Disabled = true
			fakeCrd = fakecrd.NewSimpleClientset(v4pooldefault, v4pool2)
			err := Convert(ctx, c, fakeCrd, &cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.Spec.CalicoNetwork.IPPools).To(HaveLen(1))
			Expect(cfg.Spec.CalicoNetwork.IPPools[0].CIDR).To(Equal("2.168.4.0/24"))
		})
		It("should pick v4 and v6 pool", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam", "assign_ipv6":"true"}}`,
			}}
			c := fake.NewFakeClient(ds)
			cfg := operatorv1.Installation{}
			fakeCrd = fakecrd.NewSimpleClientset(v4pool1, v6pool1)
			err := Convert(ctx, c, fakeCrd, &cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.Spec.CalicoNetwork.IPPools).To(ConsistOf([]operatorv1.IPPool{{
				CIDR:          "1.168.4.0/24",
				Encapsulation: operatorv1.EncapsulationIPIP,
				NATOutgoing:   operatorv1.NATOutgoingEnabled,
			}, {
				CIDR:          "ff00:0001::/24",
				Encapsulation: operatorv1.EncapsulationNone,
				NATOutgoing:   operatorv1.NATOutgoingEnabled,
			}}))
		})
		DescribeTable("should block mismatch of pools and assign_ip*", func(assigns string, cidrs ...string) {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: fmt.Sprintf(`{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam", %s}}`, assigns),
			}}
			c := fake.NewFakeClient(ds)
			cfg := operatorv1.Installation{}
			pools := []runtime.Object{}
			for i, c := range cidrs {
				p := crdv1.NewIPPool()
				p.Name = fmt.Sprintf("not-default-%d", i)
				p.Spec = crdv1.IPPoolSpec{
					CIDR:        c,
					IPIPMode:    crdv1.IPIPModeAlways,
					NATOutgoing: true,
				}
				pools = append(pools, p)
			}
			fakeCrd = fakecrd.NewSimpleClientset(pools...)
			err := Convert(ctx, c, fakeCrd, &cfg)
			Expect(err).To(HaveOccurred())
		},
			Entry("v4 pool but no assigning v4", `"assign_ipv4": "false"`, "1.168.4.0/24"),
			Entry("no v4 pool but assigning v4", `"assign_ipv4": "true"`),
			Entry("no v6 pool and assign v6 ", `"assign_ipv4": "false", "assign_ipv6": "true"`, "1.168.4.0/24"),
			Entry("v4 pool but assign v6 and v4", `"assign_ipv4": "true", "assign_ipv6": "true"`, "1.168.4.0/24"),
			Entry("v6 pool but assign v6 and v4", `"assign_ipv4": "true", "assign_ipv6": "true"`, "ff00:0001::/24"),
			Entry("v4 and v6 pool but no assigning v4", `"assign_ipv4": "false", "assign_ipv6": "true"`, "1.168.4.0/24", "ff00:0001::/24"),
			Entry("v4 and v6 pool but no assigning v6", `"assign_ipv4": "true", "assign_ipv6": "false"`, "1.168.4.0/24", "ff00:0001::/24"),
		)
		DescribeTable("test convert pool flags", func(success bool, crdPool crdv1.IPPool, opPool operatorv1.IPPool) {
			p, err := convertPool(crdPool)
			if success {
				Expect(err).NotTo(HaveOccurred())
				Expect(*p).To(Equal(opPool))
			} else {
				Expect(err).To(HaveOccurred())
			}
		},
			Entry("ipv4, no encap, nat, block 27", true, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeNever,
				IPIPMode:     crdv1.IPIPModeNever,
				NATOutgoing:  true,
				Disabled:     false,
				BlockSize:    27,
				NodeSelector: "nodeselectorstring",
			}}, operatorv1.IPPool{
				CIDR:          "1.168.4.0/24",
				Encapsulation: operatorv1.EncapsulationNone,
				NATOutgoing:   operatorv1.NATOutgoingEnabled,
				BlockSize:     int32Ptr(27),
				NodeSelector:  "nodeselectorstring",
			}),
			Entry("ipv4, vxlan encap, nat, block 27", true, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeAlways,
				IPIPMode:     crdv1.IPIPModeNever,
				NATOutgoing:  true,
				Disabled:     false,
				BlockSize:    27,
				NodeSelector: "nodeselectorstring",
			}}, operatorv1.IPPool{
				CIDR:          "1.168.4.0/24",
				Encapsulation: operatorv1.EncapsulationVXLAN,
				NATOutgoing:   operatorv1.NATOutgoingEnabled,
				BlockSize:     int32Ptr(27),
				NodeSelector:  "nodeselectorstring",
			}),
			Entry("ipv4, ipip encap, nat, block 27", true, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeNever,
				IPIPMode:     crdv1.IPIPModeAlways,
				NATOutgoing:  true,
				Disabled:     false,
				BlockSize:    27,
				NodeSelector: "nodeselectorstring",
			}}, operatorv1.IPPool{
				CIDR:          "1.168.4.0/24",
				Encapsulation: operatorv1.EncapsulationIPIP,
				NATOutgoing:   operatorv1.NATOutgoingEnabled,
				BlockSize:     int32Ptr(27),
				NodeSelector:  "nodeselectorstring",
			}),
			Entry("ipv4, vxlancross encap, nat, block 27", true, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeCrossSubnet,
				IPIPMode:     crdv1.IPIPModeNever,
				NATOutgoing:  true,
				Disabled:     false,
				BlockSize:    27,
				NodeSelector: "nodeselectorstring",
			}}, operatorv1.IPPool{
				CIDR:          "1.168.4.0/24",
				Encapsulation: operatorv1.EncapsulationVXLANCrossSubnet,
				NATOutgoing:   operatorv1.NATOutgoingEnabled,
				BlockSize:     int32Ptr(27),
				NodeSelector:  "nodeselectorstring",
			}),
			Entry("ipv4, ipipcross encap, nat, block 27", true, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeNever,
				IPIPMode:     crdv1.IPIPModeCrossSubnet,
				NATOutgoing:  true,
				Disabled:     false,
				BlockSize:    27,
				NodeSelector: "nodeselectorstring",
			}}, operatorv1.IPPool{
				CIDR:          "1.168.4.0/24",
				Encapsulation: operatorv1.EncapsulationIPIPCrossSubnet,
				NATOutgoing:   operatorv1.NATOutgoingEnabled,
				BlockSize:     int32Ptr(27),
				NodeSelector:  "nodeselectorstring",
			}),
			Entry("ipv4, no encap, no nat, block 27", true, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeNever,
				IPIPMode:     crdv1.IPIPModeNever,
				NATOutgoing:  false,
				Disabled:     false,
				BlockSize:    27,
				NodeSelector: "nodeselectorstring",
			}}, operatorv1.IPPool{
				CIDR:          "1.168.4.0/24",
				Encapsulation: operatorv1.EncapsulationNone,
				NATOutgoing:   operatorv1.NATOutgoingDisabled,
				BlockSize:     int32Ptr(27),
				NodeSelector:  "nodeselectorstring",
			}),
			Entry("ipv4, no encap, nat, block 24", true, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeNever,
				IPIPMode:     crdv1.IPIPModeNever,
				NATOutgoing:  true,
				Disabled:     false,
				BlockSize:    24,
				NodeSelector: "nodeselectorstring",
			}}, operatorv1.IPPool{
				CIDR:          "1.168.4.0/24",
				Encapsulation: operatorv1.EncapsulationNone,
				NATOutgoing:   operatorv1.NATOutgoingEnabled,
				BlockSize:     int32Ptr(24),
				NodeSelector:  "nodeselectorstring",
			}),
			Entry("ipv4, no encap, nat, block 27, differnt nodeselector", true, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeNever,
				IPIPMode:     crdv1.IPIPModeNever,
				NATOutgoing:  true,
				Disabled:     false,
				BlockSize:    27,
				NodeSelector: "othernodeselector",
			}}, operatorv1.IPPool{
				CIDR:          "1.168.4.0/24",
				Encapsulation: operatorv1.EncapsulationNone,
				NATOutgoing:   operatorv1.NATOutgoingEnabled,
				BlockSize:     int32Ptr(27),
				NodeSelector:  "othernodeselector",
			}),

			Entry("ipv4, invalid encap, nat, block 27", false, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeAlways,
				IPIPMode:     crdv1.IPIPModeAlways,
				NATOutgoing:  true,
				Disabled:     false,
				BlockSize:    27,
				NodeSelector: "nodeselectorstring",
			}}, operatorv1.IPPool{}),
			Entry("ipv4, invalid encap2, nat, block 27", false, crdv1.IPPool{Spec: crdv1.IPPoolSpec{
				CIDR:         "1.168.4.0/24",
				VXLANMode:    crdv1.VXLANModeCrossSubnet,
				IPIPMode:     crdv1.IPIPModeAlways,
				NATOutgoing:  true,
				Disabled:     false,
				BlockSize:    27,
				NodeSelector: "nodeselectorstring",
			}}, operatorv1.IPPool{}),
		)
	})
})
