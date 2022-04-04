package convert

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	kscheme "k8s.io/client-go/kubernetes/scheme"
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
	var pool *crdv1.IPPool
	var scheme *runtime.Scheme
	BeforeEach(func() {
		scheme = kscheme.Scheme
		err := apis.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
	})

	Context("with IPv4 pool", func() {
		BeforeEach(func() {
			pool = crdv1.NewIPPool()
			pool.Spec = crdv1.IPPoolSpec{
				CIDR:        "192.168.4.0/24",
				IPIPMode:    crdv1.IPIPModeAlways,
				NATOutgoing: true,
			}
		})

		Describe("handle alternate CNI migration", func() {
			DescribeTable("non-calico plugins", func(envs []corev1.EnvVar, plugin operatorv1.CNIPluginType) {
				ds := emptyNodeSpec()
				ds.Spec.Template.Spec.InitContainers = nil
				ds.Spec.Template.Spec.Containers[0].Env = append(envs, corev1.EnvVar{
					Name:  "CALICO_NETWORKING_BACKEND",
					Value: "none",
				})

				c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), pool, emptyFelixConfig())
				cfg, err := Convert(ctx, c)
				Expect(err).ToNot(HaveOccurred())
				Expect(cfg).ToNot(BeNil())
				Expect(cfg.Spec.CNI.Type).To(Equal(plugin))
			},
				Entry("AzureVNET", []corev1.EnvVar{{Name: "FELIX_INTERFACEPREFIX", Value: "azv"}}, operatorv1.PluginAzureVNET),
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
				c := fake.NewFakeClientWithScheme(scheme, append([]runtime.Object{pool, emptyFelixConfig(), getK8sNodes(6)}, awsCNIPolicyOnlyConfig()...)...)
				_, err := Convert(ctx, c)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Describe("handle Calico CNI migration", func() {
			It("migrate default", func() {
				c := fake.NewFakeClientWithScheme(scheme, emptyNodeSpec(), emptyKubeControllerSpec(), pool, emptyFelixConfig())
				cfg, err := Convert(ctx, c)
				Expect(err).ToNot(HaveOccurred())
				Expect(cfg).ToNot(BeNil())
				Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
				Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginCalico))
				Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPEnabled))
			})
			It("should convert Calico v3.15 manifest", func() {
				pool = crdv1.NewIPPool()
				pool.Spec = crdv1.IPPoolSpec{
					CIDR:        "192.168.4.0/24",
					IPIPMode:    crdv1.IPIPModeAlways,
					NATOutgoing: true,
				}
				c := fake.NewFakeClientWithScheme(scheme, append([]runtime.Object{pool, emptyFelixConfig()}, calicoDefaultConfig()...)...)
				cfg, err := Convert(ctx, c)
				Expect(err).NotTo(HaveOccurred())
				var _1440 int32 = 1440
				_1intstr := intstr.FromInt(1)
				Expect(*cfg).To(Equal(operatorv1.Installation{Spec: operatorv1.InstallationSpec{
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
					ComponentResources: []operatorv1.ComponentResource{{
						ComponentName: operatorv1.ComponentNameNode,
						ResourceRequirements: &corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU: resource.MustParse("250m"),
							},
						}},
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
				c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), pool, emptyFelixConfig())
				cfg, err := Convert(ctx, c)
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
				c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), pool, emptyFelixConfig())
				cfg, err := Convert(ctx, c)
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
					c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), pool, emptyFelixConfig())
					_, err := Convert(ctx, c)
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
				c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), pool, emptyFelixConfig())
				_, err := Convert(ctx, c)
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
						c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), pool, emptyFelixConfig())
						cfg, err := Convert(ctx, c)
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
						c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), pool, emptyFelixConfig())
						_, err := Convert(ctx, c)
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
						c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), pool, emptyFelixConfig())
						_, err := Convert(ctx, c)
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
						c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), pool, emptyFelixConfig())
						_, err := Convert(ctx, c)
						Expect(err).To(HaveOccurred())
					},
					Entry("unsupported ranges", `"ranges": [[{ "subnet": "usePodCidr" }],[{ "subnet": "2001:db8::/96" }]]`),
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
						c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), pool, emptyFelixConfig())
						_, err := Convert(ctx, c)
						Expect(err).NotTo(HaveOccurred())
					},
					Entry("subnet in ipam section", `"subnet": "usePodCidr"`),
					Entry("subnet in ranges section under ipam", `"ranges": [[{ "subnet": "usePodCidr" }]]`),
					Entry("dual-stack subnets in ranges section", `"ranges": [[{ "subnet": "usePodCidr" }], [{ "subnet": "usePodCidrIPv6" }]]`),
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
						c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), pool, emptyFelixConfig())
						cfg, err := Convert(ctx, c)
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
						c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), pool, emptyFelixConfig())
						cfg, err := Convert(ctx, c)
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
					c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), pool, emptyFelixConfig())
					_, err := Convert(ctx, c)
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

	Context("with IPv6 pool", func() {
		var ds *appsv1.DaemonSet
		BeforeEach(func() {
			ds = emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam", "assign_ipv4": "false", "assign_ipv6": "true"}}`,
			}}

			pool = crdv1.NewIPPool()
			pool.Spec = crdv1.IPPoolSpec{
				CIDR:        "2001:db8::1/120",
				IPIPMode:    crdv1.IPIPModeAlways,
				NATOutgoing: true,
			}

		})
		Describe("handle Calico CNI migration", func() {
			It("migrate calico-ipam and vxlan config", func() {
				ds := emptyNodeSpec()
				ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
					Name:  "CNI_NETWORK_CONFIG",
					Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam", "assign_ipv4": "false", "assign_ipv6": "true"}}`,
				}}
				ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
					Name:  "CALICO_NETWORKING_BACKEND",
					Value: "vxlan",
				}}
				c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), pool, emptyFelixConfig())
				cfg, err := Convert(ctx, c)
				Expect(err).ToNot(HaveOccurred())
				Expect(cfg).ToNot(BeNil())
				Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
				Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginCalico))
				Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPDisabled))
			})
		})

	})

	DescribeTable("handle IPv6", func(envVars []corev1.EnvVar, errorExpected bool) {
		pool = crdv1.NewIPPool()
		pool.Spec = crdv1.IPPoolSpec{
			//CIDR:        "2001:db8::1/120",
			CIDR:        "192.168.4.0/24",
			IPIPMode:    crdv1.IPIPModeAlways,
			NATOutgoing: true,
		}
		ds := emptyNodeSpec()
		ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env, envVars...)
		c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), pool, emptyFelixConfig())
		cfg, err := Convert(ctx, c)
		if errorExpected {
			Expect(err).To(HaveOccurred())
			Expect(cfg).To(BeNil())
		} else {
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
		}
	},
		Entry("should not error if IP6=none", []corev1.EnvVar{
			{Name: "IP6", Value: "none"},
			{Name: "FELIX_IPV6SUPPORT", Value: "false"}}, false),
		Entry("should error if IP6=none but FELIX_IPV6SUPPORT=true", []corev1.EnvVar{
			{Name: "IP6", Value: "none"},
			{Name: "FELIX_IPV6SUPPORT", Value: "true"}}, true),
		Entry("should not error if IP6=none and FELIX_IPV6SUPPORT is undefined", []corev1.EnvVar{{Name: "IP6", Value: "none"}}, false),
		Entry("should not error if FELIX_IPV6SUPPORT is false", []corev1.EnvVar{{Name: "FELIX_IPV6SUPPORT", Value: "false"}}, false),
		Entry("should error if FELIX_IPV6SUPPORT is true", []corev1.EnvVar{{Name: "FELIX_IPV6SUPPORT", Value: "true"}}, true),
		Entry("should allow IPv6 only",
			[]corev1.EnvVar{
				{Name: "IP", Value: "none"},
				{Name: "IP6", Value: "autodetect"},
				{Name: "FELIX_IPV6SUPPORT", Value: "true"}}, false),
		Entry("should error if IPv6 only and CALICO_ROUTER_ID is not `hash`",
			[]corev1.EnvVar{
				{Name: "IP", Value: "none"},
				{Name: "IP6", Value: "autodetect"},
				{Name: "FELIX_IPV6SUPPORT", Value: "true"},
				{Name: "CALICO_ROUTER_ID", Value: "not hash"}}, true),
		Entry("should allow dual-stack",
			[]corev1.EnvVar{
				{Name: "IP", Value: "autodetect"},
				{Name: "IP6", Value: "autodetect"},
				{Name: "FELIX_IPV6SUPPORT", Value: "true"}}, false),
		Entry("should error if IPv6 only and CALICO_ROUTER_ID is undefined", []corev1.EnvVar{{Name: "FELIX_IPV6SUPPORT", Value: "true"}}, true),
	)

	Describe("handle IP_AUTODETECTION_METHOD env", func() {
		var ds *appsv1.DaemonSet

		BeforeEach(func() {
			ds = emptyNodeSpec()
			// Set assign_ipv4=false to avoid needing an IPPool for these tests.
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam", "assign_ipv4":"false"}}`,
			}}
		})

		It("migrate cidr=", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  "IP_AUTODETECTION_METHOD",
				Value: "cidr=10.0.0.0/24,10.0.1.0/24",
			})

			c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), emptyFelixConfig())
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4).NotTo(BeNil())
			Expect(*&cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4.CIDRS).To(Equal([]string{"10.0.0.0/24", "10.0.1.0/24"}))
		})
		It("migrate first-found", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  "IP_AUTODETECTION_METHOD",
				Value: "first-found",
			})

			c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), emptyFelixConfig())
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound).NotTo(BeNil())
			Expect(*cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound).To(Equal(true))
		})
		It("migrate can-reach=", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  "IP_AUTODETECTION_METHOD",
				Value: "can-reach=8.8.8.8",
			})

			c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), emptyFelixConfig())
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4.CanReach).To(Equal("8.8.8.8"))
		})
		It("migrate interface=", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  "IP_AUTODETECTION_METHOD",
				Value: "interface=ens*",
			})

			c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), emptyFelixConfig())
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4.Interface).To(Equal("ens*"))
		})
		It("migrate skip-interface=", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  "IP_AUTODETECTION_METHOD",
				Value: "skip-interface=eth1",
			})

			c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), emptyFelixConfig())
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4.SkipInterface).To(Equal("eth1"))
		})
		It("migrate kubernetes-internal-ip", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  "IP_AUTODETECTION_METHOD",
				Value: "kubernetes-internal-ip",
			})

			c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), emptyFelixConfig())
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4.Kubernetes).NotTo(BeNil())
		})
		It("return error if method is invalid", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  "IP_AUTODETECTION_METHOD",
				Value: "invalid",
			})

			c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), emptyFelixConfig())
			cfg, err := Convert(ctx, c)
			Expect(err).To(HaveOccurred())
			Expect(cfg).To(BeNil())
		})
	})

	Describe("handle IP6_AUTODETECTION_METHOD env", func() {
		var ds *appsv1.DaemonSet

		BeforeEach(func() {
			ds = emptyNodeSpec()
			// Set assign_ipv4=false to avoid needing an IPPool for these tests.
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam", "assign_ipv4":"false"}}`,
			}}
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6",
					Value: "autodetect",
				},
				corev1.EnvVar{
					Name:  "FELIX_IPV6SUPPORT",
					Value: "true",
				},
			)
		})

		It("migrate cidr=", func() {
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam", "assign_ipv4":"false", "assign_ipv6":"false"}}`,
			}}

			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6_AUTODETECTION_METHOD",
					Value: "cidr=2001:20::8/64",
				},
			)
			c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), emptyFelixConfig())
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6).NotTo(BeNil())
			Expect(*&cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6.CIDRS).To(Equal([]string{"2001:20::8/64"}))
		})
		It("migrate first-found", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6_AUTODETECTION_METHOD",
					Value: "first-found",
				})

			c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), emptyFelixConfig())
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6.FirstFound).NotTo(BeNil())
			Expect(*cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6.FirstFound).To(Equal(true))
		})
		It("migrate can-reach=", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6_AUTODETECTION_METHOD",
					Value: "can-reach=2001:4860:4860::8888",
				},
			)

			c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), emptyFelixConfig())
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6.CanReach).To(Equal("2001:4860:4860::8888"))
		})
		It("migrate interface=", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6_AUTODETECTION_METHOD",
					Value: "interface=ens*",
				},
			)

			c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), emptyFelixConfig())
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6.Interface).To(Equal("ens*"))
		})
		It("migrate skip-interface=", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6_AUTODETECTION_METHOD",
					Value: "skip-interface=eth1",
				},
			)

			c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), emptyFelixConfig())
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6.SkipInterface).To(Equal("eth1"))
		})
		It("migrate kubernetes-internal-ip", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6_AUTODETECTION_METHOD",
					Value: "kubernetes-internal-ip",
				},
			)

			c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), emptyFelixConfig())
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6.Kubernetes).NotTo(BeNil())
		})
		It("return error if method is invalid", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6_AUTODETECTION_METHOD",
					Value: "invalid",
				},
			)

			c := fake.NewFakeClientWithScheme(scheme, ds, emptyKubeControllerSpec(), emptyFelixConfig())
			cfg, err := Convert(ctx, c)
			Expect(err).To(HaveOccurred())
			Expect(cfg).To(BeNil())
		})
	})
})
