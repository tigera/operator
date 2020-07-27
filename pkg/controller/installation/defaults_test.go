// Copyright (c) 2019 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package installation

import (
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	osconfigv1 "github.com/openshift/api/config/v1"
	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var _ = Describe("Defaulting logic tests", func() {
	It("should properly fill defaults on an empty instance", func() {
		instance := &operator.Installation{}
		fillDefaults(instance)
		Expect(instance.Spec.Variant).To(Equal(operator.Calico))
		Expect(instance.Spec.Registry).To(BeEmpty())
		v4pool := render.GetIPv4Pool(instance.Spec.CalicoNetwork.IPPools)
		Expect(v4pool).ToNot(BeNil())
		Expect(v4pool.CIDR).To(Equal("192.168.0.0/16"))
		Expect(v4pool.BlockSize).NotTo(BeNil())
		Expect(*v4pool.BlockSize).To(Equal(int32(26)))
		v6pool := render.GetIPv6Pool(instance.Spec.CalicoNetwork.IPPools)
		Expect(v6pool).To(BeNil())
		Expect(instance.Spec.CNI.Type).To(Equal(operator.PluginCalico))
		Expect(instance.Spec.CalicoNetwork).NotTo(BeNil())
		Expect(*instance.Spec.CalicoNetwork.BGP).To(Equal(operator.BGPEnabled))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should properly fill defaults on an empty TigeraSecureEnterprise instance", func() {
		instance := &operator.Installation{}
		instance.Spec.Variant = operator.TigeraSecureEnterprise
		fillDefaults(instance)
		Expect(instance.Spec.Variant).To(Equal(operator.TigeraSecureEnterprise))
		Expect(instance.Spec.Registry).To(BeEmpty())
		v4pool := render.GetIPv4Pool(instance.Spec.CalicoNetwork.IPPools)
		Expect(v4pool).ToNot(BeNil())
		Expect(v4pool.CIDR).To(Equal("192.168.0.0/16"))
		Expect(v4pool.BlockSize).NotTo(BeNil())
		Expect(*v4pool.BlockSize).To(Equal(int32(26)))
		v6pool := render.GetIPv6Pool(instance.Spec.CalicoNetwork.IPPools)
		Expect(v6pool).To(BeNil())
		Expect(instance.Spec.CalicoNetwork).NotTo(BeNil())
		Expect(*instance.Spec.CalicoNetwork.BGP).To(Equal(operator.BGPEnabled))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should not override custom configuration", func() {
		var mtu int32 = 1500
		var nodeMetricsPort int32 = 9081
		var false_ = false
		var twentySeven int32 = 27
		var oneTwoThree int32 = 123
		var one intstr.IntOrString = intstr.FromInt(1)

		hpEnabled := operator.HostPortsEnabled
		disabled := operator.BGPDisabled
		miMode := operator.MultiInterfaceModeNone
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				Variant:  operator.TigeraSecureEnterprise,
				Registry: "test-reg/",
				ImagePullSecrets: []v1.LocalObjectReference{
					{
						Name: "pullSecret1",
					},
					{
						Name: "pullSecret2",
					},
				},
				CNI: &operator.CNISpec{Type: operator.PluginCalico},
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools: []operator.IPPool{
						{
							CIDR:          "1.2.3.0/24",
							Encapsulation: "VXLANCrossSubnet",
							NATOutgoing:   "Enabled",
							NodeSelector:  "has(thiskey)",
							BlockSize:     &twentySeven,
						},
						{
							CIDR:          "fd00::0/64",
							Encapsulation: "None",
							NATOutgoing:   "Enabled",
							NodeSelector:  "has(thiskey)",
							BlockSize:     &oneTwoThree,
						},
					},
					MTU: &mtu,
					BGP: &disabled,
					NodeAddressAutodetectionV4: &operator.NodeAddressAutodetection{
						FirstFound: &false_,
					},
					NodeAddressAutodetectionV6: &operator.NodeAddressAutodetection{
						FirstFound: &false_,
					},
					HostPorts:          &hpEnabled,
					MultiInterfaceMode: &miMode,
				},
				NodeMetricsPort: &nodeMetricsPort,
				FlexVolumePath:  "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
				NodeUpdateStrategy: appsv1.DaemonSetUpdateStrategy{
					Type: appsv1.RollingUpdateDaemonSetStrategyType,
					RollingUpdate: &appsv1.RollingUpdateDaemonSet{
						MaxUnavailable: &one,
					},
				},
			},
		}
		instanceCopy := instance.DeepCopyObject().(*operator.Installation)
		fillDefaults(instanceCopy)
		Expect(instanceCopy.Spec).To(Equal(instance.Spec))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should default BGP to enabled for Calico CNI", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
				},
			},
		}
		fillDefaults(instance)
		Expect(*instance.Spec.CalicoNetwork.BGP).To(Equal(operator.BGPEnabled))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should default BGP to disabled for other CNI plugins", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CNI: &operator.CNISpec{
					Type: operator.PluginAmazonVPC,
				},
				CalicoNetwork: &operator.CalicoNetworkSpec{},
			},
		}
		fillDefaults(instance)
		Expect(*instance.Spec.CalicoNetwork.BGP).To(Equal(operator.BGPDisabled))

		// TODO: This is currently a validation error because we don't support
		// any CalicoNetwork options for non-Calico CNIs. But this will change.
		Expect(validateCustomResource(instance)).To(HaveOccurred())
	})

	It("should correct missing slashes on registry", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				Registry: "test-reg",
			},
		}
		fillDefaults(instance)
		Expect(instance.Spec.Registry).To(Equal("test-reg/"))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should properly fill defaults for an IPv6-only instance", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools: []operator.IPPool{{CIDR: "fd00::0/64"}},
				},
			},
		}

		fillDefaults(instance)

		v4pool := render.GetIPv4Pool(instance.Spec.CalicoNetwork.IPPools)
		Expect(v4pool).To(BeNil())

		v6pool := render.GetIPv6Pool(instance.Spec.CalicoNetwork.IPPools)
		Expect(v6pool).NotTo(BeNil())
		Expect(v6pool.CIDR).To(Equal("fd00::0/64"))
		Expect(v6pool.BlockSize).NotTo(BeNil())
		Expect(*v6pool.BlockSize).To(Equal(int32(122)))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	table.DescribeTable("All pools should have all fields set from mergeAndFillDefaults function",
		func(i *operator.Installation, on *osconfigv1.Network, kadmc *v1.ConfigMap) {
			Expect(mergeAndFillDefaults(i, on, kadmc)).To(BeNil())

			if i.Spec.CalicoNetwork != nil && i.Spec.CalicoNetwork.IPPools != nil && len(i.Spec.CalicoNetwork.IPPools) != 0 {
				v4pool := render.GetIPv4Pool(i.Spec.CalicoNetwork.IPPools)
				Expect(v4pool).ToNot(BeNil())
				Expect(v4pool.CIDR).ToNot(BeEmpty(), "CIDR should be set on pool %v", v4pool)
				Expect(v4pool.Encapsulation).To(BeElementOf(operator.EncapsulationTypes), "Encapsulation should be set on pool %q", v4pool)
				Expect(v4pool.NATOutgoing).To(BeElementOf(operator.NATOutgoingTypes), "NATOutgoing should be set on pool %v", v4pool)
				Expect(v4pool.NodeSelector).ToNot(BeEmpty(), "NodeSelector should be set on pool %v", v4pool)
				v6pool := render.GetIPv6Pool(i.Spec.CalicoNetwork.IPPools)
				Expect(v6pool).To(BeNil())
			}
			Expect(validateCustomResource(i)).NotTo(HaveOccurred())
		},

		table.Entry("Empty config defaults IPPool", &operator.Installation{}, nil, nil),
		table.Entry("Openshift only CIDR",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{},
				},
			}, &osconfigv1.Network{
				Spec: osconfigv1.NetworkSpec{
					ClusterNetwork: []osconfigv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/8"},
					},
				},
			},
			nil,
		),
		table.Entry("CIDR specified from OS config and Calico config",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{
						IPPools: []operator.IPPool{
							{CIDR: "10.0.0.0/24"},
						},
					},
				},
			}, &osconfigv1.Network{
				Spec: osconfigv1.NetworkSpec{
					ClusterNetwork: []osconfigv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/8"},
					},
				},
			},
			nil,
		),
		table.Entry("kubeadm only CIDR",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{},
				},
			},
			nil,
			&v1.ConfigMap{Data: map[string]string{"ClusterConfiguration": "podSubnet: 10.0.0.0/8"}},
		),
		table.Entry("CIDR specified from kubeadm config and Calico config",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{
						IPPools: []operator.IPPool{
							{CIDR: "10.0.0.0/24"},
						},
					},
				},
			},
			nil,
			&v1.ConfigMap{Data: map[string]string{"ClusterConfiguration": "podSubnet: 10.0.0.0/8"}},
		),
	)

	table.DescribeTable("Test different values for FlexVolumePath",
		func(i *operator.Installation, expectedFlexVolumePath string) {
			Expect(fillDefaults(i)).To(BeNil())
			Expect(i.Spec.FlexVolumePath).To(Equal(expectedFlexVolumePath))
		},

		table.Entry("FlexVolumePath set to None",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					FlexVolumePath: "None",
				},
			}, "None",
		),

		table.Entry("FlexVolumePath left empty (default)",
			&operator.Installation{
				Spec: operator.InstallationSpec{},
			}, "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
		),

		table.Entry("FlexVolumePath set to a custom path",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					FlexVolumePath: "/foo/bar/",
				},
			}, "/foo/bar/",
		),
	)
	It("should default an empty CNI to Calico with no KubernetesProvider", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CNI: &operator.CNISpec{},
			},
		}
		Expect(fillDefaults(instance)).NotTo(HaveOccurred())
		Expect(instance.Spec.CNI.Type).To(Equal(operator.PluginCalico))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})
	table.DescribeTable("should default CNI type based on KubernetesProvider for hosted providers",
		func(provider operator.Provider, plugin operator.CNIPluginType) {
			instance := &operator.Installation{
				Spec: operator.InstallationSpec{KubernetesProvider: provider},
			}
			Expect(fillDefaults(instance)).NotTo(HaveOccurred())
			Expect(instance.Spec.CNI.Type).To(Equal(plugin))
			Expect(instance.Spec.CalicoNetwork).To(BeNil())
			Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		},

		table.Entry("EKS provider defaults to AmazonVPC plugin", operator.ProviderEKS, operator.PluginAmazonVPC),
		table.Entry("GKE provider defaults to GKE plugin", operator.ProviderGKE, operator.PluginGKE),
		table.Entry("AKS provider defaults to AzureVNET plugin", operator.ProviderAKS, operator.PluginAzureVNET),
	)
	table.DescribeTable("setting CNI Provider should default CalicoNetwork to nil",
		func(plugin operator.CNIPluginType) {
			instance := &operator.Installation{
				Spec: operator.InstallationSpec{
					CNI: &operator.CNISpec{Type: plugin},
				},
			}
			Expect(fillDefaults(instance)).NotTo(HaveOccurred())
			Expect(instance.Spec.CNI.Type).To(Equal(plugin))
			Expect(instance.Spec.CalicoNetwork).To(BeNil())
			Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		},

		table.Entry("AmazonVPC plugin", operator.PluginAmazonVPC),
		table.Entry("GKE plugin", operator.PluginGKE),
		table.Entry("AzureVNET plugin", operator.PluginAzureVNET),
	)

	// Tests for Calico Networking on EKS should go in this context.
	Context("with Calico Networking on EKS", func() {
		It("should default properly", func() {
			instance := &operator.Installation{
				Spec: operator.InstallationSpec{
					KubernetesProvider: operator.ProviderEKS,
					CNI: &operator.CNISpec{
						Type: operator.PluginCalico,
					},
				},
			}
			fillDefaults(instance)
			Expect(*instance.Spec.CalicoNetwork.BGP).To(Equal(operator.BGPDisabled))
			Expect(*&instance.Spec.CalicoNetwork.IPPools[0].Encapsulation).To(Equal(operator.EncapsulationVXLAN))
			Expect(*&instance.Spec.CalicoNetwork.IPPools[0].CIDR).To(Equal("172.16.0.0/16"))
			Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		})
	})

})
