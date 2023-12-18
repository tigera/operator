// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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

package ippool

import (
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	configv1 "github.com/openshift/api/config/v1"
	operator "github.com/tigera/operator/api/v1"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/render"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
)

var _ = Describe("IPPool controller", func() {
	table.DescribeTable("cidrWithinCidr",
		func(CIDR, pool string, expectedResult bool) {
			if expectedResult {
				Expect(cidrWithinCidr(CIDR, pool)).To(BeTrue(), "Expected pool %s to be within CIDR %s", pool, CIDR)
			} else {
				Expect(cidrWithinCidr(CIDR, pool)).To(BeFalse(), "Expected pool %s to not be within CIDR %s", pool, CIDR)
			}
		},

		table.Entry("Default as CIDR and pool", "192.168.0.0/16", "192.168.0.0/16", true),
		table.Entry("Pool larger than CIDR should fail", "192.168.0.0/16", "192.168.0.0/15", false),
		table.Entry("Pool larger than CIDR should fail", "192.168.2.0/24", "192.168.0.0/16", false),
		table.Entry("Non overlapping CIDR and pool should fail", "192.168.0.0/16", "172.168.0.0/16", false),
		table.Entry("CIDR with smaller pool", "192.168.0.0/16", "192.168.2.0/24", true),
		table.Entry("IPv6 matching CIDR and pool", "fd00:1234::/32", "fd00:1234::/32", true),
		table.Entry("IPv6 Pool larger than CIDR should fail", "fd00:1234::/32", "fd00:1234::/31", false),
		table.Entry("IPv6 Pool larger than CIDR should fail", "fd00:1234:5600::/40", "fd00:1234::/32", false),
		table.Entry("IPv6 Non overlapping CIDR and pool should fail", "fd00:1234::/32", "fd00:5678::/32", false),
		table.Entry("IPv6 CIDR with smaller pool", "fd00:1234::/32", "fd00:1234:5600::/40", true),
	)

	var twentySix int32 = 26
	table.DescribeTable("updateInstallationForOpenshiftNetwork",
		func(i *operator.Installation, on *configv1.Network, expectSuccess bool, calicoNet *operator.CalicoNetworkSpec) {
			if expectSuccess {
				Expect(updateInstallationForOpenshiftNetwork(i, on)).To(BeNil())
			} else {
				Expect(updateInstallationForOpenshiftNetwork(i, on)).ToNot(BeNil())
				return
			}

			if calicoNet == nil {
				Expect(i.Spec.CalicoNetwork).To(BeNil())
				return
			}
			if calicoNet.IPPools == nil {
				Expect(i.Spec.CalicoNetwork).To(BeNil())
				return
			}
			if len(calicoNet.IPPools) == 0 {
				Expect(i.Spec.CalicoNetwork.IPPools).To(HaveLen(0))
				return
			}
			Expect(i.Spec.CalicoNetwork.IPPools).To(HaveLen(1))
			pool := i.Spec.CalicoNetwork.IPPools[0]
			pExpect := calicoNet.IPPools[0]
			Expect(pool).To(Equal(pExpect))
		},

		table.Entry("Empty config (with OpenShift) defaults IPPool", &operator.Installation{},
			&configv1.Network{
				Spec: configv1.NetworkSpec{
					ClusterNetwork: []configv1.ClusterNetworkEntry{
						{CIDR: "192.168.0.0/16"},
					},
				},
			}, true,
			&operator.CalicoNetworkSpec{
				IPPools: []operator.IPPool{
					{
						CIDR:          "192.168.0.0/16",
						Encapsulation: "IPIP",
						NATOutgoing:   "Enabled",
						NodeSelector:  "all()",
						BlockSize:     &twentySix,
					},
				},
			}),

		table.Entry("Openshift only CIDR",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{},
				},
			}, &configv1.Network{
				Spec: configv1.NetworkSpec{
					ClusterNetwork: []configv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/8"},
					},
				},
			}, true,
			&operator.CalicoNetworkSpec{
				IPPools: []operator.IPPool{
					{
						CIDR:          "10.0.0.0/8",
						Encapsulation: "IPIP",
						NATOutgoing:   "Enabled",
						NodeSelector:  "all()",
						BlockSize:     &twentySix,
					},
				},
			}),

		table.Entry("CIDR specified from OpenShift config and Calico config",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{
						IPPools: []operator.IPPool{
							{
								CIDR:          "10.0.0.0/24",
								Encapsulation: "VXLAN",
								NATOutgoing:   "Disabled",
							},
						},
					},
				},
			}, &configv1.Network{
				Spec: configv1.NetworkSpec{
					ClusterNetwork: []configv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/8"},
					},
				},
			}, true,
			&operator.CalicoNetworkSpec{
				IPPools: []operator.IPPool{
					{
						CIDR:          "10.0.0.0/24",
						Encapsulation: "VXLAN",
						NATOutgoing:   "Disabled",
						NodeSelector:  "all()",
						BlockSize:     &twentySix,
					},
				},
			}),

		table.Entry("Failure when IPPool is smaller than OpenShift Network",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{
						IPPools: []operator.IPPool{
							{
								CIDR:          "10.0.0.0/16",
								Encapsulation: "VXLAN",
								NATOutgoing:   "Disabled",
							},
						},
					},
				},
			}, &configv1.Network{
				Spec: configv1.NetworkSpec{
					ClusterNetwork: []configv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/24"},
					},
				},
			}, false, nil),

		table.Entry("Empty IPPool list results in no IPPool with OpenShift",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{
						IPPools: []operator.IPPool{},
					},
				},
			}, &configv1.Network{
				Spec: configv1.NetworkSpec{
					ClusterNetwork: []configv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/8"},
					},
				},
			}, true,
			&operator.CalicoNetworkSpec{
				IPPools: []operator.IPPool{},
			}),

		table.Entry("Normal defaults with no IPPools",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{},
				},
			}, nil, true,
			&operator.CalicoNetworkSpec{
				IPPools: []operator.IPPool{
					{
						CIDR:          "192.168.0.0/16",
						Encapsulation: "IPIP",
						NATOutgoing:   "Enabled",
						NodeSelector:  "all()",
						BlockSize:     &twentySix,
					},
				},
			}),
	)

	table.DescribeTable("All pools should have all fields set from mergeAndFillDefaults function",
		func(i *operator.Installation, on *configv1.Network, kadmc *v1.ConfigMap, awsN *appsv1.DaemonSet) {
			Expect(mergeAndFillDefaults(i, nil, nil)).To(BeNil())

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
			Expect(validate(i, currentPools)).NotTo(HaveOccurred())
		},

		table.Entry("Empty config defaults IPPool", &operator.Installation{}, nil, nil, nil),
		table.Entry("Openshift only CIDR",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{},
				},
			}, &configv1.Network{
				Spec: configv1.NetworkSpec{
					ClusterNetwork: []configv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/8"},
					},
				},
			},
			nil, nil,
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
			}, &configv1.Network{
				Spec: configv1.NetworkSpec{
					ClusterNetwork: []configv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/8"},
					},
				},
			},
			nil, nil,
		),
		table.Entry("kubeadm only CIDR",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{},
				},
			},
			nil,
			&v1.ConfigMap{Data: map[string]string{"ClusterConfiguration": "podSubnet: 10.0.0.0/8"}},
			nil,
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
			nil,
		),
		table.Entry("CNI Type set from AWS Node daemonset and Calico config",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CNI: &operator.CNISpec{
						Type: operator.PluginAmazonVPC,
					},
				},
			},
			nil, nil,
			&appsv1.DaemonSet{},
		),
	)
})

var _ = Describe("Test defaulting of Installation IP pools", func() {
	It("should properly fill defaults for an IPv6-only instance", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools: []operator.IPPool{{CIDR: "fd00::0/64"}},
				},
			},
		}

		err := fillDefaults(instance, nil)
		Expect(err).NotTo(HaveOccurred())

		v4pool := render.GetIPv4Pool(instance.Spec.CalicoNetwork.IPPools)
		Expect(v4pool).To(BeNil())

		v6pool := render.GetIPv6Pool(instance.Spec.CalicoNetwork.IPPools)
		Expect(v6pool).NotTo(BeNil())
		Expect(v6pool.CIDR).To(Equal("fd00::0/64"))
		Expect(v6pool.BlockSize).NotTo(BeNil())
		Expect(*v6pool.BlockSize).To(Equal(int32(122)))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

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
			err := fillDefaults(instance, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(instance.Spec.CalicoNetwork.IPPools[0].Encapsulation).To(Equal(operator.EncapsulationVXLAN))
			Expect(instance.Spec.CalicoNetwork.IPPools[0].CIDR).To(Equal("172.16.0.0/16"))
			Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		})
	})
})

var _ = Describe("Test validation of Installation IP pools", func() {
	var instance *operator.Installation
	var currentPools *crdv1.IPPoolList

	BeforeEach(func() {
		currentPools = &crdv1.IPPoolList{}
		instance = &operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork: &operator.CalicoNetworkSpec{},
				Variant:       operator.Calico,
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
				},
			},
		}
	})

	It("should not allow blocksize to exceed the pool size", func() {
		// Try with an invalid block size.
		var twentySix int32 = 26
		var enabled operator.BGPOption = operator.BGPEnabled
		instance.Spec.CalicoNetwork.BGP = &enabled
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			{
				CIDR:          "192.168.0.0/27",
				BlockSize:     &twentySix,
				Encapsulation: operator.EncapsulationNone,
				NATOutgoing:   operator.NATOutgoingEnabled,
				NodeSelector:  "all()",
			},
		}
		err := validate(instance, currentPools)
		Expect(err).To(HaveOccurred())

		// Try with a valid block size
		instance.Spec.CalicoNetwork.IPPools[0].CIDR = "192.168.0.0/26"
		err = validate(instance, currentPools)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not allow out-of-bounds block sizes", func() {
		// Try with an invalid block size.
		var blockSizeTooBig int32 = 33
		var blockSizeTooSmall int32 = 19
		var blockSizeJustRight int32 = 32

		// Start with a valid block size - /32 - just on the border.
		var enabled operator.BGPOption = operator.BGPEnabled
		instance.Spec.CalicoNetwork.BGP = &enabled
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			{
				CIDR:          "192.0.0.0/8",
				BlockSize:     &blockSizeJustRight,
				Encapsulation: operator.EncapsulationNone,
				NATOutgoing:   operator.NATOutgoingEnabled,
				NodeSelector:  "all()",
			},
		}
		err := validate(instance, currentPools)
		Expect(err).NotTo(HaveOccurred())

		// Try with out-of-bounds sizes now.
		instance.Spec.CalicoNetwork.IPPools[0].BlockSize = &blockSizeTooBig
		err = validate(instance, currentPools)
		Expect(err).To(HaveOccurred())
		instance.Spec.CalicoNetwork.IPPools[0].BlockSize = &blockSizeTooSmall
		err = validate(instance, currentPools)
		Expect(err).To(HaveOccurred())
	})
})
