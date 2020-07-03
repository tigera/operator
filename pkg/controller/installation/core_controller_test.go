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
	"fmt"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	osconfigv1 "github.com/openshift/api/config/v1"
	operator "github.com/tigera/operator/pkg/apis/operator/v1"
)

var mismatchedError = fmt.Errorf("Installation spec.kubernetesProvider 'DockerEnterprise' does not match auto-detected value 'OpenShift'")

var _ = Describe("Testing core-controller installation", func() {

	table.DescribeTable("checking rendering configuration",
		func(detectedProvider, configuredProvider operator.Provider, expectedErr error) {
			configuredInstallation := &operator.Installation{}
			configuredInstallation.Spec.KubernetesProvider = configuredProvider

			err := mergeProvider(configuredInstallation, detectedProvider)
			if expectedErr == nil {
				Expect(err).To(BeNil())
				Expect(configuredInstallation.Spec.KubernetesProvider).To(Equal(detectedProvider))
			} else {
				Expect(err).To(Equal(expectedErr))
			}
		},
		table.Entry("Same detected/configured provider", operator.ProviderOpenShift, operator.ProviderOpenShift, nil),
		table.Entry("Different detected/configured provider", operator.ProviderOpenShift, operator.ProviderDockerEE, mismatchedError),
		table.Entry("Same detected/configured managed provider", operator.ProviderEKS, operator.ProviderEKS, nil),
	)

	table.DescribeTable("test cidrWithinCidr function",
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
	var defaultMTU int32 = 1440
	var twentySix int32 = 26
	var hpEnabled operator.HostPortsType = operator.HostPortsEnabled
	var hpDisabled operator.HostPortsType = operator.HostPortsDisabled
	bpfEnabled := operator.BPFEnabled

	table.DescribeTable("Installation and Openshift should be merged and defaulted by mergeAndFillDefaults",
		func(i *operator.Installation, on *osconfigv1.Network, expectSuccess bool, calicoNet *operator.CalicoNetworkSpec) {
			if expectSuccess {
				Expect(mergeAndFillDefaults(i, on, nil)).To(BeNil())
			} else {
				Expect(mergeAndFillDefaults(i, on, nil)).ToNot(BeNil())
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
			Expect(i.Spec.CalicoNetwork.HostPorts).To(Equal(calicoNet.HostPorts))
			Expect(i.Spec.CalicoNetwork.BPFDataplaneMode).To(Equal(calicoNet.BPFDataplaneMode))
		},

		table.Entry("Empty config (with OpenShift) defaults IPPool", &operator.Installation{},
			&osconfigv1.Network{
				Spec: osconfigv1.NetworkSpec{
					ClusterNetwork: []osconfigv1.ClusterNetworkEntry{
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
				MTU:       &defaultMTU,
				HostPorts: &hpEnabled,
			}),
		table.Entry("Config with BPF enabled (with OpenShift) defaults IPPool",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{
						BPFDataplaneMode: &bpfEnabled,
					},
				},
			},
			&osconfigv1.Network{
				Spec: osconfigv1.NetworkSpec{
					ClusterNetwork: []osconfigv1.ClusterNetworkEntry{
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
				MTU:              &defaultMTU,
				HostPorts:        &hpEnabled,
				BPFDataplaneMode: &bpfEnabled,
			}),
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
				MTU:       &defaultMTU,
				HostPorts: &hpEnabled,
			}),
		table.Entry("CIDR specified from OpenShift config and Calico config",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{
						IPPools: []operator.IPPool{
							operator.IPPool{
								CIDR:          "10.0.0.0/24",
								Encapsulation: "VXLAN",
								NATOutgoing:   "Disabled",
							},
						},
					},
				},
			}, &osconfigv1.Network{
				Spec: osconfigv1.NetworkSpec{
					ClusterNetwork: []osconfigv1.ClusterNetworkEntry{
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
				MTU:       &defaultMTU,
				HostPorts: &hpEnabled,
			}),
		table.Entry("Failure when IPPool is smaller than OpenShift Network",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{
						IPPools: []operator.IPPool{
							operator.IPPool{
								CIDR:          "10.0.0.0/16",
								Encapsulation: "VXLAN",
								NATOutgoing:   "Disabled",
							},
						},
					},
				},
			}, &osconfigv1.Network{
				Spec: osconfigv1.NetworkSpec{
					ClusterNetwork: []osconfigv1.ClusterNetworkEntry{
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
			}, &osconfigv1.Network{
				Spec: osconfigv1.NetworkSpec{
					ClusterNetwork: []osconfigv1.ClusterNetworkEntry{
						{CIDR: "10.0.0.0/8"},
					},
				},
			}, true,
			&operator.CalicoNetworkSpec{
				IPPools:   []operator.IPPool{},
				MTU:       &defaultMTU,
				HostPorts: &hpEnabled,
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
				MTU:       &defaultMTU,
				HostPorts: &hpEnabled,
			}),
		table.Entry("HostPorts disabled",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{
						HostPorts: &hpDisabled,
					},
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
				MTU:       &defaultMTU,
				HostPorts: &hpDisabled,
			}),
	)

	table.DescribeTable("BPF settings",
		func(mode operator.BPFDataplaneMode, exp bool) {
			nc := GenerateRenderConfig(&operator.Installation{
				Spec: operator.InstallationSpec{
					CalicoNetwork: &operator.CalicoNetworkSpec{
						BPFDataplaneMode: &mode,
					},
				},
			})

			Expect(nc.BPFEnabled).To(Equal(exp))
		},
		table.Entry("nil", nil, false),
		table.Entry("Disabled", operator.BPFDisabled, false),
		table.Entry("Enabled", operator.BPFEnabled, true),
		table.Entry("EnabledKeepKubeProxy", operator.BPFEnabledKeepKubeProxy, true),
	)
})
