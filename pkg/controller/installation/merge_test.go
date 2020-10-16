// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	v1 "k8s.io/api/core/v1"

	opv1 "github.com/tigera/operator/api/v1"
)

func intPtr(i int32) *int32 { return &i }

var _ = Describe("Installation merge tests", func() {
	DescribeTable("merge Variant", func(main, second *opv1.ProductVariant, successful bool, expectVariant *opv1.ProductVariant) {
		m := opv1.Installation{Spec: opv1.InstallationSpec{}}
		s := opv1.Installation{Spec: opv1.InstallationSpec{}}
		if main != nil {
			m.Spec.Variant = *main
		}
		if second != nil {
			s.Spec.Variant = *second
		}
		var inst *opv1.Installation
		var err error
		inst, err = mergeCustomResources(&m, &s)
		if successful {
			Expect(err).NotTo(HaveOccurred())
			if expectVariant == nil {
				var x opv1.ProductVariant
				Expect(inst.Spec.Variant).To(Equal(x))
			} else {
				Expect(inst.Spec.Variant).To(Equal(*expectVariant))
			}
		} else {
			Expect(err).To(HaveOccurred())
		}
	},
		Entry("Both unset", nil, nil, true, nil),
		Entry("Main only set", &opv1.Calico, nil, true, &opv1.Calico),
		Entry("Second only set", nil, &opv1.Calico, true, &opv1.Calico),
		Entry("Both set equal", &opv1.Calico, &opv1.Calico, true, &opv1.Calico),
		Entry("Both set not matching", &opv1.Calico, &opv1.TigeraSecureEnterprise, false, &opv1.Calico),
	)

	DescribeTable("merge Registry", func(main, second string, successful bool, expect string) {
		m := opv1.Installation{Spec: opv1.InstallationSpec{}}
		s := opv1.Installation{Spec: opv1.InstallationSpec{}}
		if main != "" {
			m.Spec.Registry = main
		}
		if second != "" {
			s.Spec.Registry = second
		}
		var inst *opv1.Installation
		var err error
		inst, err = mergeCustomResources(&m, &s)
		if successful {
			Expect(err).NotTo(HaveOccurred())
			Expect(inst.Spec.Registry).To(Equal(expect))
		} else {
			Expect(err).To(HaveOccurred())
		}
	},
		Entry("Both unset", nil, nil, true, nil),
		Entry("Main only set", "private.registry.com", nil, true, "private.registry.com"),
		Entry("Second only set", nil, "private.registry.com", true, "private.registry.com"),
		Entry("Both set equal", "private.registry.com", "private.registry.com", true, "private.registry.com"),
		Entry("Both set not matching", "private.registry.com", "other.registry.com", false, ""),
	)

	DescribeTable("merge ImagePath", func(main, second string, successful bool, expect string) {
		m := opv1.Installation{Spec: opv1.InstallationSpec{}}
		s := opv1.Installation{Spec: opv1.InstallationSpec{}}
		if main != "" {
			m.Spec.ImagePath = main
		}
		if second != "" {
			s.Spec.ImagePath = second
		}
		var inst *opv1.Installation
		var err error
		inst, err = mergeCustomResources(&m, &s)
		if successful {
			Expect(err).NotTo(HaveOccurred())
			Expect(inst.Spec.ImagePath).To(Equal(expect))
		} else {
			Expect(err).To(HaveOccurred())
		}
	},
		Entry("Both unset", nil, nil, true, nil),
		Entry("Main only set", "pathx", nil, true, "pathx"),
		Entry("Second only set", nil, "pathx", true, "pathx"),
		Entry("Both set equal", "pathx", "pathx", true, "pathx"),
		Entry("Both set not matching", "pathx", "pathy", false, ""),
	)

	DescribeTable("merge imagePullSecrets", func(main, second []v1.LocalObjectReference, successful bool, expect []v1.LocalObjectReference) {
		m := opv1.Installation{Spec: opv1.InstallationSpec{}}
		s := opv1.Installation{Spec: opv1.InstallationSpec{}}
		if main != nil {
			m.Spec.ImagePullSecrets = main
		}
		if second != nil {
			s.Spec.ImagePullSecrets = second
		}
		inst, err := mergeCustomResources(&m, &s)
		if successful {
			Expect(err).NotTo(HaveOccurred())
			Expect(inst.Spec.ImagePullSecrets).To(ConsistOf(expect))
		} else {
			Expect(err).To(HaveOccurred())
		}
	},
		Entry("Both unset", nil, nil, true, nil),
		Entry("Main only set", []v1.LocalObjectReference{{Name: "pull-secret"}}, nil, true, []v1.LocalObjectReference{{Name: "pull-secret"}}),
		Entry("Second only set", nil, []v1.LocalObjectReference{{Name: "pull-secret"}}, true, []v1.LocalObjectReference{{Name: "pull-secret"}}),
		Entry("Both set equal", []v1.LocalObjectReference{{Name: "pull-secret"}}, []v1.LocalObjectReference{{Name: "pull-secret"}}, true, []v1.LocalObjectReference{{Name: "pull-secret"}}),
		Entry("Both set not matching", []v1.LocalObjectReference{{Name: "pull-secret"}}, []v1.LocalObjectReference{{Name: "other-pull-secret"}}, true, []v1.LocalObjectReference{{Name: "pull-secret"}, {Name: "other-pull-secret"}}),
	)

	DescribeTable("merge KubernetesProvider", func(main, second *opv1.Provider, successful bool, expect *opv1.Provider) {
		m := opv1.Installation{Spec: opv1.InstallationSpec{}}
		s := opv1.Installation{Spec: opv1.InstallationSpec{}}
		if main != nil {
			m.Spec.KubernetesProvider = *main
		}
		if second != nil {
			s.Spec.KubernetesProvider = *second
		}
		var inst *opv1.Installation
		var err error
		inst, err = mergeCustomResources(&m, &s)
		if successful {
			Expect(err).NotTo(HaveOccurred())
			if expect == nil {
				var x opv1.Provider
				Expect(inst.Spec.KubernetesProvider).To(Equal(x))
			} else {
				Expect(inst.Spec.KubernetesProvider).To(Equal(*expect))
			}
		} else {
			Expect(err).To(HaveOccurred())
		}
	},
		Entry("Both unset", nil, nil, true, nil),
		Entry("Main only set", &opv1.ProviderGKE, nil, true, &opv1.ProviderGKE),
		Entry("Second only set", nil, &opv1.ProviderAKS, true, &opv1.ProviderAKS),
		Entry("Both set equal", &opv1.ProviderOpenShift, &opv1.ProviderOpenShift, true, &opv1.ProviderOpenShift),
		Entry("Both set not matching", &opv1.ProviderEKS, &opv1.ProviderGKE, false, nil),
	)

	DescribeTable("merge CNISpec", func(main, second *opv1.CNISpec, successful bool, expect *opv1.CNISpec) {
		m := opv1.Installation{Spec: opv1.InstallationSpec{}}
		s := opv1.Installation{Spec: opv1.InstallationSpec{}}
		if main != nil {
			m.Spec.CNI = main
		}
		if second != nil {
			s.Spec.CNI = second
		}
		var inst *opv1.Installation
		var err error
		inst, err = mergeCustomResources(&m, &s)
		if successful {
			Expect(err).NotTo(HaveOccurred())
			if expect == nil {
				Expect(inst.Spec.CNI).To(BeNil())
			} else {
				Expect(*inst.Spec.CNI).To(Equal(*expect))
			}
		} else {
			Expect(err).To(HaveOccurred())
		}
	},
		Entry("Both unset", nil, nil, true, nil),
		Entry("Main only set", &opv1.CNISpec{Type: opv1.PluginCalico}, nil, true, &opv1.CNISpec{Type: opv1.PluginCalico}),
		Entry("Second only set", nil, &opv1.CNISpec{Type: opv1.PluginGKE}, true, &opv1.CNISpec{Type: opv1.PluginGKE}),
		Entry("Both set equal",
			&opv1.CNISpec{Type: opv1.PluginAmazonVPC},
			&opv1.CNISpec{Type: opv1.PluginAmazonVPC}, true,
			&opv1.CNISpec{Type: opv1.PluginAmazonVPC}),
		Entry("Both set not matching",
			&opv1.CNISpec{Type: opv1.PluginAmazonVPC},
			&opv1.CNISpec{Type: opv1.PluginAzureVNET}, false, nil),
		Entry("Both set differently but mergable",
			&opv1.CNISpec{Type: opv1.PluginAmazonVPC},
			&opv1.CNISpec{IPAM: &opv1.IPAMSpec{Type: opv1.IPAMPluginAmazonVPC}}, true,
			&opv1.CNISpec{Type: opv1.PluginAmazonVPC, IPAM: &opv1.IPAMSpec{Type: opv1.IPAMPluginAmazonVPC}}),
	)

	Context("test CalicoNetwork merge", func() {
		_BGPE := opv1.BGPEnabled
		_BGPD := opv1.BGPDisabled
		DescribeTable("merge BGP", func(main, second *opv1.BGPOption, successful bool, expect *opv1.BGPOption) {
			m := opv1.Installation{Spec: opv1.InstallationSpec{}}
			s := opv1.Installation{Spec: opv1.InstallationSpec{}}
			if main != nil {
				m.Spec.CalicoNetwork = &opv1.CalicoNetworkSpec{BGP: main}
			}
			if second != nil {
				s.Spec.CalicoNetwork = &opv1.CalicoNetworkSpec{BGP: second}
			}
			var inst *opv1.Installation
			var err error
			inst, err = mergeCustomResources(&m, &s)
			if successful {
				Expect(err).NotTo(HaveOccurred())
				if expect == nil {
					Expect(inst.Spec.CalicoNetwork).To(BeNil())
				} else {
					Expect(*inst.Spec.CalicoNetwork.BGP).To(Equal(*expect))
				}
			} else {
				Expect(err).To(HaveOccurred())
			}
		},
			Entry("Both unset", nil, nil, true, nil),
			Entry("Main only set", &_BGPE, nil, true, &_BGPE),
			Entry("Second only set", nil, &_BGPD, true, &_BGPD),
			Entry("Both set equal", &_BGPE, &_BGPE, true, &_BGPE),
			Entry("Both set not matching", &_BGPE, &_BGPD, false, nil),
		)

		DescribeTable("merge IPPools", func(main, second []opv1.IPPool, successful bool, expect []opv1.IPPool) {
			m := opv1.Installation{Spec: opv1.InstallationSpec{}}
			s := opv1.Installation{Spec: opv1.InstallationSpec{}}
			if main != nil {
				m.Spec.CalicoNetwork = &opv1.CalicoNetworkSpec{IPPools: main}
			}
			if second != nil {
				s.Spec.CalicoNetwork = &opv1.CalicoNetworkSpec{IPPools: second}
			}
			var inst *opv1.Installation
			var err error
			inst, err = mergeCustomResources(&m, &s)
			if successful {
				Expect(err).NotTo(HaveOccurred())
				if expect == nil {
					Expect(inst.Spec.CalicoNetwork).To(BeNil())
				} else {
					Expect(inst.Spec.CalicoNetwork.IPPools).To(Equal(expect))
				}
			} else {
				Expect(err).To(HaveOccurred())
			}
		},
			Entry("Both unset", nil, nil, true, nil),
			Entry("Main only set", []opv1.IPPool{{CIDR: "192.168.0.0/16"}}, nil, true, []opv1.IPPool{{CIDR: "192.168.0.0/16"}}),
			Entry("Second only set", nil, []opv1.IPPool{{CIDR: "10.0.0.0/24"}}, true, []opv1.IPPool{{CIDR: "10.0.0.0/24"}}),
			Entry("Both set equal", []opv1.IPPool{{CIDR: "10.0.0.0/24"}}, []opv1.IPPool{{CIDR: "10.0.0.0/24"}}, true, []opv1.IPPool{{CIDR: "10.0.0.0/24"}}),
			Entry("Both set not matching", []opv1.IPPool{{CIDR: "10.0.0.0/24"}}, []opv1.IPPool{{CIDR: "172.16.0.0/8"}}, false, nil),
		)

		DescribeTable("merge MTU", func(main, second *int32, successful bool, expect *int32) {
			m := opv1.Installation{Spec: opv1.InstallationSpec{}}
			s := opv1.Installation{Spec: opv1.InstallationSpec{}}
			if main != nil {
				m.Spec.CalicoNetwork = &opv1.CalicoNetworkSpec{MTU: main}
			}
			if second != nil {
				s.Spec.CalicoNetwork = &opv1.CalicoNetworkSpec{MTU: second}
			}
			var inst *opv1.Installation
			var err error
			inst, err = mergeCustomResources(&m, &s)
			if successful {
				Expect(err).NotTo(HaveOccurred())
				if expect == nil {
					Expect(inst.Spec.CalicoNetwork).To(BeNil())
				} else {
					Expect(*inst.Spec.CalicoNetwork.MTU).To(Equal(*expect))
				}
			} else {
				Expect(err).To(HaveOccurred())
			}
		},
			Entry("Both unset", nil, nil, true, nil),
			Entry("Main only set", intPtr(1500), nil, true, intPtr(1500)),
			Entry("Second only set", nil, intPtr(8980), true, intPtr(8980)),
			Entry("Both set equal", intPtr(1440), intPtr(1440), true, intPtr(1440)),
			Entry("Both set not matching", intPtr(1460), intPtr(8981), false, nil),
		)

		//TODO: Have some test that have different fields set and they merge.
	})

	It("should not allow blocksize to exceed the pool size", func() {
		// Try with an invalid block size.
		//var twentySix int32 = 26
		//var enabled operator.BGPOption = operator.BGPEnabled
		//instance.Spec.CalicoNetwork.BGP = &enabled
		//instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
		//	{
		//		CIDR:          "192.168.0.0/27",
		//		BlockSize:     &twentySix,
		//		Encapsulation: operator.EncapsulationNone,
		//		NATOutgoing:   operator.NATOutgoingEnabled,
		//		NodeSelector:  "all()",
		//	},
		//}

		//// Try with a valid block size
		//instance.Spec.CalicoNetwork.IPPools[0].CIDR = "192.168.0.0/26"
		//err = validateCustomResource(instance)
		//Expect(err).NotTo(HaveOccurred())
	})

	//Describe("validate Calico CNI plugin Type", func() {
	//	BeforeEach(func() {
	//		instance = &operator.Installation{
	//			Variant: operator.Calico,
	//			Spec: operator.InstallationSpec{
	//				CalicoNetwork:  &operator.CalicoNetworkSpec{},
	//				FlexVolumePath: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
	//				NodeUpdateStrategy: appsv1.DaemonSetUpdateStrategy{
	//					Type: appsv1.RollingUpdateDaemonSetStrategyType,
	//				},
	//				CNI: &operator.CNISpec{
	//					Type: operator.PluginCalico,
	//					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
	//				},
	//			},
	//		}
	//	})
	//	AfterEach(func() {
	//		err := validateCustomResource(instance)
	//		Expect(err).NotTo(HaveOccurred())
	//	})
	//	DescribeTable("test invalid IPAM",
	//		func(ipam operator.IPAMPluginType) {
	//			instance.Spec.CNI.Type = operator.PluginCalico
	//			instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
	//			err := validateCustomResource(instance)
	//			Expect(err).To(HaveOccurred())
	//			Expect(err.Error()).To(ContainSubstring("valid IPAM values Calico,HostLocal"))
	//		},

	//		Entry("AmazonVPC", operator.IPAMPluginAmazonVPC),
	//		Entry("AzureVNET", operator.IPAMPluginAzureVNET),
	//	)
	//	DescribeTable("test valid IPAM",
	//		func(ipam operator.IPAMPluginType) {
	//			instance.Spec.CNI.Type = operator.PluginCalico
	//			instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
	//			err := validateCustomResource(instance)
	//			Expect(err).NotTo(HaveOccurred())
	//		},

	//		Entry("Calico", operator.IPAMPluginCalico),
	//		Entry("HostLocal", operator.IPAMPluginHostLocal),
	//	)
	//})
})
