// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package utils

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	operator "github.com/tigera/operator/api/v1"

	v1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

var _ = Describe("Installation defaults recording", func() {
	It("should return nothing when defaulting added nothing", func() {
		spec := operator.InstallationSpec{Variant: operator.Calico}

		defaults, err := MergeRecordedDefaults(nil, spec, spec)
		Expect(err).NotTo(HaveOccurred())
		Expect(defaults).To(BeNil())
	})

	It("should record only the fields defaulting added", func() {
		declared := operator.InstallationSpec{Variant: operator.Calico}

		defaulted := declared
		defaulted.KubernetesProvider = operator.ProviderEKS
		defaulted.CalicoLibHostPath = "/var/lib/calico"

		defaults, err := MergeRecordedDefaults(nil, declared, defaulted)
		Expect(err).NotTo(HaveOccurred())
		Expect(defaults).To(Equal(&operator.InstallationSpec{
			KubernetesProvider: operator.ProviderEKS,
			CalicoLibHostPath:  "/var/lib/calico",
		}))
	})

	It("should not record a field the user declared", func() {
		declared := operator.InstallationSpec{
			Variant:            operator.Calico,
			KubernetesProvider: operator.ProviderGKE,
		}

		defaulted := declared
		defaulted.CalicoLibHostPath = "/var/lib/calico"

		defaults, err := MergeRecordedDefaults(nil, declared, defaulted)
		Expect(err).NotTo(HaveOccurred())
		Expect(defaults.KubernetesProvider).To(BeEmpty())
		Expect(defaults.CalicoLibHostPath).To(Equal("/var/lib/calico"))
	})

	It("should record siblings of a nested field the user declared", func() {
		mtu := int32(1440)
		declared := operator.InstallationSpec{
			CalicoNetwork: &operator.CalicoNetworkSpec{MTU: &mtu},
		}

		linuxDataplane := operator.LinuxDataplaneIptables
		defaulted := operator.InstallationSpec{
			CalicoNetwork: &operator.CalicoNetworkSpec{
				MTU:            &mtu,
				LinuxDataplane: &linuxDataplane,
			},
		}

		defaults, err := MergeRecordedDefaults(nil, declared, defaulted)
		Expect(err).NotTo(HaveOccurred())
		Expect(defaults.CalicoNetwork).NotTo(BeNil())
		Expect(defaults.CalicoNetwork.MTU).To(BeNil())
		Expect(defaults.CalicoNetwork.LinuxDataplane).To(Equal(&linuxDataplane))
	})

	It("should record a whole list when defaulting changed any element", func() {
		declared := operator.InstallationSpec{}
		defaulted := operator.InstallationSpec{
			ImagePullSecrets: []v1.LocalObjectReference{{Name: "pull-secret"}},
		}

		defaults, err := MergeRecordedDefaults(nil, declared, defaulted)
		Expect(err).NotTo(HaveOccurred())
		Expect(defaults.ImagePullSecrets).To(HaveLen(1))
		Expect(defaults.ImagePullSecrets[0].Name).To(Equal("pull-secret"))
	})

	It("should keep a recorded default when the user has not set the field", func() {
		recorded := operator.InstallationSpec{KubernetesProvider: operator.ProviderEKS}
		declared := operator.InstallationSpec{Variant: operator.Calico}

		seeded := OverrideInstallationSpec(recorded, declared)
		Expect(seeded.KubernetesProvider).To(Equal(operator.ProviderEKS))
		Expect(seeded.Variant).To(Equal(operator.Calico))
	})

	It("should drop a recorded default once the user sets the field", func() {
		recorded := operator.InstallationSpec{KubernetesProvider: operator.ProviderEKS}
		declared := operator.InstallationSpec{KubernetesProvider: operator.ProviderGKE}

		seeded := OverrideInstallationSpec(recorded, declared)
		Expect(seeded.KubernetesProvider).To(Equal(operator.ProviderGKE))

		defaults, err := MergeRecordedDefaults(nil, declared, seeded)
		Expect(err).NotTo(HaveOccurred())
		Expect(defaults).To(BeNil())
	})

	It("should layer per-pool defaults under a declared pool", func() {
		recorded := operator.InstallationSpec{
			CalicoNetwork: &operator.CalicoNetworkSpec{
				IPPools: []operator.IPPool{{
					Name:          "default-ipv4-ippool",
					CIDR:          "192.168.0.0/24",
					Encapsulation: operator.EncapsulationVXLAN,
					NodeSelector:  "all()",
					BlockSize:     ptr.To[int32](26),
				}},
			},
		}
		declared := operator.InstallationSpec{
			CalicoNetwork: &operator.CalicoNetworkSpec{
				IPPools: []operator.IPPool{{
					CIDR:          "192.168.0.0/24",
					Encapsulation: operator.EncapsulationIPIP,
				}},
			},
		}

		seeded := OverrideInstallationSpec(recorded, declared)
		Expect(LayerPoolDefaults(&seeded, &recorded)).NotTo(HaveOccurred())

		pool := seeded.CalicoNetwork.IPPools[0]
		Expect(pool.Name).To(Equal("default-ipv4-ippool"))
		Expect(pool.NodeSelector).To(Equal("all()"))
		Expect(pool.BlockSize).To(Equal(ptr.To[int32](26)))
		Expect(pool.Encapsulation).To(Equal(operator.EncapsulationIPIP))
	})

	It("should leave a declared pool alone when no default matches its CIDR", func() {
		recorded := operator.InstallationSpec{
			CalicoNetwork: &operator.CalicoNetworkSpec{
				IPPools: []operator.IPPool{{Name: "default-ipv4-ippool", CIDR: "192.168.0.0/24"}},
			},
		}
		seeded := operator.InstallationSpec{
			CalicoNetwork: &operator.CalicoNetworkSpec{
				IPPools: []operator.IPPool{{CIDR: "10.0.0.0/16"}},
			},
		}

		Expect(LayerPoolDefaults(&seeded, &recorded)).NotTo(HaveOccurred())
		Expect(seeded.CalicoNetwork.IPPools[0].Name).To(BeEmpty())
	})
})
