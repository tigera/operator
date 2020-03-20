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
	. "github.com/onsi/gomega"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
)

var _ = Describe("Installation validation tests", func() {
	var instance *operator.Installation

	BeforeEach(func() {
		instance = &operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork:  &operator.CalicoNetworkSpec{},
				FlexVolumePath: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
			},
		}
	})

	It("should not allow blocksize to exceed the pool size", func() {
		// Try with an invalid block size.
		var twentySix int32 = 26
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			{
				CIDR:          "192.168.0.0/27",
				BlockSize:     &twentySix,
				Encapsulation: operator.EncapsulationNone,
				NATOutgoing:   operator.NATOutgoingEnabled,
				NodeSelector:  "all()",
			},
		}
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())

		// Try with a valid block size
		instance.Spec.CalicoNetwork.IPPools[0].CIDR = "192.168.0.0/26"
		err = validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not allow out-of-bounds block sizes", func() {
		// Try with an invalid block size.
		var blockSizeTooBig int32 = 33
		var blockSizeTooSmall int32 = 19
		var blockSizeJustRight int32 = 32

		// Start with a valid block size - /32 - just on the border.
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			{
				CIDR:          "192.0.0.0/8",
				BlockSize:     &blockSizeJustRight,
				Encapsulation: operator.EncapsulationNone,
				NATOutgoing:   operator.NATOutgoingEnabled,
				NodeSelector:  "all()",
			},
		}
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())

		// Try with out-of-bounds sizes now.
		instance.Spec.CalicoNetwork.IPPools[0].BlockSize = &blockSizeTooBig
		err = validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
		instance.Spec.CalicoNetwork.IPPools[0].BlockSize = &blockSizeTooSmall
		err = validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	It("should not allow a relative path in FlexVolumePath", func() {
		instance.Spec.FlexVolumePath = "foo/bar/baz"
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	It("should validate HostPort", func() {
		instance.Spec.CalicoNetwork.HostPort = nil
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())

		hp := operator.HostPortEnabled
		instance.Spec.CalicoNetwork.HostPort = &hp
		err = validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())

		hp = operator.HostPortDisabled
		instance.Spec.CalicoNetwork.HostPort = &hp
		err = validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())

		hp = "NotValid"
		instance.Spec.CalicoNetwork.HostPort = &hp
		err = validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})
})
