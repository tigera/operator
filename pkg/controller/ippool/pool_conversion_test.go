// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	operator "github.com/tigera/operator/api/v1"
)

var (
	true_  = true
	false_ = false
)

var _ = table.DescribeTable("IPPool operator.tigera.io <-> crd.projectcalico.org/v1 conversion tests",
	func(input operator.IPPool) {
		// Convert to crd.projectcalico.org/v1
		crdPool, err := ToProjectCalicoV1(input)
		Expect(err).NotTo(HaveOccurred())

		// Convert back to operator.tigera.io, expect it to be equal to the input.
		operPool := operator.IPPool{}
		FromProjectCalicoV1(&operPool, *crdPool)
		Expect(operPool).To(Equal(input))
	},

	table.Entry("Fully-specified pool", operator.IPPool{
		CIDR:                  "172.16.0.0/16",
		Encapsulation:         operator.EncapsulationVXLANCrossSubnet,
		NATOutgoing:           operator.NATOutgoingEnabled,
		NodeSelector:          "foo == 'bar'",
		BlockSize:             &twentySix,
		DisableBGPExport:      &true_,
		DisableNewAllocations: &true_,
		AllowedUses:           []operator.IPPoolAllowedUse{operator.IPPoolAllowedUseWorkload},
	}),

	// Test fields that implicitly default to false when they are explicitly set to false.
	table.Entry("Explicitly false fields", operator.IPPool{
		CIDR:                  "172.16.0.0/16",
		Encapsulation:         operator.EncapsulationIPIPCrossSubnet,
		NATOutgoing:           operator.NATOutgoingDisabled,
		NodeSelector:          "",
		BlockSize:             &twentySix,
		DisableBGPExport:      &false_,
		DisableNewAllocations: &false_,
		AllowedUses:           nil,
	}),
)
