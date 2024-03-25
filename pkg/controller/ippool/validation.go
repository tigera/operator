// Copyright (c) 2023-2024 Tigera, Inc. All rights reserved.

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
	"fmt"
	"net"
	"strings"

	operator "github.com/tigera/operator/api/v1"
)

// ValidatePools validates the IP pools specified in the Installation object.
func ValidatePools(instance *operator.Installation) error {
	cidrs := map[string]bool{}
	names := map[string]bool{}
	for _, pool := range instance.Spec.CalicoNetwork.IPPools {
		_, cidr, err := net.ParseCIDR(pool.CIDR)
		if err != nil {
			return fmt.Errorf("IP pool CIDR (%s) is invalid: %s", pool.CIDR, err)
		}

		// Validate that there is only a single instance of each CIDR and Name.
		if cidrs[pool.CIDR] {
			return fmt.Errorf("IP pool %v is specified more than once", pool.CIDR)
		}
		cidrs[pool.CIDR] = true
		if names[pool.Name] {
			return fmt.Errorf("IP pool %v is specified more than once", pool.Name)
		}
		names[pool.Name] = true

		// Verify NAT outgoing values.
		switch pool.NATOutgoing {
		case operator.NATOutgoingEnabled, operator.NATOutgoingDisabled:
		default:
			return fmt.Errorf("%s is invalid for natOutgoing, should be one of %s",
				pool.NATOutgoing, strings.Join(operator.NATOutgoingTypesString, ","))
		}

		// Verify the node selector.
		if pool.NodeSelector == "" {
			return fmt.Errorf("IP pool nodeSelector should not be empty")
		}
		if instance.Spec.CNI == nil {
			// We expect this to be defaulted by the core Installation controller prior to the IP pool controller
			// being invoked, but check just in case.
			return fmt.Errorf("No CNI plugin specified in Installation resource")
		}
		if instance.Spec.CNI.Type != operator.PluginCalico {
			if pool.NodeSelector != "all()" {
				return fmt.Errorf("IP pool nodeSelector (%s) should be 'all()' when using non-Calico CNI plugin", pool.NodeSelector)
			}
		}

		// Verify per-address-family settings.
		isIPv4 := !strings.Contains(pool.CIDR, ":")
		if isIPv4 {
			// This is an IPv4 pool.
			if pool.BlockSize != nil {
				if *pool.BlockSize > 32 || *pool.BlockSize < 20 {
					return fmt.Errorf("IPv4 pool block size must be greater than 19 and less than or equal to 32")
				}

				// Verify that the CIDR contains the blocksize.
				ones, _ := cidr.Mask.Size()
				if int32(ones) > *pool.BlockSize {
					return fmt.Errorf("IP pool size is too small. It must be equal to or greater than the block size.")
				}
			}
		} else {
			// This is an IPv6 pool.
			if pool.BlockSize != nil {
				if *pool.BlockSize > 128 || *pool.BlockSize < 116 {
					return fmt.Errorf("IPv6 pool block size must be greater than 115 and less than or equal to 128")
				}

				// Verify that the CIDR contains the blocksize.
				ones, _ := cidr.Mask.Size()
				if int32(ones) > *pool.BlockSize {
					return fmt.Errorf("IP pool size is too small. It must be equal to or greater than the block size.")
				}
			}
		}

		// Check that the encapsulation mode on the IP pool is compatible with the CNI plugin that is in-use.
		if instance.Spec.CNI.Type == operator.PluginCalico {
			switch instance.Spec.CNI.IPAM.Type {
			case operator.IPAMPluginCalico:
				// Verify the specified encapsulation type is valid.
				switch pool.Encapsulation {
				case operator.EncapsulationIPIP, operator.EncapsulationIPIPCrossSubnet:
					// IPIP currently requires BGP to be running in order to program routes.
					if instance.Spec.CalicoNetwork.BGP == nil || *instance.Spec.CalicoNetwork.BGP == operator.BGPDisabled {
						return fmt.Errorf("IPIP encapsulation requires that BGP is enabled")
					}
				case operator.EncapsulationVXLAN, operator.EncapsulationVXLANCrossSubnet:
				case operator.EncapsulationNone:
					// Unencapsulated currently requires BGP to be running in order to program routes.
					if instance.Spec.CalicoNetwork.BGP == nil || *instance.Spec.CalicoNetwork.BGP == operator.BGPDisabled {
						return fmt.Errorf("Unencapsulated IP pools require that BGP is enabled")
					}
				default:
					return fmt.Errorf("%s is invalid for ipPool.encapsulation, should be one of %s",
						pool.Encapsulation, strings.Join(operator.EncapsulationTypesString, ","))
				}
			case operator.IPAMPluginHostLocal:
				// The host-local IPAM plugin doesn't support VXLAN.
				switch pool.Encapsulation {
				case operator.EncapsulationVXLAN, operator.EncapsulationVXLANCrossSubnet:
					return fmt.Errorf("%s is invalid for ipPool.encapsulation with %s CNI and %s IPAM",
						pool.Encapsulation,
						instance.Spec.CNI.Type,
						instance.Spec.CNI.IPAM.Type)
				}
			}
		} else {
			// If not using Calico CNI, then the encapsulation must be None and BGP must be disabled.
			switch pool.Encapsulation {
			case operator.EncapsulationNone:
			default:
				return fmt.Errorf("%s is invalid for ipPool.encapsulation when using non-Calico CNI, should be None",
					pool.Encapsulation)
			}
			if instance.Spec.CalicoNetwork.BGP != nil && *instance.Spec.CalicoNetwork.BGP == operator.BGPEnabled {
				return fmt.Errorf("BGP is not supported when using non-Calico CNI")
			}
		}
	}
	return nil
}
