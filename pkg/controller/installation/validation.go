// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

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
	"net"
	"strings"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
)

// validateCustomResource validates that the given custom resource is correct. This
// should be called after populating defaults and before rendering objects.
func validateCustomResource(instance *operatorv1.Installation) error {
	if instance.Spec.CalicoNetwork != nil {
		nPools := len(instance.Spec.CalicoNetwork.IPPools)
		if nPools > 2 {
			return fmt.Errorf("Only one IPPool per version is allowed.")
		}

		v4pool := render.GetIPv4Pool(instance.Spec.CalicoNetwork)
		v6pool := render.GetIPv6Pool(instance.Spec.CalicoNetwork)

		if nPools == 2 && (v4pool == nil || v6pool == nil) {
			return fmt.Errorf("Only one IPPool per version is allowed.")
		}

		if v4pool != nil {
			_, _, err := net.ParseCIDR(v4pool.CIDR)
			if err != nil {
				return fmt.Errorf("ipPool.CIDR(%s) is invalid: %s", v4pool.CIDR, err)
			}

			valid := false
			for _, t := range operatorv1.EncapsulationTypes {
				if v4pool.Encapsulation == t {
					valid = true
				}
			}
			if !valid {
				return fmt.Errorf("%s is invalid for ipPool.encapsulation, should be one of %s",
					v4pool.Encapsulation, strings.Join(operatorv1.EncapsulationTypesString, ","))
			}

			valid = false
			for _, t := range operatorv1.NATOutgoingTypes {
				if v4pool.NATOutgoing == t {
					valid = true
				}
			}
			if !valid {
				return fmt.Errorf("%s is invalid for ipPool.natOutgoing, should be one of %s",
					v4pool.NATOutgoing, strings.Join(operatorv1.NATOutgoingTypesString, ","))
			}

			if v4pool.NodeSelector == "" {
				return fmt.Errorf("ipPool.nodeSelector should not be empty")
			}

			if pool.BlockSize != nil && *pool.BlockSize > 32 || *pool.BlockSize < 20 {
				return fmt.Errorf("ipPool.blockSize must be greater than 19 and less than or equal to 32")
			}
		}

		if v6pool != nil {
			_, _, err := net.ParseCIDR(v6pool.CIDR)
			if err != nil {
				return fmt.Errorf("ipPool.CIDR(%s) is invalid: %s", v6pool.CIDR, err)
			}

			// Encapsulation is not supported for IPv6 pools.
			if v6pool.Encapsulation != operatorv1.EncapsulationNone {
				return fmt.Errorf("Encapsulation is not supported in IPv6 pools, but it is set for %s", v6pool.CIDR)
			}

			valid := false
			for _, t := range operatorv1.NATOutgoingTypes {
				if v6pool.NATOutgoing == t {
					valid = true
				}
			}
			if !valid {
				return fmt.Errorf("%s is invalid for v6 ipPool.natOutgoing, should be one of %s",
					v6pool.NATOutgoing, strings.Join(operatorv1.NATOutgoingTypesString, ","))
			}

			if pool.NodeSelector == "" {
				return fmt.Errorf("ipPool.nodeSelector should not be empty")
			}

			if pool.BlockSize != nil && *pool.BlockSize > 128 || *pool.BlockSize < 116 {
				return fmt.Errorf("ipPool.blockSize must be greater than 115 and less than or equal to 128")
			}
		}

		if instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4 != nil {
			err := validateNodeAddressDetection(instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4)
			if err != nil {
				return err
			}
		}

		if instance.Spec.CalicoNetwork.NodeAddressAutodetectionV6 != nil {
			err := validateNodeAddressDetection(instance.Spec.CalicoNetwork.NodeAddressAutodetectionV6)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// validateNodeAddressDetection checks that at most one form of IP auto-detection is configured per-family.
func validateNodeAddressDetection(ad *operatorv1.NodeAddressAutodetection) error {
	numEnabled := 0
	if len(ad.Interface) != 0 {
		numEnabled++
	}
	if len(ad.SkipInterface) != 0 {
		numEnabled++
	}
	if len(ad.CanReach) != 0 {
		numEnabled++
	}
	if ad.FirstFound != nil && *ad.FirstFound {
		numEnabled++
	}

	if numEnabled > 1 {
		return fmt.Errorf("no more than one node address autodetection method can be specified per-family")
	}
	return nil
}
