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
	"net"
	"strings"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
)

// validateCustomResource validates that the given custom resource is correct. This
// should be called after populating defaults and before rendering objects.
func validateCustomResource(instance *operatorv1.Installation) error {
	if instance.Spec.CalicoNetwork != nil {
		if len(instance.Spec.CalicoNetwork.IPPools) > 1 {
			return fmt.Errorf("With CalicoNetwork only one IPPool is allowed")
		}
		if len(instance.Spec.CalicoNetwork.IPPools) == 1 {
			pool := instance.Spec.CalicoNetwork.IPPools[0]
			_, _, err := net.ParseCIDR(pool.CIDR)
			if err != nil {
				return fmt.Errorf("ipPool.CIDR(%s) is invalid: %s", pool.CIDR, err)
			}

			valid := false
			for _, t := range operatorv1.EncapsulationTypes {
				if pool.Encapsulation == t {
					valid = true
				}
			}
			if !valid {
				return fmt.Errorf("%s is invalid for ipPool.encapsulation, should be one of %s", pool.Encapsulation,
					strings.Join(operatorv1.EncapsulationTypesString, ","))
			}

			valid = false
			for _, t := range operatorv1.NATOutgoingTypes {
				if pool.NATOutgoing == t {
					valid = true
				}
			}
			if !valid {
				return fmt.Errorf("%s is invalid for ipPool.natOutgoing, should be one of %s", pool.NATOutgoing,
					strings.Join(operatorv1.NATOutgoingTypesString, ","))
			}

			if pool.NodeSelector == "" {
				return fmt.Errorf("ipPool.nodeSelector, should not be empty")
			}
		}
	}
	return nil
}
