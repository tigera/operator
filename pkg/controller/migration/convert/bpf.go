// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package convert

import (
	"fmt"

	operatorv1 "github.com/tigera/operator/api/v1"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"k8s.io/apimachinery/pkg/types"
)

// handleBPF is a migration handler which ensures BPF configuration is carried forward.
func handleBPF(c *components, install *operatorv1.Installation) error {
	felixConfiguration := &crdv1.FelixConfiguration{}
	err := c.client.Get(ctx, types.NamespacedName{Name: "default"}, felixConfiguration)
	if err != nil {
		return fmt.Errorf("error reading felixconfiguration %w", err)
	}
	if felixConfiguration.Spec.BPFEnabled != nil && *felixConfiguration.Spec.BPFEnabled {
		if install.Spec.CalicoNetwork == nil {
			install.Spec.CalicoNetwork = &operatorv1.CalicoNetworkSpec{}
		}

		bpf := operatorv1.LinuxDataplaneBPF
		install.Spec.CalicoNetwork.LinuxDataplane = &bpf
		install.Spec.CalicoNetwork.HostPorts = nil
	}
	return nil
}
