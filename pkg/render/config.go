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

package render

import (
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
)

const (
	CNICalico = "calico"
	CNINone   = "none"
)

type NetworkConfig struct {
	CNIPlugin            operatorv1.CNIPluginType
	NodenameFileOptional bool
	IPPools              []operatorv1.IPPool
	MTU                  int32
	HostPorts            bool
}

// GenerateRenderConfig converts installation into render config.
func GenerateRenderConfig(install *operatorv1.Installation) NetworkConfig {
	networkConfig := NetworkConfig{
		CNIPlugin: install.Spec.CNI.Type,
	}

	// Set other provider-specific settings.
	switch install.Spec.KubernetesProvider {
	case operatorv1.ProviderDockerEE:
		networkConfig.NodenameFileOptional = true
	}

	// If CalicoNetwork is specified, then use Calico networking.
	if install.Spec.CalicoNetwork == nil {
		return networkConfig
	}

	networkConfig.MTU = 0
	if install.Spec.CalicoNetwork.MTU != nil {
		networkConfig.MTU = *install.Spec.CalicoNetwork.MTU
	}

	networkConfig.HostPorts = false
	if install.Spec.CalicoNetwork.HostPorts != nil && *install.Spec.CalicoNetwork.HostPorts == operatorv1.HostPortsEnabled {
		networkConfig.HostPorts = true
	}

	networkConfig.IPPools = install.Spec.CalicoNetwork.IPPools

	return networkConfig
}
