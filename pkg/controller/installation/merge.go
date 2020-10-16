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
	"reflect"

	v1 "k8s.io/api/core/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
)

type CompareResult int

const (
	Same CompareResult = iota
	AOnlySet
	BOnlySet
	Different
)

func mergeCustomResources(cfg, override *operatorv1.Installation) *operatorv1.Installation {
	inst := cfg.DeepCopy()

	switch compareFields(inst.Spec.Variant, override.Spec.Variant) {
	case BOnlySet, Different:
		inst.Spec.Variant = override.Spec.Variant
	}

	switch compareFields(inst.Spec.Registry, override.Spec.Registry) {
	case BOnlySet, Different:
		inst.Spec.Registry = override.Spec.Registry
	}

	switch compareFields(inst.Spec.ImagePath, override.Spec.ImagePath) {
	case BOnlySet, Different:
		inst.Spec.ImagePath = override.Spec.ImagePath
	}

	switch compareFields(inst.Spec.ImagePullSecrets, override.Spec.ImagePullSecrets) {
	case BOnlySet, Different:
		inst.Spec.ImagePullSecrets = make([]v1.LocalObjectReference, len(override.Spec.ImagePullSecrets))
		copy(inst.Spec.ImagePullSecrets, override.Spec.ImagePullSecrets)
	}

	switch compareFields(inst.Spec.KubernetesProvider, override.Spec.KubernetesProvider) {
	case BOnlySet, Different:
		inst.Spec.KubernetesProvider = override.Spec.KubernetesProvider
	}

	switch compareFields(inst.Spec.CNI, override.Spec.CNI) {
	case BOnlySet:
		inst.Spec.CNI = override.Spec.CNI.DeepCopy()
	case Different:
		inst.Spec.CNI = mergeCNISpecs(inst.Spec.CNI, override.Spec.CNI)
	}

	switch compareFields(inst.Spec.CalicoNetwork, override.Spec.CalicoNetwork) {
	case BOnlySet:
		inst.Spec.CalicoNetwork = override.Spec.CalicoNetwork.DeepCopy()
	case Different:
		inst.Spec.CalicoNetwork = mergeCalicoNetwork(inst.Spec.CalicoNetwork, override.Spec.CalicoNetwork)
	}

	switch compareFields(inst.Spec.ControlPlaneNodeSelector, override.Spec.ControlPlaneNodeSelector) {
	case BOnlySet, Different:
		inst.Spec.ControlPlaneNodeSelector = make(map[string]string, len(override.Spec.ControlPlaneNodeSelector))
		for key, val := range override.Spec.ControlPlaneNodeSelector {
			inst.Spec.ControlPlaneNodeSelector[key] = val
		}
	}

	switch compareFields(inst.Spec.NodeMetricsPort, override.Spec.NodeMetricsPort) {
	case BOnlySet, Different:
		inst.Spec.NodeMetricsPort = override.Spec.NodeMetricsPort
	}

	switch compareFields(inst.Spec.FlexVolumePath, override.Spec.FlexVolumePath) {
	case BOnlySet, Different:
		inst.Spec.FlexVolumePath = override.Spec.FlexVolumePath
	}

	switch compareFields(inst.Spec.NodeUpdateStrategy, override.Spec.NodeUpdateStrategy) {
	case BOnlySet, Different:
		override.Spec.NodeUpdateStrategy.DeepCopyInto(&inst.Spec.NodeUpdateStrategy)
	}

	switch compareFields(inst.Spec.ComponentResources, override.Spec.ComponentResources) {
	case BOnlySet, Different:
		inst.Spec.ComponentResources = make([]operatorv1.ComponentResource, len(override.Spec.ComponentResources))
		copy(inst.Spec.ComponentResources, override.Spec.ComponentResources)
	}

	return inst
}

func compareFields(a, b interface{}) CompareResult {
	az := reflect.DeepEqual(a, reflect.Zero(reflect.TypeOf(a)).Interface())
	bz := reflect.DeepEqual(b, reflect.Zero(reflect.TypeOf(b)).Interface())
	if az && bz {
		return Same
	}
	if reflect.DeepEqual(a, b) {
		return Same
	}
	if az {
		return BOnlySet
	}
	if bz {
		return AOnlySet
	}
	return Different
}

func mergeCNISpecs(cfg, override *operatorv1.CNISpec) *operatorv1.CNISpec {
	out := cfg.DeepCopy()

	switch compareFields(out.Type, override.Type) {
	case BOnlySet, Different:
		out.Type = override.Type
	}

	switch compareFields(out.IPAM, override.IPAM) {
	case BOnlySet, Different:
		out.IPAM = override.IPAM.DeepCopy()
	}

	return out
}

func mergeCalicoNetwork(cfg, override *operatorv1.CalicoNetworkSpec) *operatorv1.CalicoNetworkSpec {
	out := cfg.DeepCopy()

	switch compareFields(out.BGP, override.BGP) {
	case BOnlySet, Different:
		out.BGP = override.BGP
	}

	switch compareFields(out.IPPools, override.IPPools) {
	case BOnlySet, Different:
		out.IPPools = make([]operatorv1.IPPool, len(override.IPPools))
		for i := range override.IPPools {
			override.IPPools[i].DeepCopyInto(&out.IPPools[i])
		}
	}

	switch compareFields(out.MTU, override.MTU) {
	case BOnlySet, Different:
		out.MTU = override.MTU
	}

	switch compareFields(out.NodeAddressAutodetectionV4, override.NodeAddressAutodetectionV4) {
	case BOnlySet, Different:
		out.NodeAddressAutodetectionV4 = override.NodeAddressAutodetectionV4
	}

	switch compareFields(out.NodeAddressAutodetectionV6, override.NodeAddressAutodetectionV6) {
	case BOnlySet, Different:
		out.NodeAddressAutodetectionV6 = override.NodeAddressAutodetectionV6
	}

	switch compareFields(out.HostPorts, override.HostPorts) {
	case BOnlySet, Different:
		out.HostPorts = override.HostPorts
	}

	switch compareFields(out.MultiInterfaceMode, override.MultiInterfaceMode) {
	case BOnlySet, Different:
		out.MultiInterfaceMode = override.MultiInterfaceMode
	}

	switch compareFields(out.ContainerIPForwarding, override.ContainerIPForwarding) {
	case BOnlySet, Different:
		out.ContainerIPForwarding = override.ContainerIPForwarding
	}
	return out
}
