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
	"fmt"
	"reflect"

	"k8s.io/api/core/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
)

type CompareResult int

const (
	Same CompareResult = iota
	AOnlySet
	BOnlySet
	Different
)

func mergeCustomResources(main, secondary *operatorv1.Installation) (*operatorv1.Installation, error) {
	inst := main.DeepCopy()

	switch compareFields(inst.Spec.Variant, secondary.Spec.Variant) {
	case BOnlySet:
		inst.Spec.Variant = secondary.Spec.Variant
	case Different:
		return nil, fmt.Errorf("Installation variant does not match")
	}

	switch compareFields(main.Spec.Registry, secondary.Spec.Registry) {
	case BOnlySet:
		inst.Spec.Registry = secondary.Spec.Registry
	case Different:
		return nil, fmt.Errorf("Installation registry does not match")
	}

	switch compareFields(inst.Spec.ImagePath, secondary.Spec.ImagePath) {
	case BOnlySet:
		inst.Spec.ImagePath = secondary.Spec.ImagePath
	case Different:
		return nil, fmt.Errorf("Installation imagePath does not match")
	}

	switch compareFields(inst.Spec.ImagePullSecrets, secondary.Spec.ImagePullSecrets) {
	case BOnlySet:
		inst.Spec.ImagePullSecrets = secondary.Spec.ImagePullSecrets
	case Different:
		inst.Spec.ImagePullSecrets = mergeImagePullSecrets(inst.Spec.ImagePullSecrets, secondary.Spec.ImagePullSecrets)
	}

	switch compareFields(inst.Spec.KubernetesProvider, secondary.Spec.KubernetesProvider) {
	case BOnlySet:
		inst.Spec.KubernetesProvider = secondary.Spec.KubernetesProvider
	case Different:
		return nil, fmt.Errorf("Installation KubernetesProvider does not match")
	}

	switch compareFields(inst.Spec.CNI, secondary.Spec.CNI) {
	case BOnlySet:
		inst.Spec.CNI = secondary.Spec.CNI
	case Different:
		var err error
		inst.Spec.CNI, err = mergeCNISpecs(inst.Spec.CNI, secondary.Spec.CNI)
		if err != nil {
			return nil, err
		}
	}

	switch compareFields(inst.Spec.CalicoNetwork, secondary.Spec.CalicoNetwork) {
	case BOnlySet:
		inst.Spec.CalicoNetwork = secondary.Spec.CalicoNetwork
	case Different:
		var err error
		inst.Spec.CalicoNetwork, err = mergeCalicoNetwork(inst.Spec.CalicoNetwork, secondary.Spec.CalicoNetwork)
		if err != nil {
			return nil, err
		}
	}
	//CalicoNetwork *CalicoNetworkSpec `json:"calicoNetwork,omitempty"`
	//ControlPlaneNodeSelector map[string]string `json:"controlPlaneNodeSelector,omitempty"`
	//NodeMetricsPort *int32 `json:"nodeMetricsPort,omitempty"`
	//FlexVolumePath string `json:"flexVolumePath,omitempty"`
	//NodeUpdateStrategy appsv1.DaemonSetUpdateStrategy `json:"nodeUpdateStrategy,omitempty"`
	//ComponentResources []ComponentResource `json:"componentResources,omitempty"`

	return inst, nil
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

func mergeImagePullSecrets(a, b []v1.LocalObjectReference) []v1.LocalObjectReference {
	out := []v1.LocalObjectReference{}

	for _, x := range append(a, b...) {
		added := false
		for _, y := range out {
			if y.Name == x.Name {
				added = true
				break
			}
		}
		if !added {
			out = append(out, x)
		}
	}
	return out
}

func mergeCNISpecs(a, b *operatorv1.CNISpec) (*operatorv1.CNISpec, error) {
	out := a.DeepCopy()

	switch compareFields(out.Type, b.Type) {
	case BOnlySet:
		out.Type = b.Type
	case Different:
		return nil, fmt.Errorf("Type does not match")
	}

	switch compareFields(out.IPAM, b.IPAM) {
	case BOnlySet:
		out.IPAM = b.IPAM
	case Different:
		return nil, fmt.Errorf("IPAM does not match")
	}

	return out, nil
}

//BGP *BGPOption `json:"bgp,omitempty"`
//IPPools []IPPool `json:"ipPools,omitempty"`
//MTU *int32 `json:"mtu,omitempty"`
//NodeAddressAutodetectionV4 *NodeAddressAutodetection `json:"nodeAddressAutodetectionV4,omitempty"`
//NodeAddressAutodetectionV6 *NodeAddressAutodetection `json:"nodeAddressAutodetectionV6,omitempty"`
//HostPorts *HostPortsType `json:"hostPorts,omitempty"`
//MultiInterfaceMode *MultiInterfaceMode `json:"multiInterfaceMode,omitempty"`
//ContainerIPForwarding *ContainerIPForwardingType `json:"containerIPForwarding,omitempty"`
func mergeCalicoNetwork(a, b *operatorv1.CalicoNetworkSpec) (*operatorv1.CalicoNetworkSpec, error) {
	out := a.DeepCopy()

	switch compareFields(out.BGP, b.BGP) {
	case BOnlySet:
		out.BGP = b.BGP
	case Different:
		return nil, fmt.Errorf("BGP does not match")
	}

	switch compareFields(out.IPPools, b.IPPools) {
	case BOnlySet:
		out.IPPools = b.IPPools
	case Different:
		return nil, fmt.Errorf("IPPools does not match")
	}

	switch compareFields(out.MTU, b.MTU) {
	case BOnlySet:
		out.MTU = b.MTU
	case Different:
		return nil, fmt.Errorf("MTU does not match")
	}

	return out, nil
}
