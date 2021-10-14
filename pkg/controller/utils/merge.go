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

package utils

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

func OverrideInstallationSpec(cfg, override operatorv1.InstallationSpec) operatorv1.InstallationSpec {
	inst := *cfg.DeepCopy()

	switch compareFields(inst.Variant, override.Variant) {
	case BOnlySet, Different:
		inst.Variant = override.Variant
	}

	switch compareFields(inst.Registry, override.Registry) {
	case BOnlySet, Different:
		inst.Registry = override.Registry
	}

	switch compareFields(inst.ImagePath, override.ImagePath) {
	case BOnlySet, Different:
		inst.ImagePath = override.ImagePath
	}

	switch compareFields(inst.ImagePrefix, override.ImagePrefix) {
	case BOnlySet, Different:
		inst.ImagePrefix = override.ImagePrefix
	}

	switch compareFields(inst.ImagePullSecrets, override.ImagePullSecrets) {
	case BOnlySet, Different:
		inst.ImagePullSecrets = make([]v1.LocalObjectReference, len(override.ImagePullSecrets))
		copy(inst.ImagePullSecrets, override.ImagePullSecrets)
	}

	switch compareFields(inst.KubernetesProvider, override.KubernetesProvider) {
	case BOnlySet, Different:
		inst.KubernetesProvider = override.KubernetesProvider
	}

	switch compareFields(inst.CNI, override.CNI) {
	case BOnlySet:
		inst.CNI = override.CNI.DeepCopy()
	case Different:
		inst.CNI = mergeCNISpecs(inst.CNI, override.CNI)
	}

	switch compareFields(inst.CalicoNetwork, override.CalicoNetwork) {
	case BOnlySet:
		inst.CalicoNetwork = override.CalicoNetwork.DeepCopy()
	case Different:
		inst.CalicoNetwork = mergeCalicoNetwork(inst.CalicoNetwork, override.CalicoNetwork)
	}

	switch compareFields(inst.ControlPlaneNodeSelector, override.ControlPlaneNodeSelector) {
	case BOnlySet, Different:
		inst.ControlPlaneNodeSelector = make(map[string]string, len(override.ControlPlaneNodeSelector))
		for key, val := range override.ControlPlaneNodeSelector {
			inst.ControlPlaneNodeSelector[key] = val
		}
	}

	switch compareFields(inst.ControlPlaneTolerations, override.ControlPlaneTolerations) {
	case BOnlySet, Different:
		inst.ControlPlaneTolerations = make([]v1.Toleration, len(override.ControlPlaneTolerations))
		copy(inst.ControlPlaneTolerations, override.ControlPlaneTolerations)
	}

	switch compareFields(inst.ControlPlaneReplicas, override.ControlPlaneReplicas) {
	case BOnlySet, Different:
		inst.ControlPlaneReplicas = override.ControlPlaneReplicas
	}

	switch compareFields(inst.NodeMetricsPort, override.NodeMetricsPort) {
	case BOnlySet, Different:
		inst.NodeMetricsPort = override.NodeMetricsPort
	}

	switch compareFields(inst.TyphaMetricsPort, override.TyphaMetricsPort) {
	case BOnlySet, Different:
		inst.TyphaMetricsPort = override.TyphaMetricsPort
	}

	switch compareFields(inst.FlexVolumePath, override.FlexVolumePath) {
	case BOnlySet, Different:
		inst.FlexVolumePath = override.FlexVolumePath
	}

	switch compareFields(inst.NodeUpdateStrategy, override.NodeUpdateStrategy) {
	case BOnlySet, Different:
		override.NodeUpdateStrategy.DeepCopyInto(&inst.NodeUpdateStrategy)
	}

	switch compareFields(inst.ComponentResources, override.ComponentResources) {
	case BOnlySet, Different:
		inst.ComponentResources = make([]operatorv1.ComponentResource, len(override.ComponentResources))
		copy(inst.ComponentResources, override.ComponentResources)
	}

	switch compareFields(inst.TyphaAffinity, override.TyphaAffinity) {
	case BOnlySet, Different:
		inst.TyphaAffinity = override.TyphaAffinity
	}

	switch compareFields(inst.CertificateManagement, override.CertificateManagement) {
	case BOnlySet:
		inst.CertificateManagement = override.CertificateManagement.DeepCopy()
	case Different:
		override.CertificateManagement.DeepCopyInto(inst.CertificateManagement)
	}

	switch compareFields(inst.NonPrivileged, override.NonPrivileged) {
	case BOnlySet, Different:
		inst.NonPrivileged = override.NonPrivileged
	}

	return inst
}

func compareFields(a, b interface{}) CompareResult {
	// Flag if az or bz are the nil/zero value
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

	switch compareFields(out.LinuxDataplane, override.LinuxDataplane) {
	case BOnlySet, Different:
		out.LinuxDataplane = override.LinuxDataplane
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
