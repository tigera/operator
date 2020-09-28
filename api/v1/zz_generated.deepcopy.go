// +build !ignore_autogenerated

/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by controller-gen. DO NOT EDIT.

package v1

import (
	corev1 "k8s.io/api/core/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CNISpec) DeepCopyInto(out *CNISpec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CNISpec.
func (in *CNISpec) DeepCopy() *CNISpec {
	if in == nil {
		return nil
	}
	out := new(CNISpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CalicoNetworkSpec) DeepCopyInto(out *CalicoNetworkSpec) {
	*out = *in
	if in.BGP != nil {
		in, out := &in.BGP, &out.BGP
		*out = new(BGPOption)
		**out = **in
	}
	if in.IPPools != nil {
		in, out := &in.IPPools, &out.IPPools
		*out = make([]IPPool, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.MTU != nil {
		in, out := &in.MTU, &out.MTU
		*out = new(int32)
		**out = **in
	}
	if in.NodeAddressAutodetectionV4 != nil {
		in, out := &in.NodeAddressAutodetectionV4, &out.NodeAddressAutodetectionV4
		*out = new(NodeAddressAutodetection)
		(*in).DeepCopyInto(*out)
	}
	if in.NodeAddressAutodetectionV6 != nil {
		in, out := &in.NodeAddressAutodetectionV6, &out.NodeAddressAutodetectionV6
		*out = new(NodeAddressAutodetection)
		(*in).DeepCopyInto(*out)
	}
	if in.HostPorts != nil {
		in, out := &in.HostPorts, &out.HostPorts
		*out = new(HostPortsType)
		**out = **in
	}
	if in.MultiInterfaceMode != nil {
		in, out := &in.MultiInterfaceMode, &out.MultiInterfaceMode
		*out = new(MultiInterfaceMode)
		**out = **in
	}
	if in.ContainerIPForwarding != nil {
		in, out := &in.ContainerIPForwarding, &out.ContainerIPForwarding
		*out = new(ContainerIPForwardingType)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CalicoNetworkSpec.
func (in *CalicoNetworkSpec) DeepCopy() *CalicoNetworkSpec {
	if in == nil {
		return nil
	}
	out := new(CalicoNetworkSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ComponentResource) DeepCopyInto(out *ComponentResource) {
	*out = *in
	if in.ResourceRequirements != nil {
		in, out := &in.ResourceRequirements, &out.ResourceRequirements
		*out = new(corev1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ComponentResource.
func (in *ComponentResource) DeepCopy() *ComponentResource {
	if in == nil {
		return nil
	}
	out := new(ComponentResource)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPPool) DeepCopyInto(out *IPPool) {
	*out = *in
	if in.BlockSize != nil {
		in, out := &in.BlockSize, &out.BlockSize
		*out = new(int32)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPPool.
func (in *IPPool) DeepCopy() *IPPool {
	if in == nil {
		return nil
	}
	out := new(IPPool)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Installation) DeepCopyInto(out *Installation) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Installation.
func (in *Installation) DeepCopy() *Installation {
	if in == nil {
		return nil
	}
	out := new(Installation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Installation) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InstallationList) DeepCopyInto(out *InstallationList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Installation, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InstallationList.
func (in *InstallationList) DeepCopy() *InstallationList {
	if in == nil {
		return nil
	}
	out := new(InstallationList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *InstallationList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InstallationSpec) DeepCopyInto(out *InstallationSpec) {
	*out = *in
	if in.ImagePullSecrets != nil {
		in, out := &in.ImagePullSecrets, &out.ImagePullSecrets
		*out = make([]corev1.LocalObjectReference, len(*in))
		copy(*out, *in)
	}
	if in.CNI != nil {
		in, out := &in.CNI, &out.CNI
		*out = new(CNISpec)
		**out = **in
	}
	if in.CalicoNetwork != nil {
		in, out := &in.CalicoNetwork, &out.CalicoNetwork
		*out = new(CalicoNetworkSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.ControlPlaneNodeSelector != nil {
		in, out := &in.ControlPlaneNodeSelector, &out.ControlPlaneNodeSelector
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.NodeMetricsPort != nil {
		in, out := &in.NodeMetricsPort, &out.NodeMetricsPort
		*out = new(int32)
		**out = **in
	}
	in.NodeUpdateStrategy.DeepCopyInto(&out.NodeUpdateStrategy)
	if in.ComponentResources != nil {
		in, out := &in.ComponentResources, &out.ComponentResources
		*out = make([]ComponentResource, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InstallationSpec.
func (in *InstallationSpec) DeepCopy() *InstallationSpec {
	if in == nil {
		return nil
	}
	out := new(InstallationSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InstallationStatus) DeepCopyInto(out *InstallationStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InstallationStatus.
func (in *InstallationStatus) DeepCopy() *InstallationStatus {
	if in == nil {
		return nil
	}
	out := new(InstallationStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodeAddressAutodetection) DeepCopyInto(out *NodeAddressAutodetection) {
	*out = *in
	if in.FirstFound != nil {
		in, out := &in.FirstFound, &out.FirstFound
		*out = new(bool)
		**out = **in
	}
	if in.CIDRS != nil {
		in, out := &in.CIDRS, &out.CIDRS
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodeAddressAutodetection.
func (in *NodeAddressAutodetection) DeepCopy() *NodeAddressAutodetection {
	if in == nil {
		return nil
	}
	out := new(NodeAddressAutodetection)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TigeraStatus) DeepCopyInto(out *TigeraStatus) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TigeraStatus.
func (in *TigeraStatus) DeepCopy() *TigeraStatus {
	if in == nil {
		return nil
	}
	out := new(TigeraStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TigeraStatus) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TigeraStatusCondition) DeepCopyInto(out *TigeraStatusCondition) {
	*out = *in
	in.LastTransitionTime.DeepCopyInto(&out.LastTransitionTime)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TigeraStatusCondition.
func (in *TigeraStatusCondition) DeepCopy() *TigeraStatusCondition {
	if in == nil {
		return nil
	}
	out := new(TigeraStatusCondition)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TigeraStatusList) DeepCopyInto(out *TigeraStatusList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]TigeraStatus, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TigeraStatusList.
func (in *TigeraStatusList) DeepCopy() *TigeraStatusList {
	if in == nil {
		return nil
	}
	out := new(TigeraStatusList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TigeraStatusList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TigeraStatusSpec) DeepCopyInto(out *TigeraStatusSpec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TigeraStatusSpec.
func (in *TigeraStatusSpec) DeepCopy() *TigeraStatusSpec {
	if in == nil {
		return nil
	}
	out := new(TigeraStatusSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TigeraStatusStatus) DeepCopyInto(out *TigeraStatusStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]TigeraStatusCondition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TigeraStatusStatus.
func (in *TigeraStatusStatus) DeepCopy() *TigeraStatusStatus {
	if in == nil {
		return nil
	}
	out := new(TigeraStatusStatus)
	in.DeepCopyInto(out)
	return out
}
