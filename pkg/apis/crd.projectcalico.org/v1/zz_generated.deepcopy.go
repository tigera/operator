//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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
	"github.com/projectcalico/api/pkg/lib/numorstring"
	libnumorstring "github.com/tigera/api/pkg/lib/numorstring"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BGPConfiguration) DeepCopyInto(out *BGPConfiguration) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BGPConfiguration.
func (in *BGPConfiguration) DeepCopy() *BGPConfiguration {
	if in == nil {
		return nil
	}
	out := new(BGPConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *BGPConfiguration) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BGPConfigurationList) DeepCopyInto(out *BGPConfigurationList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]BGPConfiguration, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BGPConfigurationList.
func (in *BGPConfigurationList) DeepCopy() *BGPConfigurationList {
	if in == nil {
		return nil
	}
	out := new(BGPConfigurationList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *BGPConfigurationList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BGPConfigurationSpec) DeepCopyInto(out *BGPConfigurationSpec) {
	*out = *in
	if in.NodeToNodeMeshEnabled != nil {
		in, out := &in.NodeToNodeMeshEnabled, &out.NodeToNodeMeshEnabled
		*out = new(bool)
		**out = **in
	}
	if in.ASNumber != nil {
		in, out := &in.ASNumber, &out.ASNumber
		*out = new(numorstring.ASNumber)
		**out = **in
	}
	if in.ServiceLoadBalancerIPs != nil {
		in, out := &in.ServiceLoadBalancerIPs, &out.ServiceLoadBalancerIPs
		*out = make([]ServiceLoadBalancerIPBlock, len(*in))
		copy(*out, *in)
	}
	if in.ServiceExternalIPs != nil {
		in, out := &in.ServiceExternalIPs, &out.ServiceExternalIPs
		*out = make([]ServiceExternalIPBlock, len(*in))
		copy(*out, *in)
	}
	if in.ServiceClusterIPs != nil {
		in, out := &in.ServiceClusterIPs, &out.ServiceClusterIPs
		*out = make([]ServiceClusterIPBlock, len(*in))
		copy(*out, *in)
	}
	if in.Communities != nil {
		in, out := &in.Communities, &out.Communities
		*out = make([]Community, len(*in))
		copy(*out, *in)
	}
	if in.PrefixAdvertisements != nil {
		in, out := &in.PrefixAdvertisements, &out.PrefixAdvertisements
		*out = make([]PrefixAdvertisement, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.NodeMeshPassword != nil {
		in, out := &in.NodeMeshPassword, &out.NodeMeshPassword
		*out = new(BGPPassword)
		(*in).DeepCopyInto(*out)
	}
	if in.NodeMeshMaxRestartTime != nil {
		in, out := &in.NodeMeshMaxRestartTime, &out.NodeMeshMaxRestartTime
		*out = new(metav1.Duration)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BGPConfigurationSpec.
func (in *BGPConfigurationSpec) DeepCopy() *BGPConfigurationSpec {
	if in == nil {
		return nil
	}
	out := new(BGPConfigurationSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BGPPassword) DeepCopyInto(out *BGPPassword) {
	*out = *in
	if in.SecretKeyRef != nil {
		in, out := &in.SecretKeyRef, &out.SecretKeyRef
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BGPPassword.
func (in *BGPPassword) DeepCopy() *BGPPassword {
	if in == nil {
		return nil
	}
	out := new(BGPPassword)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Community) DeepCopyInto(out *Community) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Community.
func (in *Community) DeepCopy() *Community {
	if in == nil {
		return nil
	}
	out := new(Community)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FelixConfiguration) DeepCopyInto(out *FelixConfiguration) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FelixConfiguration.
func (in *FelixConfiguration) DeepCopy() *FelixConfiguration {
	if in == nil {
		return nil
	}
	out := new(FelixConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *FelixConfiguration) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FelixConfigurationList) DeepCopyInto(out *FelixConfigurationList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]FelixConfiguration, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FelixConfigurationList.
func (in *FelixConfigurationList) DeepCopy() *FelixConfigurationList {
	if in == nil {
		return nil
	}
	out := new(FelixConfigurationList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *FelixConfigurationList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FelixConfigurationSpec) DeepCopyInto(out *FelixConfigurationSpec) {
	*out = *in
	if in.UseInternalDataplaneDriver != nil {
		in, out := &in.UseInternalDataplaneDriver, &out.UseInternalDataplaneDriver
		*out = new(bool)
		**out = **in
	}
	if in.IPv6Support != nil {
		in, out := &in.IPv6Support, &out.IPv6Support
		*out = new(bool)
		**out = **in
	}
	if in.RouteRefreshInterval != nil {
		in, out := &in.RouteRefreshInterval, &out.RouteRefreshInterval
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.InterfaceRefreshInterval != nil {
		in, out := &in.InterfaceRefreshInterval, &out.InterfaceRefreshInterval
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.IptablesRefreshInterval != nil {
		in, out := &in.IptablesRefreshInterval, &out.IptablesRefreshInterval
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.IptablesPostWriteCheckInterval != nil {
		in, out := &in.IptablesPostWriteCheckInterval, &out.IptablesPostWriteCheckInterval
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.IptablesLockTimeout != nil {
		in, out := &in.IptablesLockTimeout, &out.IptablesLockTimeout
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.IptablesLockProbeInterval != nil {
		in, out := &in.IptablesLockProbeInterval, &out.IptablesLockProbeInterval
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.IpsetsRefreshInterval != nil {
		in, out := &in.IpsetsRefreshInterval, &out.IpsetsRefreshInterval
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.MaxIpsetSize != nil {
		in, out := &in.MaxIpsetSize, &out.MaxIpsetSize
		*out = new(int)
		**out = **in
	}
	if in.IptablesBackend != nil {
		in, out := &in.IptablesBackend, &out.IptablesBackend
		*out = new(IptablesBackend)
		**out = **in
	}
	if in.XDPRefreshInterval != nil {
		in, out := &in.XDPRefreshInterval, &out.XDPRefreshInterval
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.NetlinkTimeout != nil {
		in, out := &in.NetlinkTimeout, &out.NetlinkTimeout
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.MetadataPort != nil {
		in, out := &in.MetadataPort, &out.MetadataPort
		*out = new(int)
		**out = **in
	}
	if in.IPIPEnabled != nil {
		in, out := &in.IPIPEnabled, &out.IPIPEnabled
		*out = new(bool)
		**out = **in
	}
	if in.IPIPMTU != nil {
		in, out := &in.IPIPMTU, &out.IPIPMTU
		*out = new(int)
		**out = **in
	}
	if in.VXLANEnabled != nil {
		in, out := &in.VXLANEnabled, &out.VXLANEnabled
		*out = new(bool)
		**out = **in
	}
	if in.VXLANMTU != nil {
		in, out := &in.VXLANMTU, &out.VXLANMTU
		*out = new(int)
		**out = **in
	}
	if in.VXLANPort != nil {
		in, out := &in.VXLANPort, &out.VXLANPort
		*out = new(int)
		**out = **in
	}
	if in.VXLANVNI != nil {
		in, out := &in.VXLANVNI, &out.VXLANVNI
		*out = new(int)
		**out = **in
	}
	if in.ReportingInterval != nil {
		in, out := &in.ReportingInterval, &out.ReportingInterval
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.ReportingTTL != nil {
		in, out := &in.ReportingTTL, &out.ReportingTTL
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.EndpointReportingEnabled != nil {
		in, out := &in.EndpointReportingEnabled, &out.EndpointReportingEnabled
		*out = new(bool)
		**out = **in
	}
	if in.EndpointReportingDelay != nil {
		in, out := &in.EndpointReportingDelay, &out.EndpointReportingDelay
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.IptablesMarkMask != nil {
		in, out := &in.IptablesMarkMask, &out.IptablesMarkMask
		*out = new(uint32)
		**out = **in
	}
	if in.DisableConntrackInvalidCheck != nil {
		in, out := &in.DisableConntrackInvalidCheck, &out.DisableConntrackInvalidCheck
		*out = new(bool)
		**out = **in
	}
	if in.HealthEnabled != nil {
		in, out := &in.HealthEnabled, &out.HealthEnabled
		*out = new(bool)
		**out = **in
	}
	if in.HealthHost != nil {
		in, out := &in.HealthHost, &out.HealthHost
		*out = new(string)
		**out = **in
	}
	if in.HealthPort != nil {
		in, out := &in.HealthPort, &out.HealthPort
		*out = new(int)
		**out = **in
	}
	if in.PrometheusMetricsEnabled != nil {
		in, out := &in.PrometheusMetricsEnabled, &out.PrometheusMetricsEnabled
		*out = new(bool)
		**out = **in
	}
	if in.PrometheusMetricsPort != nil {
		in, out := &in.PrometheusMetricsPort, &out.PrometheusMetricsPort
		*out = new(int)
		**out = **in
	}
	if in.PrometheusGoMetricsEnabled != nil {
		in, out := &in.PrometheusGoMetricsEnabled, &out.PrometheusGoMetricsEnabled
		*out = new(bool)
		**out = **in
	}
	if in.PrometheusProcessMetricsEnabled != nil {
		in, out := &in.PrometheusProcessMetricsEnabled, &out.PrometheusProcessMetricsEnabled
		*out = new(bool)
		**out = **in
	}
	if in.PrometheusReporterPort != nil {
		in, out := &in.PrometheusReporterPort, &out.PrometheusReporterPort
		*out = new(int)
		**out = **in
	}
	if in.FailsafeInboundHostPorts != nil {
		in, out := &in.FailsafeInboundHostPorts, &out.FailsafeInboundHostPorts
		*out = new([]ProtoPort)
		if **in != nil {
			in, out := *in, *out
			*out = make([]ProtoPort, len(*in))
			copy(*out, *in)
		}
	}
	if in.FailsafeOutboundHostPorts != nil {
		in, out := &in.FailsafeOutboundHostPorts, &out.FailsafeOutboundHostPorts
		*out = new([]ProtoPort)
		if **in != nil {
			in, out := *in, *out
			*out = make([]ProtoPort, len(*in))
			copy(*out, *in)
		}
	}
	if in.KubeNodePortRanges != nil {
		in, out := &in.KubeNodePortRanges, &out.KubeNodePortRanges
		*out = new([]libnumorstring.Port)
		if **in != nil {
			in, out := *in, *out
			*out = make([]libnumorstring.Port, len(*in))
			copy(*out, *in)
		}
	}
	if in.UsageReportingEnabled != nil {
		in, out := &in.UsageReportingEnabled, &out.UsageReportingEnabled
		*out = new(bool)
		**out = **in
	}
	if in.UsageReportingInitialDelay != nil {
		in, out := &in.UsageReportingInitialDelay, &out.UsageReportingInitialDelay
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.UsageReportingInterval != nil {
		in, out := &in.UsageReportingInterval, &out.UsageReportingInterval
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.NATPortRange != nil {
		in, out := &in.NATPortRange, &out.NATPortRange
		*out = new(libnumorstring.Port)
		**out = **in
	}
	if in.DeviceRouteProtocol != nil {
		in, out := &in.DeviceRouteProtocol, &out.DeviceRouteProtocol
		*out = new(int)
		**out = **in
	}
	if in.RemoveExternalRoutes != nil {
		in, out := &in.RemoveExternalRoutes, &out.RemoveExternalRoutes
		*out = new(bool)
		**out = **in
	}
	if in.ExternalNodesCIDRList != nil {
		in, out := &in.ExternalNodesCIDRList, &out.ExternalNodesCIDRList
		*out = new([]string)
		if **in != nil {
			in, out := *in, *out
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
	}
	if in.DebugDisableLogDropping != nil {
		in, out := &in.DebugDisableLogDropping, &out.DebugDisableLogDropping
		*out = new(bool)
		**out = **in
	}
	if in.DebugSimulateCalcGraphHangAfter != nil {
		in, out := &in.DebugSimulateCalcGraphHangAfter, &out.DebugSimulateCalcGraphHangAfter
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.DebugSimulateDataplaneHangAfter != nil {
		in, out := &in.DebugSimulateDataplaneHangAfter, &out.DebugSimulateDataplaneHangAfter
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.SidecarAccelerationEnabled != nil {
		in, out := &in.SidecarAccelerationEnabled, &out.SidecarAccelerationEnabled
		*out = new(bool)
		**out = **in
	}
	if in.XDPEnabled != nil {
		in, out := &in.XDPEnabled, &out.XDPEnabled
		*out = new(bool)
		**out = **in
	}
	if in.GenericXDPEnabled != nil {
		in, out := &in.GenericXDPEnabled, &out.GenericXDPEnabled
		*out = new(bool)
		**out = **in
	}
	if in.BPFEnabled != nil {
		in, out := &in.BPFEnabled, &out.BPFEnabled
		*out = new(bool)
		**out = **in
	}
	if in.BPFDisableUnprivileged != nil {
		in, out := &in.BPFDisableUnprivileged, &out.BPFDisableUnprivileged
		*out = new(bool)
		**out = **in
	}
	if in.BPFConnectTimeLoadBalancingEnabled != nil {
		in, out := &in.BPFConnectTimeLoadBalancingEnabled, &out.BPFConnectTimeLoadBalancingEnabled
		*out = new(bool)
		**out = **in
	}
	if in.BPFKubeProxyIptablesCleanupEnabled != nil {
		in, out := &in.BPFKubeProxyIptablesCleanupEnabled, &out.BPFKubeProxyIptablesCleanupEnabled
		*out = new(bool)
		**out = **in
	}
	if in.BPFKubeProxyMinSyncPeriod != nil {
		in, out := &in.BPFKubeProxyMinSyncPeriod, &out.BPFKubeProxyMinSyncPeriod
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.BPFKubeProxyEndpointSlicesEnabled != nil {
		in, out := &in.BPFKubeProxyEndpointSlicesEnabled, &out.BPFKubeProxyEndpointSlicesEnabled
		*out = new(bool)
		**out = **in
	}
	if in.RouteTableRange != nil {
		in, out := &in.RouteTableRange, &out.RouteTableRange
		*out = new(RouteTableRange)
		**out = **in
	}
	if in.WireguardEnabled != nil {
		in, out := &in.WireguardEnabled, &out.WireguardEnabled
		*out = new(bool)
		**out = **in
	}
	if in.WireguardEnabledV6 != nil {
		in, out := &in.WireguardEnabledV6, &out.WireguardEnabledV6
		*out = new(bool)
		**out = **in
	}
	if in.WireguardListeningPort != nil {
		in, out := &in.WireguardListeningPort, &out.WireguardListeningPort
		*out = new(int)
		**out = **in
	}
	if in.WireguardListeningPortV6 != nil {
		in, out := &in.WireguardListeningPortV6, &out.WireguardListeningPortV6
		*out = new(int)
		**out = **in
	}
	if in.WireguardRoutingRulePriority != nil {
		in, out := &in.WireguardRoutingRulePriority, &out.WireguardRoutingRulePriority
		*out = new(int)
		**out = **in
	}
	if in.WireguardMTU != nil {
		in, out := &in.WireguardMTU, &out.WireguardMTU
		*out = new(int)
		**out = **in
	}
	if in.WireguardMTUV6 != nil {
		in, out := &in.WireguardMTUV6, &out.WireguardMTUV6
		*out = new(int)
		**out = **in
	}
	if in.WireguardHostEncryptionEnabled != nil {
		in, out := &in.WireguardHostEncryptionEnabled, &out.WireguardHostEncryptionEnabled
		*out = new(bool)
		**out = **in
	}
	if in.WireguardPersistentKeepAlive != nil {
		in, out := &in.WireguardPersistentKeepAlive, &out.WireguardPersistentKeepAlive
		*out = new(metav1.Duration)
		**out = **in
	}
	if in.AWSSrcDstCheck != nil {
		in, out := &in.AWSSrcDstCheck, &out.AWSSrcDstCheck
		*out = new(AWSSrcDstCheckOption)
		**out = **in
	}
	if in.TPROXYMode != nil {
		in, out := &in.TPROXYMode, &out.TPROXYMode
		*out = new(TPROXYModeOption)
		**out = **in
	}
	if in.EgressIPVXLANPort != nil {
		in, out := &in.EgressIPVXLANPort, &out.EgressIPVXLANPort
		*out = new(int)
		**out = **in
	}
	if in.EgressIPVXLANVNI != nil {
		in, out := &in.EgressIPVXLANVNI, &out.EgressIPVXLANVNI
		*out = new(int)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FelixConfigurationSpec.
func (in *FelixConfigurationSpec) DeepCopy() *FelixConfigurationSpec {
	if in == nil {
		return nil
	}
	out := new(FelixConfigurationSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPPool) DeepCopyInto(out *IPPool) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
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

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IPPool) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPPoolList) DeepCopyInto(out *IPPoolList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IPPool, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPPoolList.
func (in *IPPoolList) DeepCopy() *IPPoolList {
	if in == nil {
		return nil
	}
	out := new(IPPoolList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IPPoolList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPPoolSpec) DeepCopyInto(out *IPPoolSpec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPPoolSpec.
func (in *IPPoolSpec) DeepCopy() *IPPoolSpec {
	if in == nil {
		return nil
	}
	out := new(IPPoolSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *KubeControllersConfiguration) DeepCopyInto(out *KubeControllersConfiguration) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new KubeControllersConfiguration.
func (in *KubeControllersConfiguration) DeepCopy() *KubeControllersConfiguration {
	if in == nil {
		return nil
	}
	out := new(KubeControllersConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *KubeControllersConfiguration) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *KubeControllersConfigurationList) DeepCopyInto(out *KubeControllersConfigurationList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]KubeControllersConfiguration, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new KubeControllersConfigurationList.
func (in *KubeControllersConfigurationList) DeepCopy() *KubeControllersConfigurationList {
	if in == nil {
		return nil
	}
	out := new(KubeControllersConfigurationList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *KubeControllersConfigurationList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *KubeControllersConfigurationSpec) DeepCopyInto(out *KubeControllersConfigurationSpec) {
	*out = *in
	if in.PrometheusMetricsPort != nil {
		in, out := &in.PrometheusMetricsPort, &out.PrometheusMetricsPort
		*out = new(int)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new KubeControllersConfigurationSpec.
func (in *KubeControllersConfigurationSpec) DeepCopy() *KubeControllersConfigurationSpec {
	if in == nil {
		return nil
	}
	out := new(KubeControllersConfigurationSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PrefixAdvertisement) DeepCopyInto(out *PrefixAdvertisement) {
	*out = *in
	if in.Communities != nil {
		in, out := &in.Communities, &out.Communities
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PrefixAdvertisement.
func (in *PrefixAdvertisement) DeepCopy() *PrefixAdvertisement {
	if in == nil {
		return nil
	}
	out := new(PrefixAdvertisement)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ProtoPort) DeepCopyInto(out *ProtoPort) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ProtoPort.
func (in *ProtoPort) DeepCopy() *ProtoPort {
	if in == nil {
		return nil
	}
	out := new(ProtoPort)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RouteTableRange) DeepCopyInto(out *RouteTableRange) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RouteTableRange.
func (in *RouteTableRange) DeepCopy() *RouteTableRange {
	if in == nil {
		return nil
	}
	out := new(RouteTableRange)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceClusterIPBlock) DeepCopyInto(out *ServiceClusterIPBlock) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceClusterIPBlock.
func (in *ServiceClusterIPBlock) DeepCopy() *ServiceClusterIPBlock {
	if in == nil {
		return nil
	}
	out := new(ServiceClusterIPBlock)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceExternalIPBlock) DeepCopyInto(out *ServiceExternalIPBlock) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceExternalIPBlock.
func (in *ServiceExternalIPBlock) DeepCopy() *ServiceExternalIPBlock {
	if in == nil {
		return nil
	}
	out := new(ServiceExternalIPBlock)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceLoadBalancerIPBlock) DeepCopyInto(out *ServiceLoadBalancerIPBlock) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceLoadBalancerIPBlock.
func (in *ServiceLoadBalancerIPBlock) DeepCopy() *ServiceLoadBalancerIPBlock {
	if in == nil {
		return nil
	}
	out := new(ServiceLoadBalancerIPBlock)
	in.DeepCopyInto(out)
	return out
}
