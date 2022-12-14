// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

package v1

import (
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EgressGatewaySpec defines the desired state of EgressGateway
type EgressGatewaySpec struct {
	// Replicas defines how many instances of the Egress Gateway pod will run.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	// +required
	Replicas *int32 `json:"replicas"`

	// IPPools defines the IP Pools that the Egress Gateway pods should be using.
	// Either name or CIDR must be specified.
	// IPPools must match an existing IPPools.
	// +required
	IPPools []EgressGatewayIPPool `json:"ipPools"`

	// LogSeverity defines the logging level of the Egress Gateway.
	// Default: Info
	// +kubebuilder:validation:Enum=Trace;Debug;Info;Warn;Error;Fatal
	// +optional
	LogSeverity *LogLevel `json:"logSeverity"`

	// Template describes the EGW Deployment pod that will be created.
	// +optional
	Template *EgressGatewayDeploymentPodTemplateSpec `json:"template,omitempty"`

	// EgressGatewayFailureDetection is used to configure how Egress Gateway
	// determines readiness. If both ICMP, HTTP probes are defined, one ICMP probe and one
	// HTTP probe should succeed for Egress Gateways to become ready.
	// Otherwise one of ICMP or HTTP probe should succeed for Egress gateways to become
	// ready if configured.
	// +optional
	EgressGatewayFailureDetection *EgressGatewayFailureDetection `json:"egressGatewayFailureDetection,omitempty"`

	// AWS defines the additional configuration options for Egress Gateways on AWS.
	// +optional
	AWS *AwsEgressGateway `json:"aws,omitempty"`
}

type EgressGatewayDeploymentPodSpec struct {
	// Affinity is a group of affinity scheduling rules for the EGW pods.
	// +optional
	Affinity *v1.Affinity `json:"affinity,omitempty"`

	// NodeSelector gives more control over the nodes where the Egress Gateway pods will run on.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// TerminationGracePeriodSeconds defines the termination grace period of the Egress Gateway pods in seconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	TerminationGracePeriodSeconds *int64 `json:"terminationGracePeriodSeconds,omitempty"`

	// TopologySpreadConstraints defines how the Egress Gateway pods should be spread across different AZs.
	// +optional
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
}

// EgressGatewayDeploymentPodTemplateSpec is the EGW Deployment's PodTemplateSpec
type EgressGatewayDeploymentPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to
	// the pod's metadata.
	// +optional
	Metadata *EgressGatewayMetadata `json:"metadata,omitempty"`

	// Spec is the EGW Deployment's PodSpec.
	// +optional
	Spec *EgressGatewayDeploymentPodSpec `json:"spec,omitempty"`
}

// EgressGatewayMetadata contains the standard Kubernetes labels and annotations fields.
type EgressGatewayMetadata struct {
	// Labels is a map of string keys and values that may match replicaset and
	// service selectors. Each of these key/value pairs are added to the
	// object's labels provided the key does not already exist in the object's labels.
	// If not specified will default to projectcalico.org/egw:<name>, where <name> is
	// the name of the Egress Gateway resource.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations is a map of arbitrary non-identifying metadata. Each of these
	// key/value pairs are added to the object's annotations provided the key does not
	// already exist in the object's annotations.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

type EgressGatewayIPPool struct {
	// Name is the name of the IPPool that the Egress Gateways can use.
	// +optional
	Name string `json:"name,omitempty"`

	// CIDR is the IPPool CIDR that the Egress Gateways can use.
	// +optional
	CIDR string `json:"cidr,omitempty"`
}

type NativeIP string

const (
	NativeIPEnabled  NativeIP = "Enabled"
	NativeIPDisabled NativeIP = "Disabled"
)

type LogLevel string

const (
	LogLevelTrace LogLevel = "Trace"
	LogLevelInfo  LogLevel = "Info"
	LogLevelDebug LogLevel = "Debug"
	LogLevelWarn  LogLevel = "Warn"
	LogLevelFatal LogLevel = "Fatal"
	LogLevelError LogLevel = "Error"
)

// EgressGatewayFailureDetection defines the fields the needed for determining Egress Gateway
// readiness.
type EgressGatewayFailureDetection struct {

	// HealthTimeoutDataStoreSeconds defines how long Egress Gateway can fail to connect
	// to the datastore before reporting not ready.
	// This value must be greater than 0.
	// Default: 90
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=2147483647
	// +optional
	HealthTimeoutDataStoreSeconds *int32 `json:"healthTimeoutDataStoreSeconds,omitempty"`

	// ICMPProbes define outgoing ICMP probes that Egress Gateway will use to
	// verify its upstream connection. Egress Gateway will report not ready if all
	// fail. Timeout must be greater than interval.
	// +optional
	ICMPProbes *ICMPProbes `json:"icmpProbe,omitempty"`

	// HTTPProbes define outgoing HTTP probes that Egress Gateway will use to
	// verify its upsteam connection. Egress Gateway will report not ready if all
	// fail. Timeout must be greater than interval.
	// +optional
	HTTPProbes *HTTPProbes `json:"httpProbe,omitempty"`
}

// ICMPProbes defines the ICMP probe configuration for Egress Gateway.
type ICMPProbes struct {
	// IPs define the list of ICMP probe IPs. Egress Gateway will probe each IP
	// periodically. If all probes faile, Egress Gateway will report non-ready.
	// +optional
	IPs []string `json:"ips,omitempty"`

	// IntervalSeconds defines the interval of ICMP probes. Used when IPs is non-empty.
	// Default: 5
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	// +optional
	IntervalSeconds *int32 `json:"intervalSeconds"`

	// TimeoutSeconds defines the timeout value of ICMP probes. Used when IPs is non-empty.
	// Default: 15
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	// +optional
	TimeoutSeconds *int32 `json:"timeoutSeconds"`
}

// HTTPProbes defines the HTTP probe configuration for Egress Gateway.
type HTTPProbes struct {
	// URLs define the list of HTTP probe URLs. Egress Gateway will probe each URL
	// periodically.If all probes fail, Egress Gateway will report non-ready.
	// +optional
	URLs []string `json:"urls,omitempty"`

	// IntervalSeconds defines the interval of HTTP probes. Used when URLs is non-empty.
	// Default: 10
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	// +optional
	IntervalSeconds *int32 `json:"intervalSeconds"`

	// TimeoutSeconds defines the timeout value of HTTP probes. Used when URLs is non-empty.
	// Default: 30
	// +optional
	TimeoutSeconds *int32 `json:"timeoutSeconds"`
}

// AwsEgressGateway defines the configurations for deploying EgressGateway in AWS
type AwsEgressGateway struct {

	// NativeIP defines if EgressGateway is to use an AWS backed IPPool.
	// Default: Disabled
	// +kubebuilder:validation:Enum=Enabled;Disabled
	// +optional
	NativeIP *NativeIP `json:"nativeIP,omitempty"`

	// ElasticIPs defines the set of elastic IPs that can be used for Egress Gateway pods.
	// NativeIP must be Enabled if elastic IPs are set.
	// +optional
	ElasticIPs []string `json:"elasticIPs,omitempty"`
}

// EgressGatewayStatus defines the observed state of EgressGateway
type EgressGatewayStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// EgressGateway is the Schema for the egressgateways API
type EgressGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EgressGatewaySpec   `json:"spec,omitempty"`
	Status EgressGatewayStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// EgressGatewayList contains a list of EgressGateway
type EgressGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EgressGateway `json:"items"`
}

func (c *EgressGateway) GetLogSeverity() string {
	return string(*c.Spec.LogSeverity)
}

func (c *EgressGateway) GetHealthTimeoutDs() string {
	return fmt.Sprintf("%ds", *c.Spec.EgressGatewayFailureDetection.HealthTimeoutDataStoreSeconds)
}

func (c *EgressGateway) GetIPPools() string {
	ippools := []string{}
	for _, ippool := range c.Spec.IPPools {
		if ippool.Name != "" {
			ippools = append(ippools, ippool.Name)
		} else if ippool.CIDR != "" {
			ippools = append(ippools, ippool.CIDR)
		}
	}
	return concatString(ippools)
}

func (c *EgressGateway) GetElasticIPs() string {
	if c.Spec.AWS != nil {
		if len(c.Spec.AWS.ElasticIPs) > 0 {
			return concatString(c.Spec.AWS.ElasticIPs)
		}
	}
	return ""
}

func (c *EgressGateway) GetICMPProbes() (string, string, string) {
	probeIPs := strings.Join(c.Spec.EgressGatewayFailureDetection.ICMPProbes.IPs, ",")
	interval := fmt.Sprintf("%ds", *c.Spec.EgressGatewayFailureDetection.ICMPProbes.IntervalSeconds)
	timeout := fmt.Sprintf("%ds", *c.Spec.EgressGatewayFailureDetection.ICMPProbes.TimeoutSeconds)
	return probeIPs, interval, timeout
}

func (c *EgressGateway) GetHTTPProbes() (string, string, string) {
	probeURLs := strings.Join(c.Spec.EgressGatewayFailureDetection.HTTPProbes.URLs, ",")
	interval := fmt.Sprintf("%ds", *c.Spec.EgressGatewayFailureDetection.HTTPProbes.IntervalSeconds)
	timeout := fmt.Sprintf("%ds", *c.Spec.EgressGatewayFailureDetection.HTTPProbes.TimeoutSeconds)
	return probeURLs, interval, timeout
}

func (c *EgressGateway) GetResources() v1.ResourceRequirements {
	recommendedQuantity := resource.NewQuantity(1, resource.DecimalSI)
	if c.Spec.AWS != nil && *c.Spec.AWS.NativeIP == NativeIPEnabled {
		return v1.ResourceRequirements{
			Limits:   v1.ResourceList{"projectcalico.org/aws-secondary-ipv4": *recommendedQuantity},
			Requests: v1.ResourceList{"projectcalico.org/aws-secondary-ipv4": *recommendedQuantity},
		}
	}
	return v1.ResourceRequirements{}
}

func (c *EgressGateway) GetTerminationGracePeriod() *int64 {
	return c.Spec.Template.Spec.TerminationGracePeriodSeconds
}

func (c *EgressGateway) GetNodeSelector() map[string]string {
	return c.Spec.Template.Spec.NodeSelector
}

func (c *EgressGateway) GetAffinity() *v1.Affinity {
	return c.Spec.Template.Spec.Affinity
}

func (c *EgressGateway) GetTopoConstraints() []v1.TopologySpreadConstraint {
	return c.Spec.Template.Spec.TopologySpreadConstraints
}

func concatString(arr []string) string {
	ret := "["
	for idx, str := range arr {
		temp := fmt.Sprintf("\"%s\"", str)
		ret = ret + temp
		if idx != len(arr)-1 {
			ret = ret + ","
		}
	}
	return ret + "]"
}

func init() {
	SchemeBuilder.Register(&EgressGateway{}, &EgressGatewayList{})
}
