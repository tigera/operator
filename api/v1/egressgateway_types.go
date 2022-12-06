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
	// Replicas defines how many replicas of the Egress Gateway pods will run.
	// +required
	Replicas *int32 `json:"replicas"`

	// IPPools defines the IP Pools that the Egress Gateway pods should be using.
	// +required
	IPPools []string `json:"ipPools"`

	// Labels defines the labels on the Egress Gateway pods, which is to be used
	// by the client pods.
	// +required
	Labels map[string]string `json:"labels"`

	// LogSeverity defines the logging level of the Egress Gateway.
	// Default: info
	// +kubebuilder:validation:Enum=trace;debug;info;warn;error;fatal
	// +optional
	LogSeverity *string `json:"logSeverity"`

	// Template describes the EGW Deployment pod that will be created.
	// +optional
	Template *EgressGatewayDeploymentPodTemplateSpec `json:"template,omitempty"`

	// EgressGatewayFailureDetection defines the failure detection configuration options for Egress Gateway.
	// +optional
	EgressGatewayFailureDetection *EgressGatewayFailureDetection `json:"egressGatewayFailureDetection,omitempty"`

	// AWS defines the additional configuration options for Egress Gateways on AWS.
	// Should be specified if AWSMode is enabled.
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

	// TerminationGracePeriod defines the termination grace period of the Egress Gateway pods in seconds.
	// When not specified, it takes the default value of 30s defined by kubernetes.
	// +optional
	TerminationGracePeriod *int64 `json:"terminationGracePeriod,omitempty"`

	// TopologySpreadConstraints defines how the Egress Gateway pods should be spread across different AZs.
	// +optional
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
}

// EgressGatewayDeploymentPodTemplateSpec is the EGW Deployment's PodTemplateSpec
type EgressGatewayDeploymentPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to
	// the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the EGW Deployment's PodSpec.
	// +optional
	Spec *EgressGatewayDeploymentPodSpec `json:"spec,omitempty"`
}

type NativeIP string

const (
	NativeIPEnabled  NativeIP = "Enabled"
	NativeIPDisabled NativeIP = "Disabled"
)

// EgressGatewayFailureDetection defines the configuration for Egress Gateway failure detection.
type EgressGatewayFailureDetection struct {
	// HealthPort defines the container port used for readiness probes.
	// Default: 8080
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	HealthPort *int32 `json:"healthPort,omitempty"`

	// HealthTimeoutDataStore defines how long Egress Gateway waits before reporting its not ready.
	// Default: 90s
	// +optional
	HealthTimeoutDataStore *string `json:"healthTimeoutDataStore,omitempty"`

	// ICMPProbes defines the ICMP probe configuration options for Egress Gateway.
	// +optional
	ICMPProbes *ICMPProbes `json:"icmpProbe,omitempty"`

	// HTTPProbes defines the HTTP probe configuration options for Egress Gateway.
	// +optional
	HTTPProbes *HTTPProbes `json:"httpProbe,omitempty"`
}

// ICMPProbes defines the ICMP probe configuration for Egress Gateway.
type ICMPProbes struct {
	// IPs defines the list of ICMP probe IPs.
	// +optional
	IPs []string `json:"ips,omitempty"`

	// Interval defines the interval of ICMP probes. Used when IPs is non-empty.
	// Default: 5s
	// +optional
	Interval *string `json:"interval"`

	// Timeout defines the timeout value of ICMP probes. Used when IPs is non-empty.
	// Default: 15s
	// +optional
	Timeout *string `json:"timeout"`
}

// HTTPProbes defines the HTTP probe configuration for Egress Gateway.
type HTTPProbes struct {
	// URLs defines the list of HTTP probe URLs.
	// +optional
	URLs []string `json:"urls,omitempty"`

	// Interval defines the interval of HTTP probes. Used when URLs is non-empty.
	// Default: 10s
	// +optional
	Interval *string `json:"interval"`

	// Timeout defines the timeout value of HTTP probes. Used when URLs is non-empty.
	// Default: 30s
	// +optional
	Timeout *string `json:"timeout"`
}

// AwsEgressGateway defines the configurations for deploying EgressGateway in AWS
type AwsEgressGateway struct {

	// NativeIP defines if EgressGateway is to use an AWS backed IPPool.
	// Default: Disabled
	// +kubebuilder:validation:Enum=Enabled;Disabled
	// +optional
	NativeIP *NativeIP `json:"nativeIP,omitempty"`

	// ElasticIPs defines the set of elastic IPs that can be used for Egress Gateway pods.
	// Should be used along NativeIP enabled.
	// +optional
	ElasticIPs []string `json:"elasticIPs,omitempty"`
}

// EgressGatewayStatus defines the observed state of EgressGateway
type EgressGatewayStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`
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
	return *c.Spec.LogSeverity
}

func (c *EgressGateway) GetHealthPort() int32 {
	return *c.Spec.EgressGatewayFailureDetection.HealthPort
}

func (c *EgressGateway) GetHealthTimeoutDs() string {
	return *c.Spec.EgressGatewayFailureDetection.HealthTimeoutDataStore
}

func (c *EgressGateway) GetIPPools() string {
	return concatString(c.Spec.IPPools)
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
	interval := *c.Spec.EgressGatewayFailureDetection.ICMPProbes.Interval
	timeout := *c.Spec.EgressGatewayFailureDetection.ICMPProbes.Timeout
	return probeIPs, interval, timeout
}

func (c *EgressGateway) GetHTTPProbes() (string, string, string) {
	probeURLs := strings.Join(c.Spec.EgressGatewayFailureDetection.HTTPProbes.URLs, ",")
	interval := *c.Spec.EgressGatewayFailureDetection.HTTPProbes.Interval
	timeout := *c.Spec.EgressGatewayFailureDetection.HTTPProbes.Timeout
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
