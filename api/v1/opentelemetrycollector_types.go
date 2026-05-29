// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OpenTelemetryCollectorSpec defines the desired state of the OpenTelemetry Collector.
type OpenTelemetryCollectorSpec struct {
	// Logs configures which log types are exported via OTLP.
	// +optional
	Logs *OTelLogs `json:"logs,omitempty"`

	// Metrics configures whether Calico component metrics are exported via OTLP.
	// +optional
	Metrics *OTelMetrics `json:"metrics,omitempty"`

	// Exporters configures the OTLP export endpoints.
	// +optional
	Exporters []OTelExporter `json:"exporters,omitempty"`

	// OpenTelemetryCollectorDeployment configures the OTel Collector Deployment.
	// +optional
	OpenTelemetryCollectorDeployment *OpenTelemetryCollectorDeployment `json:"openTelemetryCollectorDeployment,omitempty"`
}

// OTelLogType represents the allowable log types for OTel export.
// +kubebuilder:validation:Enum=Audit;DNS;Flows
type OTelLogType string

const (
	OTelLogAudit OTelLogType = "Audit"
	OTelLogDNS   OTelLogType = "DNS"
	OTelLogFlows OTelLogType = "Flows"
)

// OTelLogs configures log export.
type OTelLogs struct {
	// Types specifies which log types to export. Supported values: Audit, DNS, Flows.
	// +optional
	Types []OTelLogType `json:"types,omitempty"`
}

// OTelMetricsEnabled is the option to enable or disable metrics export.
// +kubebuilder:validation:Enum=Enabled;Disabled
type OTelMetricsEnabled string

const (
	OTelMetricsEnable  OTelMetricsEnabled = "Enabled"
	OTelMetricsDisable OTelMetricsEnabled = "Disabled"
)

// OTelMetrics configures metrics export.
type OTelMetrics struct {
	// Enabled specifies whether to scrape and export Calico component metrics via OTLP.
	// Default: Disabled
	// +optional
	Enabled *OTelMetricsEnabled `json:"enabled,omitempty"`
}

// OTelExporterProtocol specifies the OTLP transport protocol.
// +kubebuilder:validation:Enum=grpc;http
type OTelExporterProtocol string

const (
	OTelProtocolGRPC OTelExporterProtocol = "grpc"
	OTelProtocolHTTP OTelExporterProtocol = "http"
)

// OTelExporter defines an OTLP export endpoint.
type OTelExporter struct {
	// Name is a unique identifier for this exporter.
	Name string `json:"name"`

	// Endpoint is the OTLP endpoint URL.
	Endpoint string `json:"endpoint"`

	// Protocol specifies the OTLP transport protocol. Default: grpc.
	// +optional
	// +kubebuilder:default=grpc
	Protocol OTelExporterProtocol `json:"protocol,omitempty"`
}

// OpenTelemetryCollectorStatus defines the observed state of the OpenTelemetry Collector.
type OpenTelemetryCollectorStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// OpenTelemetryCollector installs the OpenTelemetry Collector for exporting Calico logs and metrics via OTLP.
// At most one instance of this resource is supported. It must be named "tigera-secure".
//
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'tigera-secure'",message="resource name must be 'tigera-secure'"
type OpenTelemetryCollector struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenTelemetryCollectorSpec   `json:"spec,omitempty"`
	Status OpenTelemetryCollectorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenTelemetryCollectorList contains a list of OpenTelemetryCollector
type OpenTelemetryCollectorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenTelemetryCollector `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenTelemetryCollector{}, &OpenTelemetryCollectorList{})
}
