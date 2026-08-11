// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// OpenTelemetryLogType represents the allowable log types for OpenTelemetry export.
// +kubebuilder:validation:Enum=Audit;DNS;Flows
type OpenTelemetryLogType string

const (
	OpenTelemetryAuditLog OpenTelemetryLogType = "Audit"
	OpenTelemetryDNSLog   OpenTelemetryLogType = "DNS"
	OpenTelemetryFlowLog  OpenTelemetryLogType = "Flows"
)

// OpenTelemetryLogs configures log export.
type OpenTelemetryLogs struct {
	// Types specifies which log types to export. Supported values: Audit, DNS, Flows.
	// +optional
	Types []OpenTelemetryLogType `json:"types,omitempty"`
}

// OpenTelemetryMetricsState is the option to enable or disable metrics export.
// +kubebuilder:validation:Enum=Enabled;Disabled
type OpenTelemetryMetricsState string

const (
	OpenTelemetryMetricsEnabled  OpenTelemetryMetricsState = "Enabled"
	OpenTelemetryMetricsDisabled OpenTelemetryMetricsState = "Disabled"
)

// OpenTelemetryMetrics configures metrics export.
type OpenTelemetryMetrics struct {
	// State specifies whether Calico component metrics are scraped and exported via OTLP.
	// Default: Disabled
	// +optional
	// +kubebuilder:default=Disabled
	State *OpenTelemetryMetricsState `json:"state,omitempty"`
}

// OpenTelemetryExporterProtocol specifies the OTLP transport protocol.
// +kubebuilder:validation:Enum=grpc;http
type OpenTelemetryExporterProtocol string

const (
	OpenTelemetryProtocolGRPC OpenTelemetryExporterProtocol = "grpc"
	OpenTelemetryProtocolHTTP OpenTelemetryExporterProtocol = "http"
)

// OpenTelemetryExporter defines an OTLP export endpoint.
type OpenTelemetryExporter struct {
	// Name is a unique identifier for this exporter. It keys the exporter in the
	// generated collector config and names the operator's copies of this
	// exporter's TLS material, so it is restricted to a DNS label: anything else
	// produces a ConfigMap or Secret key the API server rejects.
	// +required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`

	// Endpoint is the OTLP endpoint URL.
	// +required
	Endpoint string `json:"endpoint"`

	// Protocol specifies the OTLP transport protocol. Default: grpc.
	// +optional
	// +kubebuilder:default=grpc
	Protocol OpenTelemetryExporterProtocol `json:"protocol,omitempty"`

	// TLS configures transport security for this exporter. Backends differ in what
	// they require, so it is set per exporter rather than once for all of them.
	// When omitted, an https endpoint is verified against the system roots and an
	// http endpoint is sent in the clear.
	// +optional
	TLS *OpenTelemetryExporterTLS `json:"tls,omitempty"`

	// Auth configures how requests to this exporter are authenticated. Backends
	// differ here too: some take a bearer token, others a vendor-specific header.
	// +optional
	Auth *OpenTelemetryExporterAuth `json:"auth,omitempty"`
}

// OpenTelemetryExporterTLS configures transport security for a single exporter.
type OpenTelemetryExporterTLS struct {
	// CAConfigMapName names a ConfigMap in the tigera-operator namespace holding
	// the CA that signs this exporter's serving certificate, under a tls.crt key.
	// It is loaded alongside the system roots, so publicly-signed and
	// privately-signed endpoints can be mixed. A CA is not secret, so this follows
	// the ConfigMap convention already used for the syslog and Splunk CAs.
	// +optional
	CAConfigMapName string `json:"caConfigMapName,omitempty"`

	// ClientCertSecretName names a Secret in the tigera-operator namespace holding
	// the client keypair to present to this exporter, under tls.crt and tls.key.
	// Setting it turns on mutual TLS for this exporter alone, so backends that
	// require different client identities can each be given their own.
	// +optional
	ClientCertSecretName string `json:"clientCertSecretName,omitempty"`
}

// OpenTelemetryExporterAuth configures request authentication for a single exporter.
type OpenTelemetryExporterAuth struct {
	// Headers are attached to every request to this exporter. Values are read from
	// Secrets rather than set inline, so credentials are not stored in the
	// LogCollector resource.
	// +optional
	// +listType=map
	// +listMapKey=name
	Headers []OpenTelemetryExporterHeader `json:"headers,omitempty"`
}

// OpenTelemetryExporterHeader is a single request header and where its value comes from.
type OpenTelemetryExporterHeader struct {
	// Name is the header name, for example Authorization or DD-API-KEY.
	// +required
	Name string `json:"name"`

	// ValueFrom selects the Secret key holding this header's value.
	// +required
	ValueFrom OpenTelemetryHeaderValueSource `json:"valueFrom"`
}

// OpenTelemetryHeaderValueSource selects where a header value is read from.
type OpenTelemetryHeaderValueSource struct {
	// SecretKeyRef selects a key of a Secret in the tigera-operator namespace.
	// +required
	SecretKeyRef *corev1.SecretKeySelector `json:"secretKeyRef"`
}

// MutualTLS reports whether this exporter presents a client certificate.
func (e OpenTelemetryExporter) MutualTLS() bool {
	return e.TLS != nil && e.TLS.ClientCertSecretName != ""
}

// CAConfigMap returns the user-supplied CA ConfigMap for this exporter, if any.
func (e OpenTelemetryExporter) CAConfigMap() string {
	if e.TLS == nil {
		return ""
	}
	return e.TLS.CAConfigMapName
}

// ClientCertSecret returns the client keypair Secret for this exporter, if any.
func (e OpenTelemetryExporter) ClientCertSecret() string {
	if e.TLS == nil {
		return ""
	}
	return e.TLS.ClientCertSecretName
}

// AuthHeaders returns the configured auth headers for this exporter, if any.
func (e OpenTelemetryExporter) AuthHeaders() []OpenTelemetryExporterHeader {
	if e.Auth == nil {
		return nil
	}
	return e.Auth.Headers
}

// HeaderEnvName is the environment variable a header credential is passed to the
// collector in, and the key it is stored under. It lives here so validation and
// rendering derive it the same way; a mismatch would leave the collector
// referencing a variable that was never set.
func HeaderEnvName(exporter, header string) string {
	return "OTEL_EXPORTER_" + envSafe(exporter) + "_" + envSafe(header)
}

// envSafe maps a name onto the characters an environment variable allows.
// Exporter names are restricted to a DNS label, so they cannot collide here;
// header names are not, which is why Validate rejects any pair that does.
func envSafe(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

// OpenTelemetryCollectorStatefulSet is the configuration for the OpenTelemetry Collector StatefulSet.
type OpenTelemetryCollectorStatefulSet struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the StatefulSet.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`
	// Spec is the specification of the OpenTelemetry Collector StatefulSet.
	// +optional
	Spec *OpenTelemetryCollectorStatefulSetSpec `json:"spec,omitempty"`
}

// OpenTelemetryCollectorStatefulSetSpec defines configuration for the OpenTelemetry Collector StatefulSet.
type OpenTelemetryCollectorStatefulSetSpec struct {
	// MinReadySeconds is the minimum number of seconds for which a newly created StatefulSet pod should
	// be ready without any of its container crashing, for it to be considered available.
	// If specified, this overrides any minReadySeconds value that may be set on the OpenTelemetry Collector StatefulSet.
	// If omitted, the OpenTelemetry Collector StatefulSet will use its default value for minReadySeconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`

	// Template describes the OpenTelemetry Collector StatefulSet pod that will be created.
	// +optional
	Template *OpenTelemetryCollectorStatefulSetPodTemplateSpec `json:"template,omitempty"`
}

// OpenTelemetryCollectorStatefulSetPodTemplateSpec is the OpenTelemetry Collector StatefulSet's PodTemplateSpec.
type OpenTelemetryCollectorStatefulSetPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`
	// Spec is the OpenTelemetry Collector StatefulSet's PodSpec.
	// +optional
	Spec *OpenTelemetryCollectorStatefulSetPodSpec `json:"spec,omitempty"`
}

// OpenTelemetryCollectorStatefulSetPodSpec is the OpenTelemetry Collector StatefulSet's PodSpec.
type OpenTelemetryCollectorStatefulSetPodSpec struct {
	// Affinity is a group of affinity scheduling rules for the OpenTelemetry Collector pods.
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`
	// Containers is a list of OpenTelemetry Collector containers.
	// If specified, this overrides the specified OpenTelemetry Collector StatefulSet containers.
	// If omitted, the OpenTelemetry Collector StatefulSet will use its default values for its containers.
	// +optional
	Containers []OpenTelemetryCollectorStatefulSetContainer `json:"containers,omitempty"`
	// NodeSelector gives more control over the nodes where the OpenTelemetry Collector pods will run on.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// TopologySpreadConstraints describes how a group of pods ought to spread across topology
	// domains. Scheduler will schedule pods in a way which abides by the constraints.
	// All topologySpreadConstraints are ANDed.
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// Tolerations is the OpenTelemetry Collector pod's tolerations.
	// If specified, this overrides any tolerations that may be set on the OpenTelemetry Collector StatefulSet.
	// If omitted, the OpenTelemetry Collector StatefulSet will use its default value for tolerations.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations"`
	// PriorityClassName allows to specify a PriorityClass resource to be used.
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`
}

// OpenTelemetryCollectorStatefulSetContainer is an OpenTelemetry Collector StatefulSet container.
type OpenTelemetryCollectorStatefulSetContainer struct {
	// Name is an enum which identifies the OpenTelemetry Collector StatefulSet container by name.
	// Supported values are: otel-collector
	// +kubebuilder:validation:Enum=otel-collector
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named OpenTelemetry Collector StatefulSet container's resources.
	// If omitted, the OpenTelemetry Collector StatefulSet will use its default value for this container's resources.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// ReadinessProbe allows customization of the readiness probe timing parameters.
	// The probe handler is set by the operator and cannot be overridden.
	// +optional
	ReadinessProbe *ProbeOverride `json:"readinessProbe,omitempty"`

	// LivenessProbe allows customization of the liveness probe timing parameters.
	// The probe handler is set by the operator and cannot be overridden.
	// +optional
	LivenessProbe *ProbeOverride `json:"livenessProbe,omitempty"`
}
