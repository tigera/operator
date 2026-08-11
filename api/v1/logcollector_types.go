// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// LogCollectorSpec defines the desired state of Tigera flow, audit, and DNS log collection.
type LogCollectorSpec struct {
	// Configuration for exporting flow, audit, and DNS logs to external storage.
	// +optional
	AdditionalStores *AdditionalLogStoreSpec `json:"additionalStores,omitempty"`

	// Configuration for importing audit logs from managed kubernetes cluster log sources.
	// +optional
	AdditionalSources *AdditionalLogSourceSpec `json:"additionalSources,omitempty"`

	// Configuration for enabling/disabling process path collection in flowlogs.
	// If Enabled, this feature sets hostPID to true in order to read process cmdline.
	// Default: Enabled
	// +optional
	// +kubebuilder:validation:Enum=Enabled;Disabled
	CollectProcessPath *CollectProcessPathOption `json:"collectProcessPath,omitempty"`

	// If running as a multi-tenant management cluster, the namespace in which
	// the management cluster's tenant services are running.
	// +optional
	MultiTenantManagementClusterNamespace string `json:"multiTenantManagementClusterNamespace,omitempty"`

	// FluentdDaemonSet configures the calico-fluent-bit DaemonSet (deprecated alias).
	//
	// Deprecated: use CalicoFluentBitDaemonSet instead. This field is retained
	// as an alias for one release during the Fluentd → Fluent Bit migration;
	// when both are set, CalicoFluentBitDaemonSet takes precedence.
	// +optional
	FluentdDaemonSet *FluentBitDaemonSet `json:"fluentdDaemonSet,omitempty"`

	// CalicoFluentBitDaemonSet configures the calico-fluent-bit DaemonSet, the
	// Fluent Bit replacement for the Fluentd DaemonSet. Pod-template override
	// semantics are unchanged from the deprecated FluentdDaemonSet field.
	// +optional
	CalicoFluentBitDaemonSet *FluentBitDaemonSet `json:"calicoFluentBitDaemonSet,omitempty"`

	// EKSLogForwarderDeployment configures the EKSLogForwarderDeployment Deployment.
	// +optional
	EKSLogForwarderDeployment *EKSLogForwarderDeployment `json:"eksLogForwarderDeployment,omitempty"`

	// OpenTelemetry configures OpenTelemetry export of logs and metrics via
	// OTLP. It is not a passthrough for OpenTelemetry Collector configuration:
	// the fields here describe what Calico Enterprise exports and where, and
	// the operator translates that into a Collector deployment.
	//
	// Unlike AdditionalStores entries (S3, Syslog, Splunk), which point at
	// external systems, that Collector is operator-managed infrastructure
	// (StatefulSet, ConfigMap, RBAC, certs) with its own lifecycle, so this
	// lives at the top level rather than under AdditionalStores.
	// +optional
	OpenTelemetry *OpenTelemetrySpec `json:"openTelemetry,omitempty"`
}

type CollectProcessPathOption string

const (
	CollectProcessPathEnable  CollectProcessPathOption = "Enabled"
	CollectProcessPathDisable CollectProcessPathOption = "Disabled"
)

// EncryptionOption specifies the traffic encryption mode when connecting to a Syslog server.
//
// One of: None, TLS
type EncryptionOption string

const (
	EncryptionNone EncryptionOption = "None"
	EncryptionTLS  EncryptionOption = "TLS"
)

type AdditionalLogStoreSpec struct {
	// If specified, enables exporting of flow, audit, and DNS logs to Amazon S3 storage.
	// +optional
	S3 *S3StoreSpec `json:"s3,omitempty"`
	// If specified, enables exporting of flow, audit, and DNS logs to syslog.
	// +optional
	Syslog *SyslogStoreSpec `json:"syslog,omitempty"`
	// If specified, enables exporting of flow, audit, and DNS logs to splunk.
	// +optional
	Splunk *SplunkStoreSpec `json:"splunk,omitempty"`
}

type AdditionalLogSourceSpec struct {
	// If specified with EKS Provider in Installation, enables fetching EKS
	// audit logs.
	// +optional
	EksCloudwatchLog *EksCloudwatchLogsSpec `json:"eksCloudwatchLog,omitempty"`
}

// HostScope determines the set of hosts that forward logs to a given store.
// +kubebuilder:default=All
// +kubebuilder:validation:Enum=All;NonClusterOnly
// +optional
type HostScope string

const (
	HostScopeAll            HostScope = "All"
	HostScopeNonClusterOnly HostScope = "NonClusterOnly"
)

// S3StoreSpec defines configuration for exporting logs to Amazon S3.
// +k8s:openapi-gen=true
type S3StoreSpec struct {
	// AWS Region of the S3 bucket
	Region string `json:"region"`

	// Name of the S3 bucket to send logs
	BucketName string `json:"bucketName"`

	// Path in the S3 bucket where to send logs
	BucketPath string `json:"bucketPath"`

	// The set of hosts that will forward their logs to this store.
	// +optional
	HostScope *HostScope `json:"hostScope,omitempty"`
}

// SyslogLogType represents the allowable log types for syslog.
// Allowable values are Audit, DNS, Flows and IDSEvents.
// * Audit corresponds to audit logs for both Kubernetes resources and Enterprise custom resources.
// * DNS corresponds to DNS logs generated by Calico node.
// * Flows corresponds to flow logs generated by Calico node.
// * IDSEvents corresponds to event logs for the intrusion detection system (anomaly detection, suspicious IPs, suspicious domains and global alerts).
// +kubebuilder:validation:Enum=Audit;DNS;Flows;IDSEvents
type SyslogLogType string

const (
	SyslogLogAudit     SyslogLogType = "Audit"
	SyslogLogDNS       SyslogLogType = "DNS"
	SyslogLogFlows     SyslogLogType = "Flows"
	SyslogLogL7        SyslogLogType = "L7"
	SyslogLogIDSEvents SyslogLogType = "IDSEvents"
)

var SyslogLogTypes []SyslogLogType = []SyslogLogType{
	SyslogLogAudit,
	SyslogLogDNS,
	SyslogLogFlows,
	SyslogLogL7,
	SyslogLogIDSEvents,
}

var SyslogLogTypesString []string = []string{
	SyslogLogAudit.String(),
	SyslogLogDNS.String(),
	SyslogLogFlows.String(),
	SyslogLogL7.String(),
	SyslogLogIDSEvents.String(),
}

func (cp SyslogLogType) String() string {
	return string(cp)
}

// SyslogStoreSpec defines configuration for exporting logs to syslog.
type SyslogStoreSpec struct {
	// Location of the syslog server. example: tcp://1.2.3.4:601
	// Only the tcp and udp schemes are supported; TLS is selected via the
	// Encryption field rather than the scheme.
	// +kubebuilder:validation:Pattern=`^(tcp|udp)://.+$`
	Endpoint string `json:"endpoint"`

	// PacketSize defines the maximum size, in bytes, of messages sent to syslog;
	// messages larger than this are truncated. When unset, the syslog output's
	// own default for the RFC5424 format the operator renders applies (2048
	// bytes). Set this only if you notice long logs being truncated.
	// +optional
	PacketSize *int32 `json:"packetSize,omitempty"`

	// If no values are provided, the list will be updated to include log types Audit, DNS and Flows.
	// Default: Audit, DNS, Flows
	LogTypes []SyslogLogType `json:"logTypes"`

	// Encryption configures traffic encryption to the Syslog server.
	// Default: None
	// +optional
	// +kubebuilder:validation:Enum=None;TLS
	Encryption EncryptionOption `json:"encryption,omitempty"`

	// The set of hosts that will forward their logs to this store.
	// +optional
	HostScope *HostScope `json:"hostScope,omitempty"`
}

// SplunkStoreSpec defines configuration for exporting logs to splunk.
type SplunkStoreSpec struct {
	// Location for splunk's http event collector end point. example `https://1.2.3.4:8088`
	Endpoint string `json:"endpoint"`

	// The set of hosts that will forward their logs to this store
	// +optional
	HostScope *HostScope `json:"hostScope,omitempty"`
}

// EksConfigSpec defines configuration for fetching EKS audit logs.
type EksCloudwatchLogsSpec struct {
	// AWS Region EKS cluster is hosted in.
	Region string `json:"region"`

	// Cloudwatch log-group name containing EKS audit logs.
	GroupName string `json:"groupName"`

	// Prefix of Cloudwatch log stream containing EKS audit logs in the log-group.
	// Default: kube-apiserver-audit-
	// +optional
	StreamPrefix string `json:"streamPrefix,omitempty"`

	// Cloudwatch audit logs fetching interval in seconds.
	// Default: 60
	// +optional
	FetchInterval int32 `json:"fetchInterval,omitempty"`
}

// LogCollectorStatus defines the observed state of Tigera flow and DNS log collection
type LogCollectorStatus struct {
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

// LogCollector installs the components required for Tigera flow and DNS log collection. At most one instance
// of this resource is supported. It must be named "tigera-secure". When created, this installs fluent-bit on all nodes
// configured to collect Tigera log data and export it to Tigera's Elasticsearch cluster as well as any additionally configured destinations.
//
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'tigera-secure'",message="resource name must be 'tigera-secure'"
type LogCollector struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for Tigera log collection.
	Spec LogCollectorSpec `json:"spec,omitempty"`
	// Most recently observed state for Tigera log collection.
	Status LogCollectorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// LogCollectorList contains a list of LogCollector
type LogCollectorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []LogCollector `json:"items"`
}

// OpenTelemetrySpec defines the desired state of the OpenTelemetry Collector.
type OpenTelemetrySpec struct {
	// Logs configures which log types are exported via OTLP.
	// +optional
	Logs *OpenTelemetryLogs `json:"logs,omitempty"`

	// Metrics configures whether Calico component metrics are exported via OTLP.
	// +optional
	Metrics *OpenTelemetryMetrics `json:"metrics,omitempty"`

	// Exporters configures the OTLP export endpoints. At least one is required:
	// every rendered pipeline exports to all of them, and the collector refuses
	// to start with an exporter-less pipeline. Names key the exporters in the
	// generated config, so they are merged and deduplicated by name.
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +listType=map
	// +listMapKey=name
	Exporters []OpenTelemetryExporter `json:"exporters,omitempty"`

	// OpenTelemetryCollectorStatefulSet configures the OpenTelemetry Collector StatefulSet.
	// +optional
	OpenTelemetryCollectorStatefulSet *OpenTelemetryCollectorStatefulSet `json:"openTelemetryCollectorStatefulSet,omitempty"`
}

func (s *OpenTelemetrySpec) HasLogs() bool {
	return s != nil && s.Logs != nil && len(s.Logs.Types) > 0
}

func (s *OpenTelemetrySpec) MetricsEnabled() bool {
	return s != nil && s.Metrics != nil && s.Metrics.State != nil &&
		*s.Metrics.State == OpenTelemetryMetricsEnabled
}

func (s *OpenTelemetrySpec) HasDataSources() bool {
	return s.HasLogs() || s.MetricsEnabled()
}

// Validate rejects the specs that render a config the collector refuses to start
// from. otelcol validates most of these itself, but only at boot, by which point
// the failure is an opaque crash-loop. It lives here rather than in the otel
// controller so every controller that has to decide whether the collector is
// deployable answers the question the same way.
func (s *OpenTelemetrySpec) Validate() error {
	// Every pipeline we render fans out to all exporters, so with none configured
	// each pipeline would be exporter-less.
	if len(s.Exporters) == 0 {
		return fmt.Errorf("at least one exporter must be configured in spec.openTelemetry.exporters")
	}
	// No log types and no metrics means no pipelines at all.
	if !s.HasDataSources() {
		return fmt.Errorf("at least one data source must be enabled: set spec.openTelemetry.logs.types or spec.openTelemetry.metrics.state")
	}
	// Names key the exporters in the rendered config, so duplicates would emit the
	// same mapping key twice. +listMapKey=name normally stops this at the API
	// server; this guards the case where the CRD is out of date.
	seen := make(map[string]struct{}, len(s.Exporters))
	for _, exp := range s.Exporters {
		if _, dup := seen[exp.Name]; dup {
			return fmt.Errorf("exporter names must be unique in spec.openTelemetry.exporters: %q is duplicated", exp.Name)
		}
		seen[exp.Name] = struct{}{}
		// TLS material on a plaintext endpoint is silently ignored by the collector,
		// so reject it rather than letting the user believe it took effect.
		if plaintext := strings.HasPrefix(exp.Endpoint, "http://"); plaintext && exp.TLS != nil {
			if exp.TLS.ClientCertSecretName != "" {
				return fmt.Errorf("exporter %q sets tls.clientCertSecretName on an http:// endpoint; the client cert is only sent over TLS", exp.Name)
			}
			if exp.TLS.CAConfigMapName != "" {
				return fmt.Errorf("exporter %q sets tls.caConfigMapName on an http:// endpoint; there is no server certificate to verify", exp.Name)
			}
		}
		for _, h := range exp.AuthHeaders() {
			if h.ValueFrom.SecretKeyRef == nil || h.ValueFrom.SecretKeyRef.Name == "" || h.ValueFrom.SecretKeyRef.Key == "" {
				return fmt.Errorf("exporter %q header %q must set valueFrom.secretKeyRef.name and .key", exp.Name, h.Name)
			}
		}
	}
	return nil
}

// Deployable reports whether the operator will actually run a collector for this
// LogCollector: export configured, licensed, and a valid spec. The monitor
// controller renders the collector's ServiceMonitor and the Prometheus egress
// rule that reaches it, so it has to agree with the otel controller exactly.
func (s *OpenTelemetrySpec) Deployable(featureActive bool) bool {
	return s != nil && featureActive && s.Validate() == nil
}

func init() {
	SchemeBuilder.Register(&LogCollector{}, &LogCollectorList{})
}
