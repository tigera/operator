// Copyright (c) 2023 Tigera, Inc. All rights reserved.
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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type DataType string

const (
	DataTypeAlerts               DataType = "Alerts"
	DataTypeAuditLogs            DataType = "AuditLogs"
	DataTypeBGPLogs              DataType = "BGPLogs"
	DataTypeComplianceBenchmarks DataType = "ComplianceBenchmarks"
	DataTypeComplianceReports    DataType = "ComplianceReports"
	DataTypeComplianceSnapshots  DataType = "ComplianceSnapshots"
	DataTypeDNSLogs              DataType = "DNSLogs"
	DataTypeFlowLogs             DataType = "FlowLogs"
	DataTypeL7Logs               DataType = "L7Logs"
	DataTypeRuntimeReports       DataType = "RuntimeReports"
	DataTypeThreadFeedsDomainSet DataType = "ThreadFeedsDomainSet"
	DataTypeThreadFeedsIPSet     DataType = "ThreadFeedsIPSet"
	DataTypeWAFLogs              DataType = "WAFLogs"
)

type TenantSpec struct {
	// ID is the unique identifier for this tenant.
	// +required
	ID string `json:"id,omitempty"`

	// Indices defines the how to store a tenant's data
	// +kubebuilder:validation:UniqueItems:=true
	Indices []Index `json:"indices"`
}

// Index defines how to store a tenant's data
type Index struct {
	// IndexName defines the name of the index
	// that will be used to store data (this name
	// excludes the numerical identifier suffix)
	IndexName string `json:"indexName"`

	// DataType represents the type of data stored
	// in the defined index
	// +kubebuilder:validation:Enum=Alerts;AuditLogs;BGPLogs;ComplianceBenchmarks;ComplianceReports;ComplianceSnapshots;DNSLogs;FlowLogs;L7Logs;RuntimeReports;ThreatFeedsDomainSet;ThreadFeedsIPSet;WAFLogs
	DataType DataType `json:"dataType"`
}

type TenantStatus struct{}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Tenant is the Schema for the tenants API
type Tenant struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TenantSpec   `json:"spec,omitempty"`
	Status TenantStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TenantList contains a list of Tenant
type TenantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Tenant `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Tenant{}, &TenantList{})
}

func (i *Index) EnvVar() corev1.EnvVar {
	return corev1.EnvVar{Name: i.DataType.IndexEnvName(), Value: i.IndexName}
}

func (t DataType) IndexEnvName() string {
	switch t {
	case DataTypeAlerts:
		return "ELASTIC_ALERTS_INDEX_NAME"
	case DataTypeAuditLogs:
		return "ELASTIC_AUDIT_LOGS_INDEX_NAME"
	case DataTypeBGPLogs:
		return "ELASTIC_BGP_LOGS_INDEX_NAME"
	case DataTypeComplianceBenchmarks:
		return "ELASTIC_COMPLIANCE_BENCHMARKS_INDEX_NAME"
	case DataTypeComplianceReports:
		return "ELASTIC_COMPLIANCE_REPORTS_INDEX_NAME"
	case DataTypeComplianceSnapshots:
		return "ELASTIC_COMPLIANCE_SNAPSHOTS_INDEX_NAME"
	case DataTypeDNSLogs:
		return "ELASTIC_DNS_LOGS_INDEX_NAME"
	case DataTypeFlowLogs:
		return "ELASTIC_FLOW_LOGS_INDEX_NAME"
	case DataTypeL7Logs:
		return "ELASTIC_L7_LOGS_INDEX_NAME"
	case DataTypeRuntimeReports:
		return "ELASTIC_RUNTIME_REPORTS_INDEX_NAME"
	case DataTypeThreadFeedsIPSet:
		return "ELASTIC_THREAT_FEEDS_IP_SET_INDEX_NAME"
	case DataTypeThreadFeedsDomainSet:
		return "ELASTIC_THREAT_FEEDS_DOMAIN_SET_INDEX_NAME"
	case DataTypeWAFLogs:
		return "ELASTIC_WAF_LOG_INDEX_NAME"
	default:
		panic("Unexpected data type")
	}
}
