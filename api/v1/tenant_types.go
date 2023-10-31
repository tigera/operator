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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DataType represent the type of data stored
// +kubebuilder:validation:Enum=Alerts;AuditLogs;BGPLogs;ComplianceBenchmarks;ComplianceReports;ComplianceSnapshots;DNSLogs;FlowLogs;L7Logs;RuntimeReports;ThreatFeedsDomainSet;ThreatFeedsIPSet;WAFLogs
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
	DataTypeThreatFeedsDomainSet DataType = "ThreatFeedsDomainSet"
	DataTypeThreatFeedsIPSet     DataType = "ThreatFeedsIPSet"
	DataTypeWAFLogs              DataType = "WAFLogs"
)

// DataTypes is a set of all data types stored mapped to
// their corresponding environment variables
var DataTypes = map[DataType]string{
	DataTypeAlerts:               "ELASTIC_ALERTS_BASE_INDEX_NAME",
	DataTypeAuditLogs:            "ELASTIC_AUDIT_LOGS_BASE_INDEX_NAME",
	DataTypeBGPLogs:              "ELASTIC_BGP_LOGS_BASE_INDEX_NAME",
	DataTypeComplianceBenchmarks: "ELASTIC_COMPLIANCE_BENCHMARKS_BASE_INDEX_NAME",
	DataTypeComplianceReports:    "ELASTIC_COMPLIANCE_REPORTS_BASE_INDEX_NAME",
	DataTypeComplianceSnapshots:  "ELASTIC_COMPLIANCE_SNAPSHOTS_BASE_INDEX_NAME",
	DataTypeDNSLogs:              "ELASTIC_DNS_LOGS_BASE_INDEX_NAME",
	DataTypeFlowLogs:             "ELASTIC_FLOW_LOGS_BASE_INDEX_NAME",
	DataTypeL7Logs:               "ELASTIC_L7_LOGS_BASE_INDEX_NAME",
	DataTypeRuntimeReports:       "ELASTIC_RUNTIME_REPORTS_BASE_INDEX_NAME",
	DataTypeThreatFeedsDomainSet: "ELASTIC_THREAT_FEEDS_DOMAIN_SET_BASE_INDEX_NAME",
	DataTypeThreatFeedsIPSet:     "ELASTIC_THREAT_FEEDS_IP_SET_BASE_INDEX_NAME",
	DataTypeWAFLogs:              "ELASTIC_WAF_LOGS_BASE_INDEX_NAME",
}

type TenantSpec struct {
	// ID is the unique identifier for this tenant.
	// +required
	ID string `json:"id,omitempty"`

	// Indices defines the how to store a tenant's data
	Indices []Index `json:"indices"`
}

// Index defines how to store a tenant's data
type Index struct {
	// BaseIndexName defines the name of the index
	// that will be used to store data (this name
	// excludes the numerical identifier suffix)
	BaseIndexName string `json:"baseIndexName"`

	// DataType represents the type of data stored in the defined index
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
	return corev1.EnvVar{Name: i.DataType.IndexEnvName(), Value: i.BaseIndexName}
}

func (t DataType) IndexEnvName() string {
	envName, ok := DataTypes[t]
	if !ok {
		panic(fmt.Sprintf("Unexpected data type %s", t))
	}

	return envName
}
