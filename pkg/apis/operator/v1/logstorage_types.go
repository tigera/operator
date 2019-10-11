package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	LogStorageStatusDegraded = "Degraded"
	LogStorageStatusReady    = "Ready"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// LogStorageStatus defines the observed state of LogStorage
// +k8s:openapi-gen=true
type LogStorageStatus struct {
	// State indicates the state of the deployment by the LogStorage controller
	State string `json:"state,omitempty"`
}

// LogStorageSpec defines the desired state of LogStorage
// +k8s:openapi-gen=true
type LogStorageSpec struct {
	// Node defines the configuration for the elasticsearch cluster nodes. The nodes created will all be of type master,
	// data, and ingest, and the number of nodes, where their data is stored, and what the resource requirements are
	// configured here
	Nodes *Nodes `json:"nodes,omitempty"`
	// Index defines the configuration for the indices in the elasticsearch cluster
	Indices *Indices `json:"indices,omitempty"`
	// Retention defines how long data is retained in the elasticsearch cluster before it is cleared.
	// +optional
	Retention *Retention `json:"retention,omitempty"`
}

type Nodes struct {
	// Count defines the number of nodes that the elasticsearch cluster will have
	Count int64 `json:"count,omitempty"`
	// ResourceRequirements represents the resource limits and requirements for the elasticsearch cluster (i.e. cpu, size)
	ResourceRequirements *corev1.ResourceRequirements `json:"resourceRequirements,omitempty"`
}

type Indices struct {
	// Replicas defines how many replicas each index will have. See https://www.elastic.co/guide/en/elasticsearch/reference/current/scalability.html
	Replicas int64 `json:"replicas"`
}

type Retention struct {
	// Flows configures the retention period for flow logs, in days.  Logs written on a day that started at least this long ago
	// are removed.  To keep logs for at least x days, use a retention period of x+1.
	// Default: 8
	// +optional
	FlowRetention *int32 `json:"flows"`
	// AuditReports configures the retention period for audit logs, in days.  Logs written on a day that started at least this long ago are
	// removed.  To keep logs for at least x days, use a retention period of x+1.
	// Default: 367
	// +optional
	AuditReportRetention *int32 `json:"auditReports"`
	// Snapshots configures the retention period for snapshots, in days. Snapshots are periodic captures
	// of resources which along with audit events are used to generate reports.
	// Consult the Compliance Reporting documentation for more details on snapshots.
	// Logs written on a day that started at least this long ago are
	// removed.  To keep logs for at least x days, use a retention period of x+1.
	// Default: 367
	// +optional
	SnapshotRetention *int32 `json:"snapshots"`
	// ComplianceReports configures the retention period for compliance reports, in days. Reports are output
	// from the analysis of the system state and audit events for compliance reporting.
	// Consult the Compliance Reporting documentation for more details on reports.
	// Logs written on a day that started at least this long ago are
	// removed.  To keep logs for at least x days, use a retention period of x+1.
	// Default: 367
	// +optional
	ComplianceReportRetention *int32 `json:"complianceReports"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LogStorage is the Schema for the logstorages  API
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type LogStorage struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   LogStorageSpec   `json:"spec,omitempty"`
	Status LogStorageStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LogStorageList contains a list of LogStorage
type LogStorageList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []LogStorage `json:"items"`
}

func init() {
	SchemeBuilder.Register(&LogStorage{}, &LogStorageList{})
}
