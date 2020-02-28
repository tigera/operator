package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	LogStorageStatusDegraded = "Degraded"
	LogStorageStatusReady    = "Ready"

	ElasticsearchHashAnnotation = "hash.operator.tigera.io/elasticsearch"
	KibanaHashAnnotation        = "hash.operator.tigera.io/kibana"

	DefaultShards = 5
)

// LogStorageStatus defines the observed state of Tigera flow and DNS log storage.
// +k8s:openapi-gen=true
type LogStorageStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// ElasticsearchHash represents the current revision and configuration of the installed Elasticsearch cluster. This
	// is an opaque string which can be monitored for changes to perform actions when Elasticsearch is modified.
	ElasticsearchHash string `json:"elasticsearchHash,omitempty"`

	// KibanaHash represents the current revision and configuration of the installed Kibana dashboard. This
	// is an opaque string which can be monitored for changes to perform actions when Kibana is modified.
	KibanaHash string `json:"kibanaHash,omitempty"`
}

// LogStorageSpec defines the desired state of Tigera flow and DNS log storage.
// +k8s:openapi-gen=true
type LogStorageSpec struct {
	// Nodes defines the configuration for a set of identical Elasticsearch cluster nodes, each of type master, data, and ingest.
	Nodes *Nodes `json:"nodes,omitempty"`

	// Index defines the configuration for the indices in the Elasticsearch cluster.
	// +optional
	Indices *Indices `json:"indices,omitempty"`

	// Retention defines how long data is retained in the Elasticsearch cluster before it is cleared.
	// +optional
	Retention *Retention `json:"retention,omitempty"`
}

// Nodes defines the configuration for a set of identical Elasticsearch cluster nodes, each of type master, data, and ingest.
type Nodes struct {
	// Count defines the number of nodes in the Elasticsearch cluster.
	Count int64 `json:"count,omitempty"`

	// ResourceRequirements defines the resource limits and requirements for the Elasticsearch cluster.
	// +optional
	ResourceRequirements *corev1.ResourceRequirements `json:"resourceRequirements,omitempty"`
}

// Indices defines the configuration for the indices in an Elasticsearch cluster.
type Indices struct {
	// Replicas defines how many replicas each index will have. See https://www.elastic.co/guide/en/elasticsearch/reference/current/scalability.html
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`
}

// Retention defines how long data is retained in an Elasticsearch cluster before it is cleared.
type Retention struct {
	// Flows configures the retention period for flow logs, in days.  Logs written on a day that started at least this long ago
	// are removed.  To keep logs for at least x days, use a retention period of x+1.
	// Default: 8
	// +optional
	Flows *int32 `json:"flows"`

	// AuditReports configures the retention period for audit logs, in days.  Logs written on a day that started at least this long ago are
	// removed.  To keep logs for at least x days, use a retention period of x+1.
	// Default: 367
	// +optional
	AuditReports *int32 `json:"auditReports"`

	// Snapshots configures the retention period for snapshots, in days. Snapshots are periodic captures
	// of resources which along with audit events are used to generate reports.
	// Consult the Compliance Reporting documentation for more details on snapshots.
	// Logs written on a day that started at least this long ago are
	// removed.  To keep logs for at least x days, use a retention period of x+1.
	// Default: 367
	// +optional
	Snapshots *int32 `json:"snapshots"`

	// ComplianceReports configures the retention period for compliance reports, in days. Reports are output
	// from the analysis of the system state and audit events for compliance reporting.
	// Consult the Compliance Reporting documentation for more details on reports.
	// Logs written on a day that started at least this long ago are
	// removed.  To keep logs for at least x days, use a retention period of x+1.
	// Default: 367
	// +optional
	ComplianceReports *int32 `json:"complianceReports"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +genclient
// +genclient:nonNamespaced

// LogStorage installs the components required for Tigera flow and DNS log storage. At most one instance
// of this resource is supported. It must be named "tigera-secure". When created, this installs an Elasticsearch cluster for use by
// Calico Enterprise.
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type LogStorage struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for Tigera log storage.
	Spec LogStorageSpec `json:"spec,omitempty"`

	// Most recently observed state for Tigera log storage.
	Status LogStorageStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LogStorageList contains a list of LogStorage
type LogStorageList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []LogStorage `json:"items"`
}

func (ls LogStorage) Replicas() int {
	return int(*ls.Spec.Indices.Replicas)
}

func (ls LogStorage) Shards() int {
	return DefaultShards
}

func init() {
	SchemeBuilder.Register(&LogStorage{}, &LogStorageList{})
}
