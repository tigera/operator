package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:openapi-gen=true
type TigeraStatusSpec struct {
}

// TigeraStatusStatus defines the observed state of TigeraStatus
// +k8s:openapi-gen=true
type TigeraStatusStatus struct {
	Conditions []TigeraStatusCondition `json:"conditions"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TigeraStatus is the Schema for the tigerastatuses API
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type TigeraStatus struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TigeraStatusSpec   `json:"spec,omitempty"`
	Status TigeraStatusStatus `json:"status,omitempty"`
}

type ConditionStatus string

const (
	ConditionTrue    ConditionStatus = "True"
	ConditionFalse   ConditionStatus = "False"
	ConditionUnknown ConditionStatus = "Unknown"
)

// StatusConditionType is a type of operator status.
type StatusConditionType string

const (
	// Available indicates that the installed component is healthy.
	ComponentAvailable StatusConditionType = "Available"

	// Progressing means that the component is in the process of being installed or upgraded.
	ComponentProgressing StatusConditionType = "Progressing"

	// Degraded means the component is not operating as desired and user action is required.
	ComponentDegraded StatusConditionType = "Degraded"
)

// +k8s:deepcopy-gen=true
type TigeraStatusCondition struct {
	Type               StatusConditionType `json:"type"`
	Status             ConditionStatus     `json:"status"`
	LastTransitionTime metav1.Time         `json:"lastTransitionTime"`
	Reason             string              `json:"reason,omitempty"`
	Message            string              `json:"message,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TigeraStatusList contains a list of TigeraStatus
type TigeraStatusList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TigeraStatus `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TigeraStatus{}, &TigeraStatusList{})
}
