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
	// Conditions represents the latest observed set of conditions for this component. A component may be one or more of
	// Available, Progressing, or Degraded.
	Conditions []TigeraStatusCondition `json:"conditions"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +genclient
// +genclient:nonNamespaced

// TigeraStatus represents the most recently observed status for Calico or a Calico Enterprise functional area.
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Available",type="string",JSONPath=".status.conditions[?(@.type=="Available")].status",description="Whether the component running and stable."
// +kubebuilder:printcolumn:name="Progressing",type="string",JSONPath=".status.conditions[?(@.type=="Progressing")].status",description="Whether the component is processing changes."
// +kubebuilder:printcolumn:name="Degraded",type="string",JSONPath=".status.conditions[?(@.type=="Degraded")].status",description="Whether the component is degraded."
// +kubebuilder:printcolumn:name="Since",type="date",JSONPath=".status.conditions[?(@.type=="Available")].lastTransitionTime",description="The time the component's Available status last changed."
type TigeraStatus struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TigeraStatusSpec   `json:"spec,omitempty"`
	Status TigeraStatusStatus `json:"status,omitempty"`
}

// ConditionStatus represents the status of a particular condition. A condition may be one of: True, False, Unknown.
type ConditionStatus string

const (
	ConditionTrue    ConditionStatus = "True"
	ConditionFalse   ConditionStatus = "False"
	ConditionUnknown ConditionStatus = "Unknown"
)

// StatusConditionType is a type of condition that may apply to a particular component.
type StatusConditionType string

const (
	// Available indicates that the component is healthy.
	ComponentAvailable StatusConditionType = "Available"

	// Progressing means that the component is in the process of being installed or upgraded.
	ComponentProgressing StatusConditionType = "Progressing"

	// Degraded means the component is not operating as desired and user action is required.
	ComponentDegraded StatusConditionType = "Degraded"
)

// TigeraStatusCondition represents a condition attached to a particular component.
// +k8s:deepcopy-gen=true
type TigeraStatusCondition struct {
	// The type of condition. May be Available, Progressing, or Degraded.
	Type StatusConditionType `json:"type"`

	// The status of the condition. May be True, False, or Unknown.
	Status ConditionStatus `json:"status"`

	// The timestamp representing the start time for the current status.
	LastTransitionTime metav1.Time `json:"lastTransitionTime"`

	// A brief reason explaining the condition.
	Reason string `json:"reason,omitempty"`

	// Optionally, a detailed message providing additional context.
	Message string `json:"message,omitempty"`
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
