// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.
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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IntrusionDetectionSpec defines the desired state of Tigera intrusion detection capabilities.
type IntrusionDetectionSpec struct {
	// ComponentResources can be used to customize the resource requirements for each component.
	// Only DeepPacketInspection is supported for this spec.
	// +optional
	ComponentResources []IntrusionDetectionComponentResource `json:"componentResources,omitempty"`

	// AnomalyDetection is now deprecated, and configuring it has no effect.
	// +optional
	AnomalyDetection AnomalyDetectionSpec `json:"anomalyDetection,omitempty"`

	// IntrusionDetectionDeployment configures the IntrusionDetection Deployment.
	// +optional
	IntrusionDetectionDeployment *IntrusionDetectionDeployment `json:"intrusionDetectionDeployment,omitempty"`
}

type AnomalyDetectionSpec struct {

	// StorageClassName is now deprecated, and configuring it has no effect.
	// +optional
	StorageClassName string `json:"storageClassName,omitempty"`
}

// IntrusionDetectionStatus defines the observed state of Tigera intrusion detection capabilities.
type IntrusionDetectionStatus struct {
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

// IntrusionDetection installs the components required for Tigera intrusion detection. At most one instance
// of this resource is supported. It must be named "tigera-secure".
type IntrusionDetection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for Tigera intrusion detection.
	Spec IntrusionDetectionSpec `json:"spec,omitempty"`
	// Most recently observed state for Tigera intrusion detection.
	Status IntrusionDetectionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// IntrusionDetectionList contains a list of IntrusionDetection
type IntrusionDetectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IntrusionDetection `json:"items"`
}

type IntrusionDetectionComponentName string

const (
	ComponentNameDeepPacketInspection IntrusionDetectionComponentName = "DeepPacketInspection"
)

// The ComponentResource struct associates a ResourceRequirements with a component by name
type IntrusionDetectionComponentResource struct {
	// ComponentName is an enum which identifies the component
	// +kubebuilder:validation:Enum=DeepPacketInspection
	ComponentName IntrusionDetectionComponentName `json:"componentName"`
	// ResourceRequirements allows customization of limits and requests for compute resources such as cpu and memory.
	ResourceRequirements *corev1.ResourceRequirements `json:"resourceRequirements"`
}

// IntrusionDetectionDeployment is the configuration for the IntrusionDetection Deployment.
type IntrusionDetectionDeployment struct {

	// Spec is the specification of the IntrusionDetection Deployment.
	// +optional
	Spec *IntrusionDetectionDeploymentSpec `json:"spec,omitempty"`
}

// IntrusionDetectionDeploymentSpec defines configuration for the IntrusionDetection Deployment.
type IntrusionDetectionDeploymentSpec struct {

	// Template describes the IntrusionDetection Deployment pod that will be created.
	// +optional
	Template *IntrusionDetectionDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// IntrusionDetectionDeploymentPodTemplateSpec is the IntrusionDetection Deployment's PodTemplateSpec
type IntrusionDetectionDeploymentPodTemplateSpec struct {

	// Spec is the IntrusionDetection Deployment's PodSpec.
	// +optional
	Spec *IntrusionDetectionDeploymentPodSpec `json:"spec,omitempty"`
}

// IntrusionDetectionDeploymentPodSpec is the IntrusionDetection Deployment's PodSpec.
type IntrusionDetectionDeploymentPodSpec struct {
	// InitContainers is a list of IntrusionDetection init containers.
	// If specified, this overrides the specified IntrusionDetection Deployment init containers.
	// If omitted, the IntrusionDetection Deployment will use its default values for its init containers.
	// +optional
	InitContainers []IntrusionDetectionDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of IntrusionDetection containers.
	// If specified, this overrides the specified IntrusionDetection Deployment containers.
	// If omitted, the IntrusionDetection Deployment will use its default values for its containers.
	// +optional
	Containers []IntrusionDetectionDeploymentContainer `json:"containers,omitempty"`
}

// IntrusionDetectionDeploymentContainer is a IntrusionDetection Deployment container.
type IntrusionDetectionDeploymentContainer struct {
	// Name is an enum which identifies the IntrusionDetection Deployment container by name.
	// +kubebuilder:validation:Enum=controller;webhooks-processor
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named IntrusionDetection Deployment container's resources.
	// If omitted, the IntrusionDetection Deployment will use its default value for this container's resources.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
}

// IntrusionDetectionDeploymentInitContainer is a IntrusionDetection Deployment init container.
type IntrusionDetectionDeploymentInitContainer struct {
	// Name is an enum which identifies the IntrusionDetection Deployment init container by name.
	// +kubebuilder:validation:Enum=intrusion-detection-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named IntrusionDetection Deployment init container's resources.
	// If omitted, the IntrusionDetection Deployment will use its default value for this init container's resources.
	// If used in conjunction with the deprecated ComponentResources, then this value takes precedence.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
}

func (c *IntrusionDetectionDeployment) GetMetadata() *Metadata {
	return nil
}

func (c *IntrusionDetectionDeployment) GetMinReadySeconds() *int32 {
	return nil
}

func (c *IntrusionDetectionDeployment) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (c *IntrusionDetectionDeployment) GetInitContainers() []corev1.Container {
	if c != nil {
		if c.Spec.Template != nil {
			if c.Spec.Template.Spec != nil {
				if c.Spec.Template.Spec.InitContainers != nil {
					cs := make([]corev1.Container, len(c.Spec.Template.Spec.InitContainers))
					for i, v := range c.Spec.Template.Spec.InitContainers {
						// Only copy and return the init container if it has resources set.
						if v.Resources == nil {
							continue
						}
						c := corev1.Container{Name: v.Name, Resources: *v.Resources}
						cs[i] = c
					}
					return cs
				}
			}
		}
	}

	return nil
}

func (c *IntrusionDetectionDeployment) GetContainers() []corev1.Container {
	if c != nil {
		if c.Spec != nil {
			if c.Spec.Template != nil {
				if c.Spec.Template.Spec != nil {
					if c.Spec.Template.Spec.Containers != nil {
						cs := make([]corev1.Container, len(c.Spec.Template.Spec.Containers))
						for i, v := range c.Spec.Template.Spec.Containers {
							// Only copy and return the init container if it has resources set.
							if v.Resources == nil {
								continue
							}
							c := corev1.Container{Name: v.Name, Resources: *v.Resources}
							cs[i] = c
						}
						return cs
					}
				}
			}
		}
	}
	return nil
}

func (c *IntrusionDetectionDeployment) GetAffinity() *corev1.Affinity {
	return nil
}

func (c *IntrusionDetectionDeployment) GetTopologySpreadConstraints() []corev1.TopologySpreadConstraint {
	return nil
}

func (c *IntrusionDetectionDeployment) GetNodeSelector() map[string]string {
	return nil
}

func (c *IntrusionDetectionDeployment) GetTolerations() []corev1.Toleration {
	return nil
}

func (c *IntrusionDetectionDeployment) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *IntrusionDetectionDeployment) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *IntrusionDetectionDeployment) GetPriorityClassName() string {
	return ""
}

func init() {
	SchemeBuilder.Register(&IntrusionDetection{}, &IntrusionDetectionList{})
}
