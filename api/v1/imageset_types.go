// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ImageSetSpec defines the desired state of ImageSet
type ImageSetSpec struct {
	Images []Image `json:"images,omitempty"`
}

type Image struct {
	// Image is an image that the operator deploys and instead of using the built in tag
	// the operator will use the Digest for the image identifier.
	Image string `json:"image"`

	// Digest is the image identifier that will be used for the Image.
	// Should not include leading `@`
	Digest string `json:"digest"`
}

// ImageSetStatus defines the observed state of ImageSet
type ImageSetStatus struct {
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// ImageSet is the Schema for the imagesets API
type ImageSet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ImageSetSpec   `json:"spec,omitempty"`
	Status ImageSetStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ImageSetList contains a list of ImageSet
type ImageSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ImageSet `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ImageSet{}, &ImageSetList{})
}
