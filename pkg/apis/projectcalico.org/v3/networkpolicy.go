// Copyright (c) 2017,2019 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v3

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	KindNetworkPolicy     = "NetworkPolicy"
	KindNetworkPolicyList = "NetworkPolicyList"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicy is the Namespaced-equivalent of the GlobalNetworkPolicy.
type NetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              NetworkPolicySpec `json:"spec,omitempty"`
}

type NetworkPolicySpec struct {
	Tier                   string       `json:"tier,omitempty" validate:"omitempty,name"`
	Order                  *float64     `json:"order,omitempty"`
	Ingress                []Rule       `json:"ingress,omitempty" validate:"omitempty,dive"`
	Egress                 []Rule       `json:"egress,omitempty" validate:"omitempty,dive"`
	Selector               string       `json:"selector,omitempty" validate:"selector"`
	Types                  []PolicyType `json:"types,omitempty" validate:"omitempty,dive,policyType"`
	ServiceAccountSelector string       `json:"serviceAccountSelector,omitempty" validate:"selector"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicyList contains a list of NetworkPolicy resources.
type NetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []NetworkPolicy `json:"items"`
}

// PolicyType enumerates the possible values of the PolicySpec Types field.
type PolicyType string

const (
	PolicyTypeIngress PolicyType = "Ingress"
	PolicyTypeEgress  PolicyType = "Egress"
)

type Rule struct {
	Action      Action     `json:"action" validate:"action"`
	Protocol    string     `json:"protocol,omitempty" validate:"omitempty"`
	Source      EntityRule `json:"source,omitempty" validate:"omitempty"`
	Destination EntityRule `json:"destination,omitempty" validate:"omitempty"`
}

type EntityRule struct {
	Nets              []string `json:"nets,omitempty" validate:"omitempty,dive,net"`
	Selector          string   `json:"selector,omitempty" validate:"omitempty,selector"`
	NamespaceSelector string   `json:"namespaceSelector,omitempty" validate:"omitempty,selector"`
	Ports             []int32  `json:"ports,omitempty" validate:"omitempty,dive"`
}

type Action string

const (
	Allow Action = "Allow"
	Deny         = "Deny"
	Log          = "Log"
	Pass         = "Pass"
)
