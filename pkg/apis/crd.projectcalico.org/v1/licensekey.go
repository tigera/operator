// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	KindLicenseKey     = "LicenseKey"
	KindLicenseKeyList = "LicenseKeyList"
)

// +kubebuilder:validation:Enum=CloudCommunity;CloudStarter;CloudPro;Enterprise
type LicensePackageType string

const (
	CloudCommunity LicensePackageType = "CloudCommunity"
	CloudStarter   LicensePackageType = "CloudStarter"
	CloudPro       LicensePackageType = "CloudPro"
	Enterprise     LicensePackageType = "Enterprise"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LicenseKey contains the Tigera CNX license key for the cluster.
type LicenseKey struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.  This resource is a singleton, always named "default".
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the LicenseKey.
	Spec LicenseKeySpec `json:"spec,omitempty"`
	// Status of the LicenseKey.
	Status LicenseKeyStatus `json:"status,omitempty"`
}

// LicenseKeySpec contains the license key itself.
type LicenseKeySpec struct {
	// Token is the JWT containing the license claims
	Token string `json:"token" yaml:"token"`
	// Certificate is used to validate the token.
	Certificate string `json:"certificate,omitempty" yaml:"certificate" validate:"omitempty"`
}

// LicenseKeyStatus contains the license key information.
type LicenseKeyStatus struct {
	// Expiry is the expiry date of License
	// +nullable
	Expiry metav1.Time `json:"expiry,omitempty" yaml:"expiry"`
	// Maximum Number of Allowed Nodes
	MaxNodes int `json:"maxnodes,omitempty" yaml:"maxnodes" validate:"omitempty"`
	// License package defines type of Calico license that is being enforced
	Package LicensePackageType `json:"package,omitempty" yaml:"package" validate:"omitempty"`
	// List of features that are available via the applied license
	Features []string `json:"features,omitempty" yaml:"features" validate:"omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LicenseKeyList contains a list of LicenseKey resources
// (even though there should only be one).
type LicenseKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []LicenseKey `json:"items"`
}

// New LicenseKey creates a new (zeroed) LicenseKey struct with the TypeMetadata
// initialized to the current version.
func NewLicenseKey() *LicenseKey {
	return &LicenseKey{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindLicenseKey,
			APIVersion: "crd.projectcalico.org/v1",
		},
	}
}

// NewLicenseKeyList creates a new (zeroed) LicenseKeyList struct with the TypeMetadata
// initialized to the current version.
func NewLicenseKeyList() *LicenseKeyList {
	return &LicenseKeyList{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindLicenseKeyList,
			APIVersion: "crd.projectcalico.org/v1",
		},
	}
}
