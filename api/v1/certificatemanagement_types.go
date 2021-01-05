// Copyright (c) 2020 Tigera, Inc. All rights reserved.
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, softwa
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CertificateManagementStatus defines the observed state of CertificateManagement
type CertificateManagementStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// CertificateManagement is the Schema for the certificate management API
type CertificateManagement struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificateManagementSpec   `json:"spec,omitempty"`
	Status CertificateManagementStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CertificateManagementList contains a list of CertificateManagement
type CertificateManagementList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CertificateManagement `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CertificateManagement{}, &CertificateManagementList{})
}

// Apply this to your cluster only if an automatic certificate signing and approving process is in place for the cluster.
// Rather than creating self-signed certificates, pods created by this operator will issue a CSR. These pods will not
// come up until their CSRs are approved.
type CertificateManagementSpec struct {
	// Root CA of the certificate authority that signs the certificate requests.
	RootCA string `json:"rootCA"`

	// Specify the signer here that will sign the Certificate Requests issued by Tigera Enterprise.
	// Must be formatted as: "<my-domain>/<my-signername>".
	SignerName string `json:"signerName"`

	// Specify the algorithm used for (public) key generation by init containers.
	// Default: RSAWithSize2048
	// +kubebuilder:validation:Enum="";RSAWithSize2048;RSAWithSize4096;RSAWithSize8192;ECDSAWithCurve256;ECDSAWithCurve384;ECDSAWithCurve521;
	// +optional
	KeyAlgorithm KeyAlgorithm `json:"keyAlgorithm,omitempty"`

	// Specify the algorithm used for the signature of the certificate request.
	// Default: SHA256WithRSA
	// +kubebuilder:validation:Enum="";SHA256WithRSA;SHA384WithRSA;SHA512WithRSA;ECDSAWithSHA256;ECDSAWithSHA384;ECDSAWithSHA512;
	// +optional
	SignatureAlgorithm SignatureAlgorithm `json:"signatureAlgorithm,omitempty"`
}

// Key algorithm for certificate signing requests.
type KeyAlgorithm string

const (
	KeyAlgorithmNone              = ""
	KeyAlgorithmRSAWithSize2048   = "RSAWithSize2048"
	KeyAlgorithmRSAWithSize4096   = "RSAWithSize4096"
	KeyAlgorithmRSAWithSize8192   = "RSAWithSize8192"
	KeyAlgorithmECDSAWithCurve256 = "ECDSAWithCurve256"
	KeyAlgorithmECDSAWithCurve384 = "ECDSAWithCurve384"
	KeyAlgorithmECDSAWithCurve521 = "ECDSAWithCurve521"
)

// Signature algorithm for certificate signing requests.
type SignatureAlgorithm string

const (
	SignatureAlgorithmNone            = ""
	SignatureAlgorithmSHA256WithRSA   = "SHA256WithRSA"
	SignatureAlgorithmSHA384WithRSA   = "SHA384WithRSA"
	SignatureAlgorithmSHA512WithRSA   = "SHA512WithRSA"
	SignatureAlgorithmECDSAWithSHA256 = "ECDSAWithSHA256"
	SignatureAlgorithmECDSAWithSHA384 = "ECDSAWithSHA384"
	SignatureAlgorithmECDSAWithSHA512 = "ECDSAWithSHA512"
)
