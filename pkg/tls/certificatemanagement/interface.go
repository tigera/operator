// Copyright (c) 2022-2024 Tigera, Inc. All rights reserved.

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

package certificatemanagement

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/tigera/operator/pkg/render/common/meta"
)

const (
	TenantCASecretName                = "tigera-ca-private-tenant"
	CASecretName                      = "tigera-ca-private"
	TrustedCertConfigMapKeyName       = "tigera-ca-bundle.crt"
	TrustedCertVolumeMountPath        = "/etc/pki/tls/"
	TrustedCertVolumeMountPathWindows = "c:/etc/pki/tls/"
	TrustedCertBundleMountPath        = "/etc/pki/tls/certs/tigera-ca-bundle.crt"
	TrustedCertBundleMountPathWindows = "c:/etc/pki/tls/certs/tigera-ca-bundle.crt"

	// TrustedCertConfigMapName is the name of the trusted certificate bundle ConfigMap. This value is used
	// for all single-tenant trusted bundles, as well as multi-tenant trusted bundles that do not include public CAs.
	TrustedCertConfigMapName = "tigera-ca-bundle"

	// TrustedCertConfigMapNamePublic is the name of the trusted certificate bundle ConfigMap that includes public CAs, used
	// only in multi-tenant environments as a single namespace requires both a trusted bundle with public CAs as well as one without.
	TrustedCertConfigMapNamePublic = "tigera-ca-bundle-system-certs"
)

// KeyPairInterface wraps a Secret object that contains a private key and a certificate. Whether CertificateManagement is
// configured or not, KeyPair returns the right InitContainer, VolumeMount or Volume (when applicable).
type KeyPairInterface interface {
	// UseCertificateManagement returns true if this key pair was not user provided and certificate management has been configured.
	UseCertificateManagement() bool
	// BYO returns true if this KeyPair was provided by the user. If BYO is true, UseCertificateManagement is false.
	BYO() bool
	InitContainer(namespace string) corev1.Container
	VolumeMount(osType meta.OSType) corev1.VolumeMount
	VolumeMountKeyFilePath() string
	VolumeMountCertificateFilePath() string
	Volume() corev1.Volume
	Secret(namespace string) *corev1.Secret
	HashAnnotationKey() string
	HashAnnotationValue() string
	CertificateInterface
}

// CertificateInterface wraps the certificate. Combine this with a TrustedBundle, to mount a trusted certificate bundle to a pod.
type CertificateInterface interface {
	GetIssuer() CertificateInterface
	GetCertificatePEM() []byte
	GetName() string
	GetNamespace() string
}

// TrustedBundle is used to create a trusted certificate bundle of the CertificateManager CA and 0 or more Certificates.
type TrustedBundle interface {
	MountPath() string
	ConfigMap(namespace string) *corev1.ConfigMap
	HashAnnotations() map[string]string
	VolumeMounts(osType meta.OSType) []corev1.VolumeMount
	Volume() corev1.Volume
	AddCertificates(certificates ...CertificateInterface)
}

// Read-only version of a trusted bundle, useful for rendering components without needing to parse certificates.
type TrustedBundleRO interface {
	MountPath() string
	HashAnnotations() map[string]string
	VolumeMounts(osType meta.OSType) []corev1.VolumeMount
	Volume() corev1.Volume
}
