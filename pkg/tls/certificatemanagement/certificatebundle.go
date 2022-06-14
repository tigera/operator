// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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
	"bytes"
	"fmt"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type trustedBundle struct {
	// certificates is a map of key: hash, value: certificate.
	certificates map[string]CertificateInterface
}

// CreateTrustedBundle creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
func CreateTrustedBundle(certificates ...CertificateInterface) TrustedBundle {
	bundle := &trustedBundle{
		certificates: make(map[string]CertificateInterface),
	}
	bundle.AddCertificates(certificates...)
	return bundle
}

// AddCertificates Adds the certificates to the bundle.
func (t *trustedBundle) AddCertificates(certificates ...CertificateInterface) {
	for _, cert := range certificates {
		// Check if we already trust an issuer of this cert. In practice, this will be 0 or 1 iteration,
		// because the issuer is only set when the tigera-ca-private is the issuer.
		cur := cert
		var skip bool
		for cur != nil && !skip {
			hash := rmeta.AnnotationHash(cur.GetCertificatePEM())
			cur = cur.GetIssuer()
			if _, found := t.certificates[hash]; found {
				skip = true
			}
		}
		if cert != nil && !skip {
			// Add the leaf certificate
			hash := rmeta.AnnotationHash(cert.GetCertificatePEM())
			t.certificates[hash] = cert
		}
	}
}

func (t *trustedBundle) MountPath() string {
	return TrustedCertBundleMountPath
}

func (t *trustedBundle) HashAnnotations() map[string]string {
	annotations := make(map[string]string)
	for hash, cert := range t.certificates {
		annotations[fmt.Sprintf("hash.operator.tigera.io/%s", cert.GetName())] = hash
	}
	return annotations
}

func (t *trustedBundle) VolumeMount(osType rmeta.OSType) corev1.VolumeMount {
	var mountPath string
	if osType == rmeta.OSTypeWindows {
		mountPath = TrustedCertVolumeMountPathWindows
	} else {
		mountPath = TrustedCertVolumeMountPath
	}
	return corev1.VolumeMount{
		Name:      TrustedCertConfigMapName,
		MountPath: mountPath,
		ReadOnly:  true,
	}
}

func (t *trustedBundle) Volume() corev1.Volume {
	return corev1.Volume{
		Name: TrustedCertConfigMapName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: TrustedCertConfigMapName},
			},
		},
	}
}

func (t *trustedBundle) ConfigMap(namespace string) *corev1.ConfigMap {
	pemBuf := bytes.Buffer{}
	for _, cert := range t.certificates {
		pemBuf.WriteString(fmt.Sprintf("# certificate name: %s\n%s\n\n",
			cert.GetName(), string(cert.GetCertificatePEM()))) // err is always nil
	}
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TrustedCertConfigMapName,
			Namespace: namespace,
		},
		Data: map[string]string{
			TrustedCertConfigMapKeyName: pemBuf.String(),
		},
	}
}

// NewCertificate creates a new certificate.
func NewCertificate(name string, pem []byte, issuer CertificateInterface) CertificateInterface {
	return &certificate{name: name, pem: pem, issuer: issuer}
}

type certificate struct {
	name   string
	issuer CertificateInterface
	pem    []byte
}

func (c *certificate) GetCertificatePEM() []byte {
	return c.pem
}

func (c *certificate) GetName() string {
	return c.name
}

func (c *certificate) GetIssuer() CertificateInterface {
	return c.issuer
}
