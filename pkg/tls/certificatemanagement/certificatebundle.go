// Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.

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
	"os"
	"path"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

const (
	// RHELRootCertificateBundleName is the name of the system CA bundle as present in UBI/RHEL systems.
	RHELRootCertificateBundleName = "ca-bundle.crt"
	// SSLCertFile is the symbolic link to the system CA bundle used by libssl SSL_CERT_FILE.
	SSLCertFile = "cert.pem"

	sslCertDir = "certs"
)

type trustedBundle struct {
	// systemCertificates is a bundle of certificates loaded from the host systems root location.
	systemCertificates []byte
	// certificates is a map of key: hash, value: certificate.
	certificates map[string]CertificateInterface
}

// CreateTrustedBundle creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
// It will include:
// - A bundle with Calico's root certificates + any user supplied certificates in /etc/pki/tls/certs/tigera-ca-bundle.crt.
func CreateTrustedBundle(certificates ...CertificateInterface) TrustedBundle {
	bundle, err := createTrustedBundle(false, certificates...)
	if err != nil {
		panic(err) // This should never happen.
	}
	return bundle
}

// CreateTrustedBundleWithSystemRootCertificates creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
// It will include:
// - A bundle with Calico's root certificates + any user supplied certificates in /etc/pki/tls/certs/tigera-ca-bundle.crt.
// - A system root certificate bundle in /etc/pki/tls/certs/ca-bundle.crt.
func CreateTrustedBundleWithSystemRootCertificates(certificates ...CertificateInterface) (TrustedBundle, error) {
	return createTrustedBundle(true, certificates...)
}

// createTrustedBundle creates a TrustedBundle, which provides standardized methods for mounting a bundle of certificates to trust.
func createTrustedBundle(includeSystemBundle bool, certificates ...CertificateInterface) (TrustedBundle, error) {
	var systemCertificates []byte
	var err error
	if includeSystemBundle {
		systemCertificates, err = getSystemCertificates()
		if err != nil {
			return nil, err
		}
	}

	bundle := &trustedBundle{
		systemCertificates: systemCertificates,
		certificates:       make(map[string]CertificateInterface),
	}
	bundle.AddCertificates(certificates...)

	return bundle, err
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
	if len(t.systemCertificates) > 0 {
		annotations["hash.operator.tigera.io/system"] = rmeta.AnnotationHash(t.systemCertificates)
	}
	return annotations
}

func (t *trustedBundle) VolumeMounts(osType rmeta.OSType) []corev1.VolumeMount {
	var mountPath string
	if osType == rmeta.OSTypeWindows {
		mountPath = TrustedCertVolumeMountPathWindows
	} else {
		mountPath = TrustedCertVolumeMountPath
	}

	// golang stdlib reads this path
	mounts := []corev1.VolumeMount{
		{
			Name:      TrustedCertConfigMapName,
			MountPath: path.Join(mountPath, sslCertDir),
			ReadOnly:  true,
		},
	}
	if len(t.systemCertificates) > 0 {
		// apps linking libssl need this file (SSL_CERT_FILE)
		mounts = append(mounts,
			corev1.VolumeMount{
				Name:      TrustedCertConfigMapName,
				MountPath: path.Join(mountPath, SSLCertFile),
				SubPath:   RHELRootCertificateBundleName,
				ReadOnly:  true,
			},
		)
	}
	return mounts
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
			RHELRootCertificateBundleName: string(t.systemCertificates),
			TrustedCertConfigMapKeyName:   pemBuf.String(),
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

// certFiles is copied from the x509 package, but re-ordered, since in practice this should run containerized
// and stop at the first entry. More at: https://go.dev/src/crypto/x509/root_linux.go for the source.
//
// Possible certificate files; stop after finding one.
var certFiles = []string{
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
	"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
	"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
	"/etc/pki/tls/cacert.pem",                           // OpenELEC
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
	"/etc/ssl/cert.pem",                                 // Alpine Linux
}

// getSystemCertificates returns the certificate that are installed in the operator's base image.
// The code of this function is loosely based on x509's loadSystemRoots() func:
// https://go.dev/src/crypto/x509/root_unix.go
func getSystemCertificates() ([]byte, error) {
	for _, filename := range certFiles {
		data, err := os.ReadFile(filename)
		if err == nil {
			return data, nil
		}
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf(fmt.Sprintf("error occurred when loading system root certificate with name %s", filename), err)
		}
	}
	return nil, nil
}
