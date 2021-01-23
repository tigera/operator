// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package utils

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"reflect"

	"github.com/tigera/operator/pkg/render"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func GetSecret(ctx context.Context, client client.Client, name string, ns string) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	if err := client.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, secret); err != nil {
		if !errors.IsNotFound(err) {
			return nil, err
		}
		return nil, nil
	}
	return secret, nil
}

// EnsureCertificateSecret ensures that the certificate in the provided
// secrets has the expected DNS names. If no key secret is provided, a new key
// secret is created and returned. If the key secret provided does have the
// right DNS name, then that given key secret is returned.
// Otherwise a new key secret is created and returned.
func EnsureCertificateSecret(ctx context.Context, secretName string, secret *corev1.Secret, svcDNSNames ...string) (*corev1.Secret, error) {
	var err error

	// Create the secret if it doesn't exist.
	if secret == nil {
		secret, err = render.CreateOperatorTLSSecret(nil,
			secretName, "tls.key", "tls.crt",
			render.DefaultCertificateDuration, nil, svcDNSNames...,
		)
		if err != nil {
			return nil, err
		}
		return secret, nil
	}

	// If the cert's DNS names have changed then we need to recreate the secret.
	ok, err := secretHasExpectedDNSNames(secret, svcDNSNames)

	if err != nil {
		return nil, err
	}
	// DNS names on the cert do not match expected values; create a new cert.
	if !ok {
		return render.CreateOperatorTLSSecret(nil,
			secretName, "tls.key", "tls.crt",
			render.DefaultCertificateDuration, nil, svcDNSNames...,
		)
	}

	// Finally return just the secret.
	return secret, nil
}

func secretHasExpectedDNSNames(secret *corev1.Secret, expectedDNSNames []string) (bool, error) {
	certBytes := secret.Data["tls.crt"]
	pemBlock, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return false, err
	}

	return reflect.DeepEqual(cert.DNSNames, expectedDNSNames), nil
}
