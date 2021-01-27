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

package render

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

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

// EnsureCertificateSecret ensures that the certificate in the
// secret has the expected DNS names. If no secret is provided, a new
// secret is created and returned. If the secret does have the
// right DNS name then the secret is returned.
// If the cert in the secret has invalid DNS names and the secret is owned by
// the provided component, then a new secret is created and returned. Otherwise,
// if the secret is user-supplied, an error is returned.
func EnsureCertificateSecret(ctx context.Context, secretName string, secret *corev1.Secret, keyName string, certName string, certDuration time.Duration, componentUID types.UID, svcDNSNames ...string) (*corev1.Secret, error) {
	var err error

	// Create the secret if it doesn't exist.
	if secret == nil {
		log.Info(fmt.Sprintf("cert %q doesn't exist, creating it", secretName))
		secret, err = CreateOperatorTLSSecret(nil,
			secretName, keyName, certName,
			certDuration, nil, svcDNSNames...,
		)
		if err != nil {
			return nil, err
		}
		return secret, nil
	}

	// If the cert's DNS names have changed, create a new one.
	ok, err := SecretHasExpectedDNSNames(secret, certName, svcDNSNames)
	if err != nil {
		return nil, err
	}
	if !ok {
		// If the secret is owned by the component (i.e. the operator), then
		// create a new secret to replace the invalid one.
		if isOwnedByUID(secret, componentUID) {
			log.Info(fmt.Sprintf("cert %q has wrong DNS names, recreating it", secretName))
			secret, err = CreateOperatorTLSSecret(nil,
				secretName, keyName, certName,
				DefaultCertificateDuration, nil, svcDNSNames...,
			)
			return secret, err
		}
		// Otherwise, the secret was supplied so return an error.
		return nil, fmt.Errorf("Expected cert %q to have DNS names: %v", secretName, strings.Join(svcDNSNames, ", "))
	}

	// Return the original secret.
	return secret, nil
}

// Check if object is owned by the resource with given UID.
func isOwnedByUID(obj client.Object, uid types.UID) bool {
	ownerRefs := obj.GetOwnerReferences()
	for _, ref := range ownerRefs {
		if ref.UID == uid {
			return true
		}
	}
	return false
}

func SecretHasExpectedDNSNames(secret *corev1.Secret, certName string, expectedDNSNames []string) (bool, error) {
	certBytes := secret.Data[certName]
	pemBlock, _ := pem.Decode(certBytes)
	if pemBlock == nil {
		return false, fmt.Errorf("cert has no PEM data")
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return false, err
	}

	sort.Strings(cert.DNSNames)
	sort.Strings(expectedDNSNames)
	return reflect.DeepEqual(cert.DNSNames, expectedDNSNames), nil
}
