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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tigera/operator/pkg/render"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	certsLogger             = logf.Log.WithName("certs")
	ErrInvalidCertDNSNames  = errors.New("cert has the wrong DNS names")
	ErrInvalidCertNoPEMData = errors.New("cert has no PEM data")
)

func GetSecret(ctx context.Context, client client.Client, name string, ns string) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	if err := client.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, secret); err != nil {
		if !kerrors.IsNotFound(err) {
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
func EnsureCertificateSecret(secretName string, secret *corev1.Secret, keyName string, certName string, certDuration time.Duration, componentUID types.UID, svcDNSNames ...string) (*corev1.Secret, error) {
	var err error

	// Create the secret if it doesn't exist.
	if secret == nil {
		certsLogger.Info(fmt.Sprintf("cert %q doesn't exist, creating it", secretName))
		return render.CreateOperatorTLSSecret(nil,
			secretName, keyName, certName,
			certDuration, nil, svcDNSNames...,
		)
	}

	err = SecretHasExpectedDNSNames(secret, certName, svcDNSNames)
	if err == ErrInvalidCertDNSNames {
		// If the cert's DNS names are invalid and the secret is owned by the
		// component, then create a new secret to replace the invalid one.
		if isOwnedByUID(secret, componentUID) {
			certsLogger.Info(fmt.Sprintf("cert %q has wrong DNS names, recreating it", secretName))
			return render.CreateOperatorTLSSecret(nil,
				secretName, keyName, certName,
				render.DefaultCertificateDuration, nil, svcDNSNames...,
			)
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

// Check that the cert in the secret has the expected DNS names.
func SecretHasExpectedDNSNames(secret *corev1.Secret, certName string, expectedDNSNames []string) error {
	certBytes := secret.Data[certName]
	pemBlock, _ := pem.Decode(certBytes)
	if pemBlock == nil {
		return ErrInvalidCertNoPEMData
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return err
	}

	dnsNames := sets.NewString(cert.DNSNames...)
	if dnsNames.HasAll(expectedDNSNames...) {
		return nil
	}
	return ErrInvalidCertDNSNames
}
