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
	"regexp"
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

	operatorIssuedCertRegexp = regexp.MustCompile(fmt.Sprintf(`%s@\d+`, render.TigeraOperatorCAIssuerPrefix))
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
// right DNS names then the secret is returned.
// If the cert in the secret has invalid DNS names and the secret is operator
// managed, then a new secret is created and returned. Otherwise,
// if the secret is user-supplied, an error is returned.
func EnsureCertificateSecret(secretName string, secret *corev1.Secret, keyName string, certName string, certDuration time.Duration, svcDNSNames ...string) (*corev1.Secret, error) {
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
		// If the cert's DNS names are invalid and the cert secret is managed
		// by the operator, then create a new secret to replace the invalid one.
		operatorManaged, err := IsOperatorManaged(secret, certName)
		if err != nil {
			return nil, err
		}
		if operatorManaged {
			certsLogger.Info(fmt.Sprintf("operator-managed cert %q has wrong DNS names, recreating it", secretName))
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

// Check if the cert secret is created and managed by the operator.
func IsOperatorManaged(certSecret *corev1.Secret, certKeyName string) (bool, error) {
	cert, err := parseCertificate(certSecret, certKeyName)
	if err != nil {
		certsLogger.Info(fmt.Sprintf("Parsing certificate error: %v", err))
		return false, err
	}

	return operatorIssuedCertRegexp.MatchString(cert.Issuer.CommonName), nil
}

func parseCertificate(secret *corev1.Secret, certKeyName string) (*x509.Certificate, error) {
	certBytes := secret.Data[certKeyName]
	pemBlock, _ := pem.Decode(certBytes)
	if pemBlock == nil {
		return nil, ErrInvalidCertNoPEMData
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// Check that the cert in the secret has the expected DNS names.
func SecretHasExpectedDNSNames(secret *corev1.Secret, certKeyName string, expectedDNSNames []string) error {
	cert, err := parseCertificate(secret, certKeyName)
	if err != nil {
		return err
	}

	dnsNames := sets.NewString(cert.DNSNames...)
	if dnsNames.HasAll(expectedDNSNames...) {
		return nil
	}
	return ErrInvalidCertDNSNames
}
