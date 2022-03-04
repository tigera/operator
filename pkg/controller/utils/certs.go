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
	"time"

	"github.com/tigera/operator/pkg/common"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rsecret "github.com/tigera/operator/pkg/render/common/secret"
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

	operatorIssuedCertRegexp = regexp.MustCompile(fmt.Sprintf(`%s@\d+`, rmeta.TigeraOperatorCAIssuerPrefix))
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
// secret has the expected DNS names. If no secret is provided, a new secret is created.
// The first returned value (*corev1.Secret) is the validated or created Secret to use.
// The second returned value (bool) is true if the Secret returned is managed by the operator or false if the secret is user-supplied.
// The third returned value (error) is nil if the Secret pass in is valid or was created successfully. If there was a
// problem creating the certificate or the Secret has invalid DNS names and the secret is not operator managed, an error is returned.
func EnsureCertificateSecret(secretName string, secret *corev1.Secret, keyName string, certName string, certDuration time.Duration, svcDNSNames ...string) (*corev1.Secret, bool, error) {
	var err error

	// Create the secret if it doesn't exist.
	if secret == nil {
		certsLogger.Info(fmt.Sprintf("cert %q doesn't exist, creating it", secretName))

		secret, err = rsecret.CreateTLSSecret(nil,
			secretName, common.OperatorNamespace(), keyName, certName,
			certDuration, nil, svcDNSNames...,
		)

		return secret, true, err
	}

	operatorManaged, err := IsCertOperatorIssued(secret.Data[certName])
	if err != nil {
		return nil, false, err
	}

	// For user provided certs, skip checking whether they have the right DNS
	// names.
	if !operatorManaged {
		return secret, operatorManaged, err
	}

	err = SecretHasExpectedDNSNames(secret, certName, svcDNSNames)
	if err == ErrInvalidCertDNSNames {
		// If the cert's DNS names are invalid, then create a new secret to
		// replace the invalid one since it's managed by the operator.
		certsLogger.Info(fmt.Sprintf("operator-managed cert %q has wrong DNS names, recreating it", secretName))

		secret, err = rsecret.CreateTLSSecret(nil,
			secretName, common.OperatorNamespace(), keyName, certName,
			rmeta.DefaultCertificateDuration, nil, svcDNSNames...,
		)
	}

	return secret, operatorManaged, err
}

// IsOperatorIssued checks if the cert secret is issued operator.
func IsOperatorIssued(issuer string) bool {
	return operatorIssuedCertRegexp.MatchString(issuer)
}

func IsCertOperatorIssued(certPem []byte) (bool, error) {

	issuer, err := GetCertificateIssuer(certPem)
	if err != nil {
		return false, err
	}

	return IsOperatorIssued(issuer), nil
}

// GetCertificateIssuer returns the issuer of a PEM block.
func GetCertificateIssuer(certPem []byte) (string, error) {
	cert, err := parseCertificate(certPem)
	if err != nil {
		certsLogger.Info(fmt.Sprintf("Parsing certificate error: %v", err))
		return "", err
	}

	return cert.Issuer.CommonName, nil

}

func parseCertificate(certBytes []byte) (*x509.Certificate, error) {
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

// SecretHasExpectedDNSNames Check that the cert in the secret has the expected DNS names.
func SecretHasExpectedDNSNames(secret *corev1.Secret, certKeyName string, expectedDNSNames []string) error {
	cert, err := parseCertificate(secret.Data[certKeyName])
	if err != nil {
		return err
	}

	dnsNames := sets.NewString(cert.DNSNames...)
	if dnsNames.HasAll(expectedDNSNames...) {
		return nil
	}
	return ErrInvalidCertDNSNames
}
