// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package dex

import (
	ccrypto "github.com/tigera/operator/pkg/crypto"
	rutil "github.com/tigera/operator/pkg/render/common"
	"github.com/tigera/operator/pkg/tls"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func CreateClientSecret() *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-dex",
			Namespace: rutil.OperatorNamespace(),
		},
		Data: map[string][]byte{
			ClientSecretSecretField: []byte(ccrypto.GeneratePassword(24)),
		},
	}
}

func CreateTLSSecret(dexCommonName string) *corev1.Secret {
	key, cert := tls.CreateSelfSignedSecret(dexCommonName, []string{dexCommonName})
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TLSSecretName,
			Namespace: rutil.OperatorNamespace(),
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       []byte(cert),
			corev1.TLSPrivateKeyKey: []byte(key),
		},
	}
}
