// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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
	"github.com/tigera/operator/pkg/tls"

	rutil "github.com/tigera/operator/pkg/render/common"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Voltron related constants.
const (
	VoltronDnsName = "voltron"
)

// Creates a secret that will store the CA needed to generated certificates
// for managed cluster registration
func voltronTunnelSecret() *corev1.Secret {
	key, cert := tls.CreateSelfSignedSecret("tigera-voltron", []string{VoltronDnsName})
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      VoltronTunnelSecretName,
			Namespace: rutil.OperatorNamespace(),
		},
		Data: map[string][]byte{
			VoltronTunnelSecretCertName: []byte(cert),
			VoltronTunnelSecretKeyName:  []byte(key),
		},
	}
}
