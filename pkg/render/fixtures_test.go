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

package render_test

import (
	"github.com/tigera/operator/pkg/render"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var internalManagerTLSSecret = v1.Secret{
	TypeMeta: metav1.TypeMeta{
		Kind:       "Secret",
		APIVersion: "v1",
	},
	ObjectMeta: metav1.ObjectMeta{
		Name:      render.ManagerInternalTLSSecretName,
		Namespace: render.OperatorNamespace(),
	},
	Data: map[string][]byte{
		"cert": []byte("cert"),
		"key":  []byte("key"),
	},
}

var complianceServerCertSecret = v1.Secret{
	TypeMeta: metav1.TypeMeta{
		Kind:       "Secret",
		APIVersion: "v1",
	},
	ObjectMeta: metav1.ObjectMeta{
		Name:      render.ComplianceServerCertSecret,
		Namespace: render.OperatorNamespace(),
	},
	Data: map[string][]byte{
		"cert": []byte("cert"),
		"key":  []byte("key"),
	},
}
var voltronTunnelSecret = v1.Secret{
	TypeMeta: metav1.TypeMeta{
		Kind:       "Secret",
		APIVersion: "v1",
	},
	ObjectMeta: metav1.ObjectMeta{
		Name:      render.VoltronTunnelSecretName,
		Namespace: render.OperatorNamespace(),
	},
	Data: map[string][]byte{
		render.VoltronTunnelSecretCertName: []byte("cert"),
		render.VoltronTunnelSecretKeyName:  []byte("key"),
	},
}
