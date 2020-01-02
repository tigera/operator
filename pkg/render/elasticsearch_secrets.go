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

package render

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// elasticsearchSecrets is a Component that contains the secrets that need to be created in the tigera operator namespace
// after Elasticsearch and Kibana are running. At this time these secrets contain elasticsearch users credentials and
// tls certificate information.
type elasticsearchSecrets struct {
	updatedESUserSecrets   []*corev1.Secret
	esPublicCertSecret     *corev1.Secret
	kibanaPublicCertSecret *corev1.Secret
}

func ElasticsearchSecrets(updatedESUserSecrets []*corev1.Secret, esPublicCertSecret *corev1.Secret, kibanaPublicCertSecret *corev1.Secret) Component {
	return &elasticsearchSecrets{
		updatedESUserSecrets:   updatedESUserSecrets,
		esPublicCertSecret:     esPublicCertSecret,
		kibanaPublicCertSecret: kibanaPublicCertSecret,
	}
}

func (es elasticsearchSecrets) Objects() []runtime.Object {
	var objs []runtime.Object
	objs = append(objs, secretsToRuntimeObject(es.updatedESUserSecrets...)...)
	objs = append(objs, secretsToRuntimeObject(copySecrets(OperatorNamespace(), es.esPublicCertSecret, es.kibanaPublicCertSecret)...)...)
	return objs
}

func (es elasticsearchSecrets) Ready() bool {
	return true
}
