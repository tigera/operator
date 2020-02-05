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

// The code in this file renders the necessary components for a managed cluster to be able to communicate with the elasticsearch
// in it's management cluster
package render

import (
	"fmt"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const ElasticsearchServiceName = "tigera-secure-es-http"

func ElasticsearchManaged(clusterDNS string, provider operatorv1.Provider) Component {
	return &elasticsearchManaged{
		clusterDNS: clusterDNS,
		provider:   provider,
	}
}

type elasticsearchManaged struct {
	clusterDNS string
	provider   operatorv1.Provider
}

func (es elasticsearchManaged) Objects() []runtime.Object {
	return []runtime.Object{
		createNamespace(ElasticsearchNamespace, es.provider == operatorv1.ProviderOpenShift),
		es.externalService(),
	}
}

func (es elasticsearchManaged) Ready() bool {
	return true
}

func (es elasticsearchManaged) externalService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ElasticsearchServiceName,
			Namespace: ElasticsearchNamespace,
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: fmt.Sprintf("%s.%s.%s", GuardianServiceName, GuardianNamespace, es.clusterDNS),
		},
	}
}
