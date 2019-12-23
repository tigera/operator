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
