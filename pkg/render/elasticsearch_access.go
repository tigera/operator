package render

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Elasticsearch is a Component that contains the k8s resources required for another component to have elasticsearch access.
type elasticsearchAccess struct {
	namespace    string
	esUserSecret corev1.Secret
	esCertSecret corev1.Secret
	esConfigMap  corev1.ConfigMap
}

func ElasticsearchAccess(namespace string, esUserSecret corev1.Secret, esCertSecret corev1.Secret, esConfigMap corev1.ConfigMap) Component {
	return &elasticsearchAccess{
		namespace:    namespace,
		esUserSecret: esUserSecret,
		esCertSecret: esCertSecret,
		esConfigMap:  esConfigMap,
	}
}

func (ea elasticsearchAccess) Objects() []runtime.Object {
	var objs []runtime.Object

	objs = append(objs, copySecrets(ea.namespace, &ea.esUserSecret, &ea.esCertSecret)...)
	objs = append(objs, copyConfigMaps(ea.namespace, ea.esConfigMap)...)
	return objs
}

func (ea elasticsearchAccess) Ready() bool {
	return true
}
