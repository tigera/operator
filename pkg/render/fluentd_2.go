package render

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	LogCollectorNamespace = "tigera-log-collector"
)

func Fluentd(elasticsearchAccess Component, pullSecrets []*corev1.Secret) Component {
	return &fluentd{
		elasticsearchAccess: elasticsearchAccess,
		pullSecrets:         pullSecrets,
	}
}

type fluentd struct {
	elasticsearchAccess Component
	pullSecrets         []*corev1.Secret
}

func (f *fluentd) Objects() []runtime.Object {
	var objs []runtime.Object
	objs = append(objs, createNamespace(LogCollectorNamespace, false))
	objs = append(objs, copySecrets(LogCollectorNamespace, f.pullSecrets...)...)
	objs = append(objs, f.elasticsearchAccess.Objects()...)
	return objs
}

func (f *fluentd) Ready() bool {
	return true
}
