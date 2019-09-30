package render

import (
	"fmt"
	cmneckalpha1 "github.com/elastic/cloud-on-k8s/pkg/apis/common/v1alpha1"
	eckv1alpha1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1alpha1"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	ElasticsearchClusterName  = "tigera-elasticsearch"
	ElasticsearchStorageClass = "tigera-elasticsearch"
	ElasticsearchNamespace    = "tigera-elasticsearch"
	ElasticsearchClusterHTTP  = "tigera-elasticsearch-es-http"
	ElasticsearchVersion      = "7.3.0"
)

func Elasticsearch(logStorage operatorv1.LogStorage, openShift bool) (Component, error) {
	return &elasticsearchComponent{
		logStorage: logStorage,
		openShift:  openShift,
	}, nil
}

type elasticsearchComponent struct {
	logStorage operatorv1.LogStorage
	openShift  bool
}

func (es *elasticsearchComponent) Objects() []runtime.Object {
	var objs []runtime.Object
	objs = append(objs, createNamespace(ElasticsearchNamespace, es.openShift))
	if es.logStorage.StorageClass() == nil {
		objs = append(objs, esDefaultStorageClass())
	}

	objs = append(objs, es.elasticsearchCluster())

	return objs
}

func (es *elasticsearchComponent) Ready() bool {
	return true
}

func esDefaultStorageClass() *storagev1.StorageClass {
	return &storagev1.StorageClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: ElasticsearchStorageClass,
		},
		Provisioner: "kubernetes.io/host-path",
	}
}

// generate the PVC required for the Elasticsearch nodes
func (es elasticsearchComponent) pvcTemplate() corev1.PersistentVolumeClaim {
	storageClassName := ElasticsearchStorageClass
	if es.logStorage.StorageClass() != nil {
		storageClassName = es.logStorage.StorageClass().Name
	}

	pvcTemplate := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name: "elasticsearch-data", // ECK requires this name
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					"storage": resource.MustParse("10Gi"),
				},
			},
			StorageClassName: &storageClassName,
		},
	}

	// We only allow the user to overwrite the resource requirements for the pvc
	if es.logStorage.Spec.Nodes != nil && es.logStorage.Spec.Nodes.ResourceRequirements != nil {
		pvcTemplate.Spec.Resources = *es.logStorage.Spec.Nodes.ResourceRequirements
	}

	return pvcTemplate
}

// render the Elasticsearch CR that the ECK operator uses to create elasticsearch cluster
func (es elasticsearchComponent) elasticsearchCluster() *eckv1alpha1.Elasticsearch {
	nodeConfig := es.logStorage.Spec.Nodes

	tls := cmneckalpha1.TLSOptions{}
	if es.logStorage.Spec.Certificate != nil {
		tls.Certificate = cmneckalpha1.SecretRef{
			SecretName: es.logStorage.Spec.Certificate.SecretName,
		}
	} else {
		tls.SelfSignedCertificate = &cmneckalpha1.SelfSignedCertificate{
			SubjectAlternativeNames: []cmneckalpha1.SubjectAlternativeName{{
				DNS: fmt.Sprintf("%s.%s.svc.cluster.local", ElasticsearchClusterHTTP, ElasticsearchNamespace),
			}},
		}
	}

	return &eckv1alpha1.Elasticsearch{
		TypeMeta: metav1.TypeMeta{Kind: "Elasticsearch", APIVersion: "elasticsearch.k8s.elastic.co/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-secure",
			Namespace: ElasticsearchNamespace,
			Annotations: map[string]string{
				// TODO when the eck operator is created through the TSEE operator we need to make sure this is in sync
				"common.k8s.elastic.co/controller-version": "0.9.0",
			},
		},
		Spec: eckv1alpha1.ElasticsearchSpec{
			Version: ElasticsearchVersion,
			HTTP: cmneckalpha1.HTTPConfig{
				TLS: tls,
			},
			Nodes: []eckv1alpha1.NodeSpec{
				{
					NodeCount: int32(nodeConfig.Count),
					Config: &cmneckalpha1.Config{
						Data: map[string]interface{}{
							"node.master": "true",
							"node.data":   "true",
							"node.ingest": "true",
						},
					},
					VolumeClaimTemplates: []corev1.PersistentVolumeClaim{es.pvcTemplate()},
				},
			},
		},
	}
}
